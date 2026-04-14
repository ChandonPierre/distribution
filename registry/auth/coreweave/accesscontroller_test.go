package coreweave

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/auth"
)

// memCache is an in-memory principalCacher for tests.
// It honours TTLs so stale-vs-fresh tests can use time manipulation.
type memCache struct {
	mu    sync.Mutex
	items map[string]memCacheItem
}

type memCacheItem struct {
	p         *principal
	expiresAt time.Time
}

func newMemCache() *memCache { return &memCache{items: make(map[string]memCacheItem)} }

func (m *memCache) load(_ context.Context, key string) (*principal, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.p, true
}

func (m *memCache) store(_ context.Context, key string, p *principal, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = memCacheItem{p: p, expiresAt: time.Now().Add(ttl)}
}

func (m *memCache) delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

// seedStale pre-populates the stale cache key for a given raw token.
func (m *memCache) seedStale(rawToken string, p *principal, ttl time.Duration) {
	m.store(context.Background(), whoAmIStaleKeyPrefix+hashToken(rawToken), p, ttl)
}

// newWhoAmIServer starts a test HTTP server that returns the given principal
// (or a non-200 status if principal is nil).
func newWhoAmIServer(t *testing.T, status int, p *principal) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(whoAmIResponse{Principal: p})
	}))
}

func newTestAC(t *testing.T, server *httptest.Server, policyCfgs []policyConfig) *accessController {
	t.Helper()
	celEnv, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compilePolicies(policyCfgs, celEnv)
	if err != nil {
		t.Fatal(err)
	}
	ac := &accessController{
		realm:      "test-realm",
		service:    "test-service",
		whoAmIURL:  server.URL,
		httpClient: server.Client(),
		cacheTTL:   defaultWhoAmICacheTTL,
		staleTTL:   defaultWhoAmIStaleTTL,
	}
	ac.policySet.Store(&policySet{policies: compiled})
	return ac
}

func bearerRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// --- Tests ---

func TestNoTokenReturnsChallenge(t *testing.T) {
	srv := newWhoAmIServer(t, http.StatusOK, &principal{Uid: "u1", OrgUid: "o1"})
	defer srv.Close()

	ac := newTestAC(t, srv, nil)
	_, err := ac.Authorized(bearerRequest(t, ""), auth.Access{Resource: auth.Resource{Type: "repository", Name: "myns/img"}, Action: "pull"})
	if err == nil {
		t.Fatal("expected challenge error")
	}
	if _, ok := err.(auth.Challenge); !ok {
		t.Fatalf("expected auth.Challenge, got %T", err)
	}
}

func TestWhoAmIFailureReturnsChallenge(t *testing.T) {
	srv := newWhoAmIServer(t, http.StatusUnauthorized, nil)
	defer srv.Close()

	ac := newTestAC(t, srv, nil)
	_, err := ac.Authorized(bearerRequest(t, "bad-token"))
	if err == nil {
		t.Fatal("expected challenge error")
	}
	if _, ok := err.(auth.Challenge); !ok {
		t.Fatalf("expected auth.Challenge, got %T", err)
	}
}

func TestGrantedByPolicy(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs",
		Expression: `"devs" in principal["groups"]`,
	}}
	ac := newTestAC(t, srv, policies)

	grant, err := ac.Authorized(
		bearerRequest(t, "valid-token"),
		auth.Access{Resource: auth.Resource{Type: "repository", Name: "ns/img"}, Action: "pull"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if grant.User.Name != "alice" {
		t.Errorf("expected user alice, got %s", grant.User.Name)
	}
}

func TestDeniedByPolicy(t *testing.T) {
	p := &principal{Uid: "bob", OrgUid: "acme", Groups: []string{"interns"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs-only",
		Expression: `"devs" in principal["groups"]`,
	}}
	ac := newTestAC(t, srv, policies)

	_, err := ac.Authorized(
		bearerRequest(t, "intern-token"),
		auth.Access{Resource: auth.Resource{Type: "repository", Name: "ns/img"}, Action: "pull"},
	)
	if err == nil {
		t.Fatal("expected denial")
	}
	ch, ok := err.(auth.Challenge)
	if !ok {
		t.Fatalf("expected auth.Challenge, got %T", err)
	}
	if !containsStr(ch.Error(), "insufficient") {
		t.Errorf("unexpected challenge message: %s", ch.Error())
	}
}

func TestCatalogFullAccess(t *testing.T) {
	p := &principal{Uid: "admin", OrgUid: "acme", Groups: []string{"admins"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:              "admins",
		Expression:        `"admins" in principal["groups"]`,
		CatalogFullAccess: true,
	}}
	ac := newTestAC(t, srv, policies)

	grant, err := ac.Authorized(
		bearerRequest(t, "admin-token"),
		auth.Access{Resource: auth.Resource{Type: "registry", Name: ""}, Action: "catalog"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// nil CatalogPrefixes means full access
	if grant.CatalogPrefixes != nil {
		t.Errorf("expected nil CatalogPrefixes for full access, got %v", grant.CatalogPrefixes)
	}
}

func TestCatalogPrefixByUID(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:                    "uid-prefix",
		Expression:              `"devs" in principal["groups"]`,
		CatalogPrefixExpression: `principal["uid"]`,
	}}
	ac := newTestAC(t, srv, policies)

	grant, err := ac.Authorized(
		bearerRequest(t, "alice-token"),
		auth.Access{Resource: auth.Resource{Type: "repository", Name: "alice/img"}, Action: "pull"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grant.CatalogPrefixes) != 1 || grant.CatalogPrefixes[0] != "alice" {
		t.Errorf("expected catalog prefix [alice], got %v", grant.CatalogPrefixes)
	}
}

func TestPrincipalToMap(t *testing.T) {
	p := &principal{
		Uid:            "u1",
		OrgUid:         "o1",
		Groups:         []string{"g1", "g2"},
		ConsoleActions: []string{"a1"},
	}
	m := p.toMap()
	if m["uid"] != "u1" {
		t.Errorf("uid mismatch: %v", m["uid"])
	}
	if m["org_uid"] != "o1" {
		t.Errorf("org_uid mismatch: %v", m["org_uid"])
	}
	groups, ok := m["groups"].([]any)
	if !ok || len(groups) != 2 {
		t.Errorf("groups mismatch: %v", m["groups"])
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	h1 := hashToken("abc")
	h2 := hashToken("abc")
	if h1 != h2 {
		t.Error("hash should be deterministic")
	}
	h3 := hashToken("def")
	if h1 == h3 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestNewAccessControllerMissingRealm(t *testing.T) {
	_, err := newAccessController(map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing realm")
	}
}

func TestNewAccessControllerInvalidTimeout(t *testing.T) {
	_, err := newAccessController(map[string]any{
		"realm":           "r",
		"whoami_timeout":  "not-a-duration",
	})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestWhoAmICachingSkipsAPI(t *testing.T) {
	calls := 0
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(whoAmIResponse{Principal: p})
	}))
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs",
		Expression: `"devs" in principal["groups"]`,
	}}

	celEnv, _ := newCELEnv()
	compiled, _ := compilePolicies(policies, celEnv)

	ac := &accessController{
		realm:      "r",
		service:    "s",
		whoAmIURL:  srv.URL,
		httpClient: srv.Client(),
		cacheTTL:   time.Minute,
		staleTTL:   time.Hour,
	}
	ac.policySet.Store(&policySet{policies: compiled})

	// First call — hits the server.
	_, err := ac.Authorized(bearerRequest(t, "tok"), auth.Access{Resource: auth.Resource{Type: "repository", Name: "ns/img"}, Action: "pull"})
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 API call, got %d", calls)
	}

	// Second call with same token — also hits the server (no Redis configured).
	_, err = ac.Authorized(bearerRequest(t, "tok"), auth.Access{Resource: auth.Resource{Type: "repository", Name: "ns/img"}, Action: "pull"})
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 API calls without Redis, got %d", calls)
	}
}

// --- Two-phase cache tests ---

// TestStaleCacheServedWhenWhoAmIUnreachable verifies that a stale principal is
// returned when the WhoAmI endpoint is down (network error), and that the
// existing stale entry is consulted rather than failing the request.
func TestStaleCacheServedWhenWhoAmIUnreachable(t *testing.T) {
	stale := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}

	policies := []policyConfig{{
		Name:       "devs",
		Expression: `"devs" in principal["groups"]`,
	}}
	celEnv, _ := newCELEnv()
	compiled, _ := compilePolicies(policies, celEnv)

	cache := newMemCache()
	cache.seedStale("my-token", stale, time.Hour)

	// Point the controller at a non-existent address so the HTTP call fails.
	ac := &accessController{
		realm:      "r",
		service:    "s",
		whoAmIURL:  "http://127.0.0.1:0/whoami", // connection refused
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
		cache:      cache,
		cacheTTL:   5 * time.Minute,
		staleTTL:   time.Hour,
	}
	ac.policySet.Store(&policySet{policies: compiled})

	grant, err := ac.Authorized(
		bearerRequest(t, "my-token"),
		auth.Access{Resource: auth.Resource{Type: "repository", Name: "ns/img"}, Action: "pull"},
	)
	if err != nil {
		t.Fatalf("expected stale grant, got error: %v", err)
	}
	if grant.User.Name != "alice" {
		t.Errorf("expected user alice from stale cache, got %s", grant.User.Name)
	}
}

// TestStaleCacheNotServedOnTokenRejected verifies that a 401/403 from WhoAmI
// causes an auth challenge even when a stale cache entry exists.
func TestStaleCacheNotServedOnTokenRejected(t *testing.T) {
	stale := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}

	srv := newWhoAmIServer(t, http.StatusUnauthorized, nil)
	defer srv.Close()

	cache := newMemCache()
	cache.seedStale("bad-token", stale, time.Hour)

	ac := &accessController{
		realm:      "r",
		service:    "s",
		whoAmIURL:  srv.URL,
		httpClient: srv.Client(),
		cache:      cache,
		cacheTTL:   5 * time.Minute,
		staleTTL:   time.Hour,
	}
	ac.policySet.Store(&policySet{policies: nil})

	_, err := ac.Authorized(bearerRequest(t, "bad-token"))
	if err == nil {
		t.Fatal("expected challenge, got nil error")
	}
	if _, ok := err.(auth.Challenge); !ok {
		t.Fatalf("expected auth.Challenge, got %T: %v", err, err)
	}
}

// TestStaleCacheAbsentReturnsError verifies that when WhoAmI is unreachable
// and no stale entry exists, the request is rejected.
func TestStaleCacheAbsentReturnsError(t *testing.T) {
	ac := &accessController{
		realm:      "r",
		service:    "s",
		whoAmIURL:  "http://127.0.0.1:0/whoami", // connection refused
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
		cache:      newMemCache(), // empty cache
		cacheTTL:   5 * time.Minute,
		staleTTL:   time.Hour,
	}
	ac.policySet.Store(&policySet{policies: nil})

	_, err := ac.Authorized(bearerRequest(t, "tok"))
	if err == nil {
		t.Fatal("expected error when WhoAmI unreachable and no stale cache")
	}
	if _, ok := err.(auth.Challenge); !ok {
		t.Fatalf("expected auth.Challenge, got %T: %v", err, err)
	}
}

// TestBothCachetiersWrittenOnSuccess verifies that a successful WhoAmI call
// populates both the fresh and stale cache keys.
func TestBothCachetiersWrittenOnSuccess(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs",
		Expression: `"devs" in principal["groups"]`,
	}}
	celEnv, _ := newCELEnv()
	compiled, _ := compilePolicies(policies, celEnv)

	cache := newMemCache()
	ac := &accessController{
		realm:      "r",
		service:    "s",
		whoAmIURL:  srv.URL,
		httpClient: srv.Client(),
		cache:      cache,
		cacheTTL:   5 * time.Minute,
		staleTTL:   time.Hour,
	}
	ac.policySet.Store(&policySet{policies: compiled})

	_, err := ac.Authorized(
		bearerRequest(t, "tok"),
		auth.Access{Resource: auth.Resource{Type: "repository", Name: "ns/img"}, Action: "pull"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	h := hashToken("tok")
	if _, ok := cache.load(ctx, whoAmIFreshKeyPrefix+h); !ok {
		t.Error("expected fresh cache entry after successful WhoAmI call")
	}
	if _, ok := cache.load(ctx, whoAmIStaleKeyPrefix+h); !ok {
		t.Error("expected stale cache entry after successful WhoAmI call")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
