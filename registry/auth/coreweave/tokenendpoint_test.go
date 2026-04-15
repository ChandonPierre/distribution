package coreweave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/auth"
)

// newTestACWithTokenEndpoint builds an accessController with a token endpoint
// backed by the given WhoAmI test server.
func newTestACWithTokenEndpoint(t *testing.T, server *httptest.Server, policyCfgs []policyConfig) *accessController {
	t.Helper()
	celEnv, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compilePolicies(policyCfgs, celEnv)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ac := &accessController{
		realm:       "test-realm",
		service:     "test-service",
		whoAmIURL:   server.URL,
		httpClient:  server.Client(),
		cacheTTL:    defaultWhoAmICacheTTL,
		staleTTL:    defaultWhoAmIStaleTTL,
		tokenIssuer: "test-service",
	}
	ac.signingKey.Store(&signingKeyState{
		privateKey: key,
		publicKey:  &key.PublicKey,
	})
	ac.policySet.Store(&policySet{policies: compiled})
	ac.tokenEndpoint = &tokenEndpointHandler{
		ac:          ac,
		service:     "test-service",
		issuer:      "test-service",
		tokenExpiry: 5 * time.Minute,
		signingKey:  &ac.signingKey,
	}
	return ac
}

func basicAuthRequest(t *testing.T, password string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service", nil)
	if password != "" {
		r.SetBasicAuth("user", password)
	}
	return r
}

func TestTokenEndpointImplementsInterface(t *testing.T) {
	srv := newWhoAmIServer(t, http.StatusOK, &principal{Uid: "u1"})
	defer srv.Close()

	ac := newTestACWithTokenEndpoint(t, srv, nil)
	var _ auth.TokenEndpointer = ac
	h := ac.TokenHandler()
	if h == nil {
		t.Fatal("TokenHandler() returned nil")
	}
}

func TestTokenEndpointIssuesJWT(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs-pull",
		Expression: `"devs" in principal["groups"]`,
	}}
	ac := newTestACWithTokenEndpoint(t, srv, policies)

	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service&scope=repository:acme/img:pull", nil)
	r.SetBasicAuth("alice", "cw-token")

	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var resp tokenResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
	// Three-part JWT.
	if len(strings.Split(resp.Token, ".")) != 3 {
		t.Fatalf("expected a JWT, got: %s", resp.Token)
	}
}

func TestTokenEndpointRoundTrip(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs-pull",
		Expression: `"devs" in principal["groups"]`,
	}}
	ac := newTestACWithTokenEndpoint(t, srv, policies)

	// Step 1: exchange CoreWeave token for registry JWT.
	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service&scope=repository:acme/img:pull", nil)
	r.SetBasicAuth("alice", "cw-token")
	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %s", rw.Code, rw.Body.String())
	}
	var resp tokenResponse
	if err := json.NewDecoder(rw.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}

	// Step 2: use the registry JWT in Authorized — should bypass WhoAmI.
	req := httptest.NewRequest(http.MethodGet, "/v2/acme/img/manifests/latest", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)

	grant, err := ac.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "acme/img"},
		Action:   "pull",
	})
	if err != nil {
		t.Fatalf("Authorized returned error: %v", err)
	}
	if grant.User.Name != "alice" {
		t.Errorf("expected subject alice, got %q", grant.User.Name)
	}
}

func TestTokenEndpointInsufficientScope(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"viewers"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	// Only viewers can pull, not push.
	policies := []policyConfig{{
		Name:       "viewers-pull",
		Expression: `"viewers" in principal["groups"] && !("push" in request["actions"])`,
	}}
	ac := newTestACWithTokenEndpoint(t, srv, policies)

	// Request push scope — should get a token with no push access.
	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service&scope=repository:acme/img:push", nil)
	r.SetBasicAuth("alice", "cw-token")
	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 (empty grant), got %d", rw.Code)
	}

	var resp tokenResponse
	_ = json.NewDecoder(rw.Body).Decode(&resp)

	// Attempt to use the zero-access token for push.
	req := httptest.NewRequest(http.MethodGet, "/v2/acme/img/manifests/latest", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)

	_, err := ac.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "acme/img"},
		Action:   "push",
	})
	if err == nil {
		t.Fatal("expected insufficient_scope error")
	}
}

func TestTokenEndpointBadCredentials(t *testing.T) {
	srv := newWhoAmIServer(t, http.StatusUnauthorized, nil)
	defer srv.Close()

	ac := newTestACWithTokenEndpoint(t, srv, nil)

	rw := httptest.NewRecorder()
	r := basicAuthRequest(t, "bad-token")
	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rw.Code)
	}
}

func TestTokenEndpointAnonymousNoAccess(t *testing.T) {
	srv := newWhoAmIServer(t, http.StatusOK, &principal{Uid: "u1"})
	defer srv.Close()

	// Policy requires group membership — anonymous cannot satisfy it.
	policies := []policyConfig{{
		Name:       "members-only",
		Expression: `"members" in principal["groups"]`,
	}}
	ac := newTestACWithTokenEndpoint(t, srv, policies)

	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service&scope=repository:img:pull", nil)
	// No Authorization header — anonymous.
	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous with no access, got %d", rw.Code)
	}
}

func TestTokenEndpointMethodNotAllowed(t *testing.T) {
	srv := newWhoAmIServer(t, http.StatusOK, &principal{Uid: "u1"})
	defer srv.Close()

	ac := newTestACWithTokenEndpoint(t, srv, nil)

	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/auth/token", nil)
	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rw.Code)
	}
}

func TestAuthorizedRegistryJWTBypassesWhoAmI(t *testing.T) {
	// WhoAmI server that fails every request — registry JWT must not hit it.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &principal{Uid: "alice", OrgUid: "acme", Groups: []string{"devs"}}
	policies := []policyConfig{{
		Name:       "devs-pull",
		Expression: `"devs" in principal["groups"]`,
	}}

	// Use a separate healthy WhoAmI server just for token issuance.
	issueSrv := newWhoAmIServer(t, http.StatusOK, p)
	defer issueSrv.Close()

	ac := newTestACWithTokenEndpoint(t, issueSrv, policies)

	// Issue a registry JWT.
	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service&scope=repository:acme/img:pull", nil)
	r.SetBasicAuth("alice", "cw-token")
	ac.TokenHandler().ServeHTTP(rw, r)
	if rw.Code != http.StatusOK {
		t.Fatalf("token issuance failed: %d", rw.Code)
	}
	var resp tokenResponse
	_ = json.NewDecoder(rw.Body).Decode(&resp)

	// Now point ac at the broken WhoAmI server.
	ac.whoAmIURL = srv.URL
	ac.httpClient = srv.Client()

	req := httptest.NewRequest(http.MethodGet, "/v2/acme/img/manifests/latest", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)

	_, err := ac.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "acme/img"},
		Action:   "pull",
	})
	if err != nil {
		t.Fatalf("Authorized failed even though WhoAmI should not have been called: %v", err)
	}
	if callCount != 0 {
		t.Errorf("expected 0 WhoAmI calls for registry JWT, got %d", callCount)
	}
}

func TestAuthorizedFallsBackToWhoAmIForNonRegistryJWT(t *testing.T) {
	p := &principal{Uid: "bob", OrgUid: "acme", Groups: []string{"devs"}}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:       "devs-pull",
		Expression: `"devs" in principal["groups"]`,
	}}
	ac := newTestACWithTokenEndpoint(t, srv, policies)

	// An opaque (non-JWT) CoreWeave token.
	opaqueToken := base64.RawURLEncoding.EncodeToString([]byte("opaque-coreweave-token"))
	req := httptest.NewRequest(http.MethodGet, "/v2/acme/img/manifests/latest", nil)
	req.Header.Set("Authorization", "Bearer "+opaqueToken)

	grant, err := ac.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "acme/img"},
		Action:   "pull",
	})
	if err != nil {
		t.Fatalf("expected grant via WhoAmI, got error: %v", err)
	}
	if grant.User.Name != "bob" {
		t.Errorf("expected bob, got %q", grant.User.Name)
	}
}

func TestTokenEndpointCatalogPrefixes(t *testing.T) {
	p := &principal{Uid: "alice", OrgUid: "acme"}
	srv := newWhoAmIServer(t, http.StatusOK, p)
	defer srv.Close()

	policies := []policyConfig{{
		Name:                    "tenant-prefix",
		Expression:              `principal["org_uid"] != ""`,
		CatalogPrefixExpression: `principal["org_uid"]`,
	}}
	ac := newTestACWithTokenEndpoint(t, srv, policies)

	rw := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/token?service=test-service&scope=registry:catalog:*", nil)
	r.SetBasicAuth("alice", "cw-token")
	ac.TokenHandler().ServeHTTP(rw, r)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp tokenResponse
	_ = json.NewDecoder(rw.Body).Decode(&resp)
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Use the token in Authorized and check CatalogPrefixes.
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	grant, err := ac.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "registry", Name: "catalog"},
		Action:   "*",
	})
	if err != nil {
		t.Fatalf("Authorized error: %v", err)
	}
	if len(grant.CatalogPrefixes) != 1 || grant.CatalogPrefixes[0] != "acme" {
		t.Errorf("expected CatalogPrefixes=[acme], got %v", grant.CatalogPrefixes)
	}
}

func TestSigningKeyReloaderHotSwap(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var ptr atomic.Pointer[signingKeyState]
	ptr.Store(&signingKeyState{privateKey: key1, publicKey: &key1.PublicKey})

	// Simulate a key swap (hot reload).
	ptr.Store(&signingKeyState{privateKey: key2, publicKey: &key2.PublicKey})

	loaded := ptr.Load()
	if loaded.publicKey != &key2.PublicKey {
		t.Error("expected key2 after hot swap")
	}
}

func TestQualifyScope(t *testing.T) {
	cases := []struct {
		scope     string
		namespace string
		want      string
	}{
		// No namespace — pass through unchanged.
		{"repository:image:pull", "", "repository:image:pull"},
		// Already qualified — no double-prefix.
		{"repository:foo/image:pull", "foo", "repository:foo/image:pull"},
		// Multi-level path already under namespace — no double-prefix.
		{"repository:foo/bar/image:pull", "foo", "repository:foo/bar/image:pull"},
		// Multi-level path not under namespace — prepend namespace.
		{"repository:bar/image:pull", "foo", "repository:foo/bar/image:pull"},
		// Unqualified repository — prepend namespace.
		{"repository:image:pull", "foo", "repository:foo/image:pull"},
		{"repository:image:pull,push", "ns", "repository:ns/image:pull,push"},
		// Non-repository scopes are untouched.
		{"registry:catalog:*", "ns", "registry:catalog:*"},
		// Malformed scope — pass through unchanged.
		{"badscope", "ns", "badscope"},
	}
	for _, tc := range cases {
		got := qualifyScope(tc.scope, tc.namespace)
		if got != tc.want {
			t.Errorf("qualifyScope(%q, %q) = %q; want %q", tc.scope, tc.namespace, got, tc.want)
		}
	}
}
