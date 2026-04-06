package kubeoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// setupMockOIDCServer creates a test HTTP server that serves OIDC discovery + JWKS.
func setupMockOIDCServer(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "test-kid", Algorithm: "ES256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidcDiscoveryDocument{
			Issuer:  serverURL,
			JWKSURI: serverURL + "/keys",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})

	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	t.Cleanup(srv.Close)

	return srv, key, serverURL
}

func TestOIDCDiscoverySuccess(t *testing.T) {
	srv, _, issuer := setupMockOIDCServer(t)
	_ = srv

	client := &http.Client{Timeout: 5 * time.Second}
	cache, err := newJWKSCache(issuer, time.Hour, client)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	keys := cache.getKeys()
	if keys == nil || len(keys.Keys) == 0 {
		t.Fatal("expected non-empty JWKS after discovery")
	}
}

func TestOIDCDiscoveryJWKSFetchFails(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "kid", Algorithm: "ES256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, _ := json.Marshal(jwks)
	_ = jwksBytes

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidcDiscoveryDocument{
			Issuer:  serverURL,
			JWKSURI: serverURL + "/keys",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := newJWKSCache(serverURL, time.Hour, client)
	if err == nil {
		t.Fatal("expected error when JWKS fetch fails")
	}
}

func TestJWKSRotationOnUnknownKID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var rotated bool
	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidcDiscoveryDocument{
			Issuer:  serverURL,
			JWKSURI: serverURL + "/keys",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		kid := "original-kid"
		if rotated {
			kid = "rotated-kid"
		}
		jwk := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		_ = json.NewEncoder(w).Encode(jwks)
	})

	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	cache, err := newJWKSCache(serverURL, time.Hour, client)
	if err != nil {
		t.Fatal(err)
	}

	// Initially no rotated-kid.
	keys := cache.getKeys()
	if len(keys.Key("rotated-kid")) != 0 {
		t.Fatal("unexpected rotated-kid before rotation")
	}

	// Simulate rotation.
	rotated = true

	// syncRefresh should pick up the new key.
	if err := cache.syncRefresh(); err != nil {
		t.Fatal(err)
	}

	keys = cache.getKeys()
	if len(keys.Key("rotated-kid")) == 0 {
		t.Fatal("expected rotated-kid after sync refresh")
	}
}

func TestJWKSLazyRefresh(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "original-kid"

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidcDiscoveryDocument{
			Issuer:  serverURL,
			JWKSURI: serverURL + "/keys",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	// Very short refresh interval to trigger stale detection.
	cache, err := newJWKSCache(serverURL, 1*time.Millisecond, client)
	if err != nil {
		t.Fatal(err)
	}

	// Sleep past the refresh interval.
	time.Sleep(10 * time.Millisecond)

	// getKeys() should trigger a background refresh but not block.
	keys := cache.getKeys()
	if keys == nil {
		t.Fatal("expected non-nil keys even during stale period")
	}

	// Allow the background refresh to complete.
	time.Sleep(50 * time.Millisecond)
}

func TestUntrustedIssuerRejected(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	m := newIssuerCacheMap([]string{"https://trusted.example.com"}, time.Hour, client)

	_, err := m.getCache("https://untrusted.example.com")
	if err == nil {
		t.Fatal("expected error for untrusted issuer")
	}
}

func TestIsTrusted(t *testing.T) {
	issuers := []string{
		"https://exact.example.com",
		"https://oidc.example.com/id/*",
		"https://oidc-staging.cks.coreweave.com/id/*",
	}
	client := &http.Client{Timeout: 5 * time.Second}
	m := newIssuerCacheMap(issuers, time.Hour, client)

	tests := []struct {
		issuer  string
		trusted bool
	}{
		// Exact match.
		{"https://exact.example.com", true},
		// Exact issuer doesn't match a different host.
		{"https://other.example.com", false},
		// Prefix match — tenant UUID under the path.
		{"https://oidc.example.com/id/75d1413a-39ef-42da-aa33-3283236e28de", true},
		// Prefix match — different UUID same host.
		{"https://oidc.example.com/id/00000000-0000-0000-0000-000000000000", true},
		// Wildcard entry itself is not a valid issuer (trailing * stripped, empty suffix would still match prefix).
		{"https://oidc.example.com/id/", true},
		// Different host that shares a prefix string shouldn't match.
		{"https://oidc.example.com.evil.com/id/tenant", false},
		// Path that doesn't start with the prefix.
		{"https://oidc.example.com/other/tenant", false},
		// Staging wildcard matches.
		{"https://oidc-staging.cks.coreweave.com/id/75d1413a-39ef-42da-aa33-3283236e28de", true},
		// Staging wildcard does not match prod host.
		{"https://oidc.cks.coreweave.com/id/75d1413a-39ef-42da-aa33-3283236e28de", false},
		// Empty issuer is not trusted.
		{"", false},
	}

	for _, tt := range tests {
		got := m.isTrusted(tt.issuer)
		if got != tt.trusted {
			t.Errorf("isTrusted(%q) = %v, want %v", tt.issuer, got, tt.trusted)
		}
	}
}

func TestNewIssuerCacheMapSeparatesExactAndPrefix(t *testing.T) {
	issuers := []string{
		"https://exact.example.com",
		"https://prefix.example.com/id/*",
	}
	client := &http.Client{Timeout: 5 * time.Second}
	m := newIssuerCacheMap(issuers, time.Hour, client)

	if !m.exactIssuers["https://exact.example.com"] {
		t.Error("exact issuer not in exactIssuers map")
	}
	if m.exactIssuers["https://prefix.example.com/id/*"] {
		t.Error("wildcard entry should not be in exactIssuers map")
	}
	if len(m.prefixIssuers) != 1 {
		t.Fatalf("expected 1 prefix, got %d", len(m.prefixIssuers))
	}
	if m.prefixIssuers[0] != "https://prefix.example.com/id/" {
		t.Errorf("prefix stored as %q, want %q", m.prefixIssuers[0], "https://prefix.example.com/id/")
	}
}

func TestGetCacheWildcardIssuer(t *testing.T) {
	// The mock OIDC server's URL is not known at construction time, so we set up
	// the issuer cache with a prefix derived from a common base URL, then confirm
	// that getCache succeeds for the concrete tenant issuer.
	srv, _, baseURL := setupMockOIDCServer(t)
	_ = srv

	// Simulate a wildcard config: trust any issuer under baseURL + "/id/".
	wildcard := baseURL + "/id/*"
	concreteIssuer := baseURL + "/id/some-tenant-uuid"

	// The mock server's discovery endpoint serves the baseURL as issuer, but for
	// this test we only care that getCache doesn't reject on the trusted-issuer
	// check. The OIDC discovery will fail (no /id/some-tenant-uuid path) which
	// is expected — we just want to confirm the trust check passes.
	client := &http.Client{Timeout: 5 * time.Second}
	m := newIssuerCacheMap([]string{wildcard}, time.Hour, client)

	if !m.isTrusted(concreteIssuer) {
		t.Fatalf("isTrusted(%q) = false with wildcard %q", concreteIssuer, wildcard)
	}

	// getCache will attempt OIDC discovery for the concrete issuer and fail
	// (no discovery doc at that path), but the error must NOT be "untrusted issuer".
	_, err := m.getCache(concreteIssuer)
	if err == nil {
		t.Fatal("expected OIDC discovery error, got nil")
	}
	if err.Error() == "kubeoidc: issuer \""+concreteIssuer+"\" is not in the trusted issuers list" {
		t.Errorf("getCache returned untrusted-issuer error but issuer should be trusted; got: %v", err)
	}
}

func TestOrgIDStoredFromJWKSHeader(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "kid", Algorithm: "ES256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	const wantOrgID = "org-abc-123"
	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{Issuer: serverURL, JWKSURI: serverURL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Org-Id", wantOrgID)
		_, _ = w.Write(jwksBytes)
	})
	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	cache, err := newJWKSCache(serverURL, time.Hour, client)
	if err != nil {
		t.Fatalf("newJWKSCache: %v", err)
	}
	if got := cache.getOrgID(); got != wantOrgID {
		t.Errorf("getOrgID() = %q, want %q", got, wantOrgID)
	}
}

func TestOrgIDEmptyWhenHeaderAbsent(t *testing.T) {
	srv, _, issuer := setupMockOIDCServer(t) // does NOT set X-Org-Id
	_ = srv

	client := &http.Client{Timeout: 5 * time.Second}
	cache, err := newJWKSCache(issuer, time.Hour, client)
	if err != nil {
		t.Fatalf("newJWKSCache: %v", err)
	}
	if got := cache.getOrgID(); got != "" {
		t.Errorf("getOrgID() = %q, want empty string", got)
	}
}

func TestOrgIDUpdatedOnRefresh(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "kid", Algorithm: "ES256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	orgID := "first-org"
	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{Issuer: serverURL, JWKSURI: serverURL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Org-Id", orgID)
		_, _ = w.Write(jwksBytes)
	})
	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second}
	cache, err := newJWKSCache(serverURL, time.Hour, client)
	if err != nil {
		t.Fatalf("newJWKSCache: %v", err)
	}
	if got := cache.getOrgID(); got != "first-org" {
		t.Errorf("initial getOrgID() = %q, want %q", got, "first-org")
	}

	// Simulate the org ID changing on the server (e.g. issuer migration).
	orgID = "second-org"
	if err := cache.syncRefresh(); err != nil {
		t.Fatalf("syncRefresh: %v", err)
	}
	if got := cache.getOrgID(); got != "second-org" {
		t.Errorf("after refresh getOrgID() = %q, want %q", got, "second-org")
	}
}

func TestGetCacheExactIssuerStillWorks(t *testing.T) {
	srv, _, issuer := setupMockOIDCServer(t)
	_ = srv

	client := &http.Client{Timeout: 5 * time.Second}
	m := newIssuerCacheMap([]string{issuer}, time.Hour, client)

	cache, err := m.getCache(issuer)
	if err != nil {
		t.Fatalf("expected no error for exact trusted issuer, got: %v", err)
	}
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
}
