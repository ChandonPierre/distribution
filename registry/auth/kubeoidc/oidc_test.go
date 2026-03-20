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
