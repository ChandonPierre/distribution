package kubeoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/distribution/distribution/v3/registry/auth"
)

// testServerState holds the state for a mock OIDC+JWKS server used in access controller tests.
type testServerState struct {
	key     *ecdsa.PrivateKey
	kid     string
	jwks    jose.JSONWebKeySet
	issuer  string
	service string
}

// newTestServer sets up a mock OIDC discovery + JWKS HTTP test server.
func newTestServer(t *testing.T) (*httptest.Server, *testServerState) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	state := &testServerState{
		key:     key,
		kid:     "test-kid",
		service: "registry.example.com",
	}
	state.jwks = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: state.kid, Algorithm: "ES256", Use: "sig"},
		},
	}

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidcDiscoveryDocument{
			Issuer:  state.issuer,
			JWKSURI: state.issuer + "/keys",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.jwks)
	})

	srv = httptest.NewServer(mux)
	state.issuer = srv.URL
	t.Cleanup(srv.Close)

	return srv, state
}

// makeToken creates a signed JWT with the given claims using the test server's key.
func makeToken(t *testing.T, state *testServerState, claims jwt.Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: state.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", state.kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// newTestController builds an accessController pointed at the test server.
func newTestController(t *testing.T, state *testServerState, policies []policyConfig) *accessController {
	t.Helper()

	options := map[string]any{
		"realm":   state.issuer + "/auth",
		"service": state.service,
		"issuers": []any{state.issuer},
		"policies": func() []any {
			result := make([]any, len(policies))
			for i, p := range policies {
				result[i] = map[string]any{"name": p.Name, "expression": p.Expression}
			}
			return result
		}(),
	}

	ctrl, err := newAccessController(options)
	if err != nil {
		t.Fatalf("newAccessController: %v", err)
	}
	return ctrl.(*accessController)
}

func validClaims(state *testServerState) jwt.Claims {
	now := time.Now()
	return jwt.Claims{
		Issuer:    state.issuer,
		Subject:   "system:serviceaccount:ci:builder",
		Audience:  jwt.Audience{state.service},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
	}
}

func makeRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// ---- Tests ----

func TestAuthorizedSuccess(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{Name: "allow-pull", Expression: `"pull" in request["actions"]`},
	}
	ctrl := newTestController(t, state, policies)

	token := makeToken(t, state, validClaims(state))
	req := makeRequest(token)

	grant, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "myorg/myimage"},
		Action:   "pull",
	})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if grant.User.Name != "system:serviceaccount:ci:builder" {
		t.Errorf("unexpected user: %s", grant.User.Name)
	}
	if len(grant.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(grant.Resources))
	}
}

func TestMissingToken(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestController(t, state, nil)

	req := makeRequest("") // no Authorization header
	_, err := ctrl.Authorized(req)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	ch, ok := err.(auth.Challenge)
	if !ok {
		t.Fatal("expected auth.Challenge error")
	}
	if ch.Error() != ErrTokenRequired.Error() {
		t.Errorf("expected ErrTokenRequired, got: %v", ch.Error())
	}
}

func TestMalformedToken(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestController(t, state, nil)

	req := makeRequest("not.a.valid.jwt.token")
	_, err := ctrl.Authorized(req)
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
	ch, ok := err.(auth.Challenge)
	if !ok {
		t.Fatal("expected auth.Challenge error")
	}
	if ch.Error() != ErrMalformedToken.Error() {
		t.Errorf("expected ErrMalformedToken, got: %v", ch.Error())
	}
}

func TestWrongIssuer(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{{Name: "allow", Expression: `true`}}
	ctrl := newTestController(t, state, policies)

	// Create a second key pair to sign with a different "issuer" claim.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherState := &testServerState{
		key:     otherKey,
		kid:     "other-kid",
		issuer:  "https://untrusted.example.com",
		service: state.service,
	}
	claims := validClaims(state)
	claims.Issuer = otherState.issuer

	token := makeToken(t, otherState, claims)
	req := makeRequest(token)

	_, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "pull",
	})
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestWrongAudience(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{{Name: "allow", Expression: `true`}}
	ctrl := newTestController(t, state, policies)

	claims := validClaims(state)
	claims.Audience = jwt.Audience{"wrong-audience"}
	token := makeToken(t, state, claims)
	req := makeRequest(token)

	_, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "pull",
	})
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	ch, _ := err.(auth.Challenge)
	if ch.Error() != ErrInvalidToken.Error() {
		t.Errorf("expected ErrInvalidToken, got: %v", ch.Error())
	}
}

func TestExpiredToken(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{{Name: "allow", Expression: `true`}}
	ctrl := newTestController(t, state, policies)

	past := time.Now().Add(-2 * time.Hour)
	claims := jwt.Claims{
		Issuer:    state.issuer,
		Subject:   "system:serviceaccount:ci:builder",
		Audience:  jwt.Audience{state.service},
		IssuedAt:  jwt.NewNumericDate(past),
		NotBefore: jwt.NewNumericDate(past),
		Expiry:    jwt.NewNumericDate(past.Add(time.Minute)), // expired 119 minutes ago
	}
	token := makeToken(t, state, claims)
	req := makeRequest(token)

	_, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "pull",
	})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	ch, _ := err.(auth.Challenge)
	if ch.Error() != ErrInvalidToken.Error() {
		t.Errorf("expected ErrInvalidToken, got: %v", ch.Error())
	}
}

func TestInsufficientScope(t *testing.T) {
	_, state := newTestServer(t)
	// Only allows pull, not push.
	policies := []policyConfig{
		{Name: "pull-only", Expression: `"pull" in request["actions"] && !("push" in request["actions"])`},
	}
	ctrl := newTestController(t, state, policies)

	token := makeToken(t, state, validClaims(state))
	req := makeRequest(token)

	_, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "push",
	})
	if err == nil {
		t.Fatal("expected error for insufficient scope")
	}
	ch, _ := err.(auth.Challenge)
	if ch.Error() != ErrInsufficientScope.Error() {
		t.Errorf("expected ErrInsufficientScope, got: %v", ch.Error())
	}
}

func TestMultiIssuerPolicy(t *testing.T) {
	_, stateA := newTestServer(t)
	_, stateB := newTestServer(t)

	// Build a controller that trusts both issuers.
	policies := []policyConfig{
		{
			Name:       "cluster-a-push",
			Expression: fmt.Sprintf(`token["iss"] == %q && "push" in request["actions"]`, stateA.issuer),
		},
		{
			Name:       "cluster-b-pull",
			Expression: fmt.Sprintf(`token["iss"] == %q && "pull" in request["actions"]`, stateB.issuer),
		},
	}

	options := map[string]any{
		"realm":   stateA.issuer + "/auth",
		"service": stateA.service,
		"issuers": []any{stateA.issuer, stateB.issuer},
		"policies": func() []any {
			result := make([]any, len(policies))
			for i, p := range policies {
				result[i] = map[string]any{"name": p.Name, "expression": p.Expression}
			}
			return result
		}(),
	}
	ctrlRaw, err := newAccessController(options)
	if err != nil {
		t.Fatalf("newAccessController: %v", err)
	}
	ctrl := ctrlRaw.(*accessController)

	// Cluster-A token should be able to push.
	tokenA := makeToken(t, stateA, validClaims(stateA))
	reqA := makeRequest(tokenA)
	_, err = ctrl.Authorized(reqA, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "push",
	})
	if err != nil {
		t.Errorf("expected cluster-A push to succeed, got: %v", err)
	}

	// Cluster-B token should be able to pull.
	claimsB := validClaims(stateA)
	claimsB.Issuer = stateB.issuer
	claimsB.Audience = jwt.Audience{stateB.service}
	tokenB := makeToken(t, stateB, claimsB)
	reqB := makeRequest(tokenB)
	_, err = ctrl.Authorized(reqB, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "pull",
	})
	if err != nil {
		t.Errorf("expected cluster-B pull to succeed, got: %v", err)
	}

	// Cluster-A token should not be able to pull (policy only grants push).
	_, err = ctrl.Authorized(makeRequest(tokenA), auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "repo"},
		Action:   "pull",
	})
	if err == nil {
		t.Error("expected cluster-A pull to be denied")
	}
}

func TestNewAccessControllerValidation(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]any
		wantErr bool
	}{
		{
			name: "missing realm",
			options: map[string]any{
				"service": "svc",
				"issuers": []any{"https://example.com"},
			},
			wantErr: true,
		},
		{
			name: "missing issuers",
			options: map[string]any{
				"realm":   "https://example.com/auth",
				"service": "svc",
			},
			wantErr: true,
		},
		{
			name: "token_issuer conflicts with trusted issuer (service default)",
			options: map[string]any{
				"realm":    "https://example.com/auth",
				"service":  "svc",
				"issuers":  []any{"svc"},
			},
			wantErr: true,
		},
		{
			name: "token_issuer conflicts with trusted issuer (explicit)",
			options: map[string]any{
				"realm":        "https://example.com/auth",
				"service":      "svc",
				"issuers":      []any{"https://kubernetes.default.svc"},
				"token_issuer": "https://kubernetes.default.svc",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newAccessController(tt.options)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewAccessControllerInvalidCEL(t *testing.T) {
	options := map[string]any{
		"realm":   "https://example.com/auth",
		"service": "svc",
		"issuers": []any{"https://example.com"},
		"policies": []any{
			map[string]any{
				"name":       "bad",
				"expression": "this === invalid",
			},
		},
	}
	_, err := newAccessController(options)
	if err == nil {
		t.Fatal("expected compile error for invalid CEL expression")
	}
}

func TestWWWAuthenticateHeader(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestController(t, state, nil)

	req := makeRequest("") // triggers ErrTokenRequired
	rw := httptest.NewRecorder()
	_, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "myrepo"},
		Action:   "pull",
	})
	if err == nil {
		t.Fatal("expected challenge error")
	}
	ch, ok := err.(auth.Challenge)
	if !ok {
		t.Fatal("expected auth.Challenge")
	}
	ch.SetHeaders(req, rw)

	header := rw.Header().Get("WWW-Authenticate")
	if header == "" {
		t.Fatal("expected WWW-Authenticate header to be set")
	}
	if !contains(header, "Bearer") {
		t.Errorf("expected Bearer in WWW-Authenticate, got: %s", header)
	}
	if !contains(header, "realm=") {
		t.Errorf("expected realm= in WWW-Authenticate, got: %s", header)
	}
	if !contains(header, "service=") {
		t.Errorf("expected service= in WWW-Authenticate, got: %s", header)
	}
}

// TestOrgIDAvailableInPolicy verifies that the X-Org-Id header from the JWKS
// endpoint is injected into the token map as "org_id" so CEL policies can use it.
func TestOrgIDAvailableInPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-kid"
	const wantOrgID = "coreweave-prod"

	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "ES256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcDiscoveryDocument{Issuer: issuer, JWKSURI: issuer + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Org-Id", wantOrgID)
		_ = json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)

	const service = "registry.example.com"
	options := map[string]any{
		"realm":   issuer + "/auth",
		"service": service,
		"issuers": []any{issuer},
		"policies": []any{
			map[string]any{
				"name":       "org-check",
				"expression": fmt.Sprintf(`token["org_id"] == %q`, wantOrgID),
			},
		},
	}
	ctrl, err := newAccessController(options)
	if err != nil {
		t.Fatalf("newAccessController: %v", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    issuer,
		Subject:   "system:serviceaccount:ci:builder",
		Audience:  jwt.Audience{service},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	rawToken, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	grant, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "ns/img"},
		Action:   "pull",
	})
	if err != nil {
		t.Fatalf("expected grant, got error: %v", err)
	}
	if grant == nil {
		t.Fatal("expected non-nil grant")
	}

	// Now verify that a policy matching a different org_id correctly denies.
	optionsDeny := map[string]any{
		"realm":   issuer + "/auth",
		"service": service,
		"issuers": []any{issuer},
		"policies": []any{
			map[string]any{
				"name":       "wrong-org",
				"expression": `token["org_id"] == "wrong-org"`,
			},
		},
	}
	ctrlDeny, err := newAccessController(optionsDeny)
	if err != nil {
		t.Fatalf("newAccessController deny: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req2.Header.Set("Authorization", "Bearer "+rawToken)

	_, err = ctrlDeny.Authorized(req2, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "ns/img"},
		Action:   "pull",
	})
	if err == nil {
		t.Fatal("expected denial when org_id does not match policy")
	}
	if _, ok := err.(auth.Challenge); !ok {
		t.Fatalf("expected auth.Challenge, got %T: %v", err, err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
