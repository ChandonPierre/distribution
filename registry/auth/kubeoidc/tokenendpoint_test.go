package kubeoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/distribution/distribution/v3/registry/auth"
)

// newTestControllerWithOptions creates a controller with extra options merged in.
func newTestControllerWithOptions(t *testing.T, state *testServerState, policies []policyConfig, extra map[string]any) *accessController {
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
	maps.Copy(options, extra)

	ctrl, err := newAccessController(options)
	if err != nil {
		t.Fatalf("newAccessController: %v", err)
	}
	return ctrl.(*accessController)
}

// callTokenEndpoint performs a GET /auth/token request against the controller's token handler.
func callTokenEndpoint(t *testing.T, ctrl *accessController, username, password string, scopes []string) *httptest.ResponseRecorder {
	t.Helper()

	q := url.Values{"service": {ctrl.service}}
	for _, s := range scopes {
		q.Add("scope", s)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/token?"+q.Encode(), nil)
	if password != "" {
		req.SetBasicAuth(username, password)
	}

	rw := httptest.NewRecorder()
	ctrl.TokenHandler().ServeHTTP(rw, req)
	return rw
}

func TestTokenEndpointSuccess(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{Name: "allow-pull", Expression: `"pull" in request["actions"]`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, nil)

	saToken := makeToken(t, state, validClaims(state))
	rw := callTokenEndpoint(t, ctrl, "user", saToken, []string{"repository:myimage:pull"})

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expected positive expires_in, got %d", resp.ExpiresIn)
	}
}

func TestTokenEndpointDeniedScopeOmitted(t *testing.T) {
	_, state := newTestServer(t)
	// Only pull is allowed.
	policies := []policyConfig{
		{Name: "pull-only", Expression: `"pull" in request["actions"]`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, nil)

	saToken := makeToken(t, state, validClaims(state))
	// Request both pull and push; push should be silently omitted.
	rw := callTokenEndpoint(t, ctrl, "user", saToken, []string{"repository:myimage:pull,push"})

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// Parse the issued token and check that only "pull" is in the access list.
	var claims registryClaims
	parsedToken, err := jwt.ParseSigned(resp.Token, defaultSigningAlgorithms)
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	if err := parsedToken.Claims(ctrl.localSigningKey, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}

	if len(claims.Access) != 1 {
		t.Fatalf("expected 1 access entry, got %d", len(claims.Access))
	}
	if claims.Access[0].Actions[0] != "pull" {
		t.Errorf("expected only pull, got %v", claims.Access[0].Actions)
	}
}

func TestTokenEndpointMissingCredentials(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil)

	// No credentials at all.
	rw := callTokenEndpoint(t, ctrl, "", "", []string{"repository:myimage:pull"})
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestTokenEndpointMalformedSAToken(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil)

	rw := callTokenEndpoint(t, ctrl, "user", "not.a.valid.jwt", nil)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestTokenEndpointUntrustedIssuer(t *testing.T) {
	_, state := newTestServer(t)
	// Second state has a different server (different issuer URL).
	_, otherState := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil) // only trusts state's issuer

	badToken := makeToken(t, otherState, jwt.Claims{
		Issuer:    otherState.issuer,
		Subject:   "system:serviceaccount:ci:builder",
		Audience:  jwt.Audience{state.service},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	rw := callTokenEndpoint(t, ctrl, "user", badToken, nil)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestTokenEndpointExpiredSAToken(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil)

	past := time.Now().Add(-2 * time.Hour)
	expiredClaims := jwt.Claims{
		Issuer:    state.issuer,
		Subject:   "system:serviceaccount:ci:builder",
		Audience:  jwt.Audience{state.service},
		IssuedAt:  jwt.NewNumericDate(past),
		NotBefore: jwt.NewNumericDate(past),
		Expiry:    jwt.NewNumericDate(past.Add(time.Minute)),
	}
	expiredToken := makeToken(t, state, expiredClaims)

	rw := callTokenEndpoint(t, ctrl, "user", expiredToken, nil)
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rw.Code)
	}
}

func TestTokenEndpointMethodNotAllowed(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/auth/token", nil)
	rw := httptest.NewRecorder()
	ctrl.TokenHandler().ServeHTTP(rw, req)

	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rw.Code)
	}
}

// TestAuthorizeRegistryToken verifies the full round-trip:
// SA token → token endpoint → registry JWT → Authorized()
func TestAuthorizeRegistryToken(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{Name: "allow-all", Expression: `true`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, map[string]any{
		"token_expiry": "10m",
	})

	// Step 1: Exchange SA token for registry JWT at the token endpoint.
	saToken := makeToken(t, state, validClaims(state))
	rw := callTokenEndpoint(t, ctrl, "user", saToken, []string{"repository:myimage:pull"})

	if rw.Code != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %s", rw.Code, rw.Body.String())
	}

	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Step 2: Use the registry JWT in Authorized().
	req := makeRequest(resp.Token)
	grant, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "myimage"},
		Action:   "pull",
	})
	if err != nil {
		t.Fatalf("Authorized with registry token failed: %v", err)
	}
	if grant.User.Name != "system:serviceaccount:ci:builder" {
		t.Errorf("unexpected user: %q", grant.User.Name)
	}
}

func TestAuthorizeRegistryTokenInsufficientScope(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{Name: "allow-all", Expression: `true`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, nil)

	// Token endpoint grants only pull.
	saToken := makeToken(t, state, validClaims(state))
	rw := callTokenEndpoint(t, ctrl, "user", saToken, []string{"repository:myimage:pull"})

	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Try to push with a pull-only token → should fail.
	req := makeRequest(resp.Token)
	_, err := ctrl.Authorized(req, auth.Access{
		Resource: auth.Resource{Type: "repository", Name: "myimage"},
		Action:   "push",
	})
	if err == nil {
		t.Fatal("expected insufficient scope error")
	}
	ch, ok := err.(auth.Challenge)
	if !ok {
		t.Fatal("expected auth.Challenge")
	}
	if ch.Error() != ErrInsufficientScope.Error() {
		t.Errorf("expected ErrInsufficientScope, got: %v", ch.Error())
	}
}

// TestTokenImplementsInterface verifies that accessController satisfies auth.TokenEndpointer.
func TestTokenImplementsInterface(t *testing.T) {
	_, state := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil)

	var _ interface{ TokenHandler() http.Handler } = ctrl
	h := ctrl.TokenHandler()
	if h == nil {
		t.Fatal("TokenHandler() returned nil")
	}
}

func TestTokenEndpointCustomExpiry(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{Name: "allow", Expression: `true`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, map[string]any{
		"token_expiry": "2m",
	})

	saToken := makeToken(t, state, validClaims(state))
	rw := callTokenEndpoint(t, ctrl, "user", saToken, []string{"repository:myimage:pull"})

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}

	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.ExpiresIn != 120 {
		t.Errorf("expected expires_in=120, got %d", resp.ExpiresIn)
	}
}

func TestTokenEndpointMultipleScopes(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{Name: "allow-repo-a", Expression: `request["repository"] == "repoA" && "pull" in request["actions"]`},
		{Name: "allow-repo-b", Expression: `request["repository"] == "repoB" && "pull" in request["actions"]`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, nil)

	saToken := makeToken(t, state, validClaims(state))
	rw := callTokenEndpoint(t, ctrl, "user", saToken, []string{
		"repository:repoA:pull",
		"repository:repoB:pull",
		"repository:repoC:pull", // denied by policy
	})

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}

	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var claims registryClaims
	parsedToken, err := jwt.ParseSigned(resp.Token, defaultSigningAlgorithms)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsedToken.Claims(ctrl.localSigningKey, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}

	if len(claims.Access) != 2 {
		names := make([]string, len(claims.Access))
		for i, a := range claims.Access {
			names[i] = fmt.Sprintf("%s:%v", a.Name, a.Actions)
		}
		t.Errorf("expected 2 granted scopes, got %d: %s", len(claims.Access), strings.Join(names, ", "))
	}
}

// writePEMKey writes a PEM-encoded EC PRIVATE KEY to a temp file and returns its path.
func writePEMKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "signing-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoadOrGenerateSigningKey(t *testing.T) {
	t.Run("ephemeral when no path", func(t *testing.T) {
		key, id, err := loadOrGenerateSigningKey("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key == nil {
			t.Fatal("expected non-nil key")
		}
		if id != "" {
			t.Errorf("expected empty key ID for ephemeral key, got %q", id)
		}
		if key.Curve != elliptic.P256() {
			t.Errorf("expected P-256, got %s", key.Curve.Params().Name)
		}
	})

	t.Run("valid P-256 key", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		path := writePEMKey(t, k)
		key, id, err := loadOrGenerateSigningKey(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key.Curve != elliptic.P256() {
			t.Errorf("expected P-256, got %s", key.Curve.Params().Name)
		}
		if id != path {
			t.Errorf("expected key ID == path, got %q", id)
		}
	})

	t.Run("P-384 key rejected", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		path := writePEMKey(t, k)
		_, _, err := loadOrGenerateSigningKey(path)
		if err == nil {
			t.Fatal("expected error for P-384 key, got nil")
		}
		if !strings.Contains(err.Error(), "P-256") {
			t.Errorf("expected error to mention P-256, got: %v", err)
		}
	})

	t.Run("P-521 key rejected", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		path := writePEMKey(t, k)
		_, _, err := loadOrGenerateSigningKey(path)
		if err == nil {
			t.Fatal("expected error for P-521 key, got nil")
		}
		if !strings.Contains(err.Error(), "P-256") {
			t.Errorf("expected error to mention P-256, got: %v", err)
		}
	})

	t.Run("P-384 PKCS8 key rejected", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp(t.TempDir(), "signing-*.pem")
		if err != nil {
			t.Fatal(err)
		}
		if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
			t.Fatal(err)
		}
		f.Close()
		_, _, err = loadOrGenerateSigningKey(f.Name())
		if err == nil {
			t.Fatal("expected error for PKCS8 P-384 key, got nil")
		}
		if !strings.Contains(err.Error(), "P-256") {
			t.Errorf("expected error to mention P-256, got: %v", err)
		}
	})
}
