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
	"runtime"
	"strings"
	"sync/atomic"
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
	if err := parsedToken.Claims(ctrl.signingKey.Load().publicKey, &claims); err != nil {
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

	// No credentials, no matching anonymous policy, scope requested: must return
	// 401 so that clients with imagepullsecrets / credential providers fall back
	// to retrying with their SA JWT instead of using a zero-access token.
	rw := callTokenEndpoint(t, ctrl, "", "", []string{"repository:myimage:pull"})
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rw.Code, rw.Body.String())
	}
	if rw.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header in response")
	}
}

func TestTokenEndpointAnonymousGranted(t *testing.T) {
	_, state := newTestServer(t)
	policies := []policyConfig{
		{
			Name: "anon-pull",
			Expression: `request["type"] == "repository" &&
request["repository"] == "publicimg" &&
"pull" in request["actions"]`,
		},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, nil)

	// Anonymous request matching the policy should receive a token with pull access.
	rw := callTokenEndpoint(t, ctrl, "", "", []string{"repository:publicimg:pull"})
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	var claims registryClaims
	parsedToken, err := jwt.ParseSigned(resp.Token, defaultSigningAlgorithms)
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	if err := parsedToken.Claims(ctrl.signingKey.Load().publicKey, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "publicimg" {
		t.Fatalf("expected access to publicimg, got %v", claims.Access)
	}
	if len(claims.Access[0].Actions) != 1 || claims.Access[0].Actions[0] != "pull" {
		t.Errorf("expected only pull, got %v", claims.Access[0].Actions)
	}
}

// TestTokenEndpointAnonymousNoGrantFallback is a regression test for the bug
// introduced in 32b5f9b: Docker/containerd clients first attempt a token fetch
// without credentials. When no anonymous policy grants the requested scope the
// token endpoint must return 401 so the client retries with its imagepullsecret
// / kubelet credential provider SA JWT.  Returning 200 with an empty-access
// token caused the registry to reply with "insufficient scope" instead.
func TestTokenEndpointAnonymousNoGrantFallback(t *testing.T) {
	_, state := newTestServer(t)
	// Policy requires a valid token — anonymous requests must not match.
	policies := []policyConfig{
		{Name: "sa-pull", Expression: `token["sub"] != "" && "pull" in request["actions"]`},
	}
	ctrl := newTestControllerWithOptions(t, state, policies, nil)

	// Anonymous request (no Authorization header) must return 401, not 200.
	rw := callTokenEndpoint(t, ctrl, "", "", []string{"repository:myimage:pull"})
	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for anonymous+no-grant, got %d: %s", rw.Code, rw.Body.String())
	}
	if rw.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header so the client can retry with credentials")
	}

	// Authenticated request with a valid SA token must still succeed.
	saToken := makeToken(t, state, validClaims(state))
	rw = callTokenEndpoint(t, ctrl, "user", saToken, []string{"repository:myimage:pull"})
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated request, got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestTokenEndpointEmptyPassword(t *testing.T) {
	// Regression: imagepullsecrets/kubelet credential provider sending Basic auth
	// with an empty password (stale/expired credentials) must return 401, not a
	// zero-access token that later produces "insufficient scope" from the registry.
	_, state := newTestServer(t)
	ctrl := newTestControllerWithOptions(t, state, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/token?service="+ctrl.service+"&scope=repository:myimage:pull", nil)
	req.SetBasicAuth("user", "") // non-empty username, empty password
	rw := httptest.NewRecorder()
	ctrl.TokenHandler().ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rw.Code, rw.Body.String())
	}
	if rw.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header in response")
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
	if err := parsedToken.Claims(ctrl.signingKey.Load().publicKey, &claims); err != nil {
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
		if id == "" {
			t.Error("expected non-empty JWK thumbprint key ID")
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
		want, err := publicKeyThumbprint(&k.PublicKey)
		if err != nil {
			t.Fatalf("thumbprint: %v", err)
		}
		if id != want {
			t.Errorf("expected key ID == %q (JWK thumbprint), got %q", want, id)
		}

		// Different key material must produce a different kid so JWKS entries
		// don't collide under hot-reload.
		k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		path2 := writePEMKey(t, k2)
		_, id2, err := loadOrGenerateSigningKey(path2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id == id2 {
			t.Error("expected distinct kids for distinct keys")
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

func TestSigningKeyReloaderExitsOnStop(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	path := writePEMKey(t, k)

	var ptr atomic.Pointer[signingKeyState]
	_, kid, err := loadOrGenerateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	ptr.Store(&signingKeyState{privateKey: k, publicKey: &k.PublicKey, keyID: kid})

	// Let the runtime quiesce before sampling, so unrelated test
	// goroutines don't inflate the baseline.
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	stop := make(chan struct{})
	startSigningKeyReloader(stop, path, 10*time.Millisecond, &ptr)

	// Give the reloader a few ticks, then confirm it's live.
	time.Sleep(50 * time.Millisecond)
	if runtime.NumGoroutine() <= baseline {
		t.Fatalf("expected reloader goroutine to be running; NumGoroutine=%d, baseline=%d",
			runtime.NumGoroutine(), baseline)
	}

	close(stop)

	// The reloader should exit within a few ticks of stop being closed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return // reloader exited as expected
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("reloader goroutine did not exit after stop; NumGoroutine=%d, baseline=%d",
		runtime.NumGoroutine(), baseline)
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

func TestSubdomainNamespace(t *testing.T) {
	realm := "https://example.com/auth/token"
	cases := []struct {
		reqHost string
		want    string
	}{
		{"foo.example.com", "foo"},
		{"example.com", ""},               // base domain — no subdomain
		{"foo.unrelated.com", ""},         // different domain entirely
		{"a.b.example.com", ""},           // multi-level subdomain — not a direct subdomain
		{"foo.example.com:443", "foo"},    // with port
	}
	for _, tc := range cases {
		got := subdomainNamespace(tc.reqHost, realm)
		if got != tc.want {
			t.Errorf("subdomainNamespace(%q, realm) = %q; want %q", tc.reqHost, got, tc.want)
		}
	}
}

func TestSetHeadersRealmSubdomain(t *testing.T) {
	ch := authChallenge{
		err:     ErrTokenRequired,
		realm:   "https://registry.example.com/auth/token",
		service: "registry.example.com",
	}

	// Request arriving on the subdomain — realm host should be rewritten.
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "foo.registry.example.com"
	rw := httptest.NewRecorder()
	ch.SetHeaders(req, rw)
	got := rw.Result().Header.Get("WWW-Authenticate")
	wantRealm := `realm="https://foo.registry.example.com/auth/token"`
	if !strings.Contains(got, wantRealm) {
		t.Errorf("subdomain request: expected realm rewrite in WWW-Authenticate\n  got:  %s\n  want substring: %s", got, wantRealm)
	}

	// Request arriving on the base domain — realm should be unchanged.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req2.Host = "registry.example.com"
	rw2 := httptest.NewRecorder()
	ch.SetHeaders(req2, rw2)
	got2 := rw2.Result().Header.Get("WWW-Authenticate")
	wantRealm2 := `realm="https://registry.example.com/auth/token"`
	if !strings.Contains(got2, wantRealm2) {
		t.Errorf("base domain request: expected unchanged realm\n  got:  %s\n  want substring: %s", got2, wantRealm2)
	}

	// Deep subdomain — should not be rewritten (only direct subdomains are scoped).
	req3 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req3.Host = "a.b.registry.example.com"
	rw3 := httptest.NewRecorder()
	ch.SetHeaders(req3, rw3)
	got3 := rw3.Result().Header.Get("WWW-Authenticate")
	if !strings.Contains(got3, wantRealm2) {
		t.Errorf("deep subdomain: expected unchanged realm\n  got:  %s\n  want substring: %s", got3, wantRealm2)
	}
}
