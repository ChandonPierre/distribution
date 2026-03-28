package kubeoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirupsen/logrus"
)

// tokenResponse is the JSON body returned by the token endpoint.
// It follows the Docker Registry Token Authentication specification.
type tokenResponse struct {
	Token       string    `json:"token"`
	AccessToken string    `json:"access_token"` // alias, same value
	ExpiresIn   int       `json:"expires_in"`
	IssuedAt    time.Time `json:"issued_at"`
}

// registryClaims is the JWT payload for registry-issued tokens.
type registryClaims struct {
	josejwt.Claims
	Access          []resourceActions `json:"access"`
	// CatalogPrefixes, when present, restricts /v2/_catalog responses to
	// repositories whose names start with one of the listed prefixes.
	CatalogPrefixes []string          `json:"catalog_prefixes,omitempty"`
}

// resourceActions mirrors the Docker token spec access claim element.
type resourceActions struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// loadOrGenerateSigningKey loads an ECDSA P-256 private key from a PEM file, or
// generates an ephemeral one if no path is given.
func loadOrGenerateSigningKey(path string) (*ecdsa.PrivateKey, string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("reading signing key file: %w", err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, "", fmt.Errorf("no PEM block found in signing key file %q", path)
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, "", fmt.Errorf("parsing EC private key: %w", err)
			}
			if key.Curve != elliptic.P256() {
				return nil, "", fmt.Errorf("signing key must use P-256 curve (ES256); got %s", key.Curve.Params().Name)
			}
			return key, path, nil
		case "PRIVATE KEY":
			raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, "", fmt.Errorf("parsing PKCS8 private key: %w", err)
			}
			key, ok := raw.(*ecdsa.PrivateKey)
			if !ok {
				return nil, "", fmt.Errorf("signing key file must contain an ECDSA private key")
			}
			if key.Curve != elliptic.P256() {
				return nil, "", fmt.Errorf("signing key must use P-256 curve (ES256); got %s", key.Curve.Params().Name)
			}
			return key, path, nil
		default:
			return nil, "", fmt.Errorf("unsupported PEM block type %q in signing key file", block.Type)
		}
	}

	// Generate ephemeral key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generating ephemeral signing key: %w", err)
	}
	logrus.Warn("kubeoidc: no signing_key configured — using ephemeral key; tokens will be invalidated on restart")
	return key, "", nil
}

// signingKeyState holds a key pair that can be atomically replaced on hot-reload.
type signingKeyState struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	keyID      string
}

// tokenEndpointHandler serves GET/POST /auth/token following the Docker Registry
// Token Authentication specification.
type tokenEndpointHandler struct {
	ac          *accessController
	service     string
	issuer      string // "iss" in issued tokens
	tokenExpiry time.Duration
	signingKey  *atomic.Pointer[signingKeyState]
}

// ServeHTTP implements http.Handler.
func (h *tokenEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// --- Parse query parameters ---
	q := r.URL.Query()
	service := q.Get("service")
	if service == "" {
		service = h.service
	}
	// scope may be repeated: e.g. scope=repository:foo:pull&scope=repository:bar:push
	scopes := q["scope"]

	// --- Extract credentials ---
	// Docker sends Basic auth where username = docker login username and
	// password = the Kubernetes service account JWT.
	// An anonymous request (no Authorization header) is allowed through so that
	// policies without token checks (e.g. public pull) can still match.
	username, password, ok := r.BasicAuth()
	if !ok && r.Header.Get("Authorization") != "" {
		// Authorization header present but malformed (not valid Basic auth).
		http.Error(w, "invalid credentials: malformed authorization header", http.StatusUnauthorized)
		return
	}
	if ok && password == "" {
		// Credentials supplied but password is empty (e.g. stale/expired imagepullsecret).
		// Return 401 so the client re-authenticates rather than falling through to the
		// anonymous path and receiving a zero-access token.
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", service))
		http.Error(w, "basic auth required", http.StatusUnauthorized)
		return
	}

	// anonymous is true when no Authorization header was sent at all.
	// Requests with credentials (ok=true, password!="") are never anonymous.
	anonymous := !ok

	// Build the CEL token map from credentials, or leave nil for anonymous requests.
	var tokenMap map[string]any
	if password != "" {
		// --- Validate the SA token (password) ---
		parsedToken, err := josejwt.ParseSigned(password, defaultSigningAlgorithms)
		if err != nil {
			http.Error(w, "invalid credentials: malformed token", http.StatusUnauthorized)
			return
		}
		var unverified josejwt.Claims
		if err := parsedToken.UnsafeClaimsWithoutVerification(&unverified); err != nil {
			http.Error(w, "invalid credentials: cannot read token claims", http.StatusUnauthorized)
			return
		}

		cache, err := h.ac.issuerCache.getCache(unverified.Issuer)
		if err != nil {
			logrus.Warnf("kubeoidc/token: untrusted issuer %q: %v", unverified.Issuer, err)
			http.Error(w, "invalid credentials: untrusted issuer", http.StatusUnauthorized)
			return
		}

		keySet := cache.getKeys()
		var verified josejwt.Claims
		verifyErr := tryVerifyKeys(parsedToken, keySet, &verified)
		if verifyErr != nil {
			// Unknown kid? Try a sync refresh once.
			if syncErr := cache.syncRefresh(); syncErr != nil {
				logrus.Warnf("kubeoidc/token: sync JWKS refresh failed: %v", syncErr)
			}
			keySet = cache.getKeys()
			verifyErr = tryVerifyKeys(parsedToken, keySet, &verified)
		}
		if verifyErr != nil {
			http.Error(w, "invalid credentials: token verification failed", http.StatusUnauthorized)
			return
		}

		expected := josejwt.Expected{
			Issuer: unverified.Issuer,
		}
		if h.ac.service != "" {
			expected.AnyAudience = josejwt.Audience{h.ac.service}
		}
		if err := verified.ValidateWithLeeway(expected, 60*time.Second); err != nil {
			http.Error(w, "invalid credentials: token validation failed", http.StatusUnauthorized)
			return
		}

		if err := parsedToken.UnsafeClaimsWithoutVerification(&tokenMap); err != nil {
			http.Error(w, "invalid credentials: cannot read token claims", http.StatusUnauthorized)
			return
		}
		if raw, ok := tokenMap["aud"]; ok {
			tokenMap["aud"] = toStringSlice(raw)
		}
	}

	ps := h.ac.policySet.Load()

	var grantedAccess []resourceActions
	for _, scope := range scopes {
		ra, granted, err := evaluateScopePolicy(ps, tokenMap, scope)
		if err != nil {
			logrus.Warnf("kubeoidc/token: policy error for scope %q: %v", scope, err)
			continue
		}
		if granted {
			grantedAccess = append(grantedAccess, ra)
		}
		// Scopes that are denied are simply omitted from the token (not an error).
	}

	// When the request was anonymous (no credentials at all) and the policy
	// evaluation granted nothing, return 401 so that clients with credentials
	// fall back to retrying with their JWT rather than presenting a zero-access token to the
	// registry and receiving "insufficient scope".
	if anonymous && len(grantedAccess) == 0 {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", service))
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}

	// --- Issue the registry JWT ---
	now := time.Now()
	var sub string
	if tokenMap != nil {
		if s, ok := tokenMap["sub"].(string); ok {
			sub = s
		}
	}
	if sub == "" {
		sub = username
	}
	claims := registryClaims{
		Claims: josejwt.Claims{
			Issuer:    h.issuer,
			Subject:   sub,
			Audience:  josejwt.Audience{service},
			IssuedAt:  josejwt.NewNumericDate(now),
			Expiry:    josejwt.NewNumericDate(now.Add(h.tokenExpiry)),
			NotBefore: josejwt.NewNumericDate(now.Add(-60 * time.Second)),
		},
		Access:          grantedAccess,
		CatalogPrefixes: catalogPrefixesForToken(ps, tokenMap),
	}

	ks := h.signingKey.Load()
	signerOpts := (&jose.SignerOptions{}).WithType("JWT")
	if ks.keyID != "" {
		signerOpts = signerOpts.WithHeader("kid", ks.keyID)
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: ks.privateKey},
		signerOpts,
	)
	if err != nil {
		logrus.Errorf("kubeoidc/token: signer creation failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	rawToken, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		logrus.Errorf("kubeoidc/token: token serialization failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := tokenResponse{
		Token:       rawToken,
		AccessToken: rawToken,
		ExpiresIn:   int(h.tokenExpiry.Seconds()),
		IssuedAt:    now.UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logrus.Warnf("kubeoidc/token: writing response: %v", err)
	}
}

// tryVerifyKeys attempts to verify the JWT against any key in the JWKS.
// It prefers the key matching the token's kid header.
func tryVerifyKeys(parsedToken *josejwt.JSONWebToken, keySet *jose.JSONWebKeySet, out *josejwt.Claims) error {
	if len(parsedToken.Headers) > 0 && parsedToken.Headers[0].KeyID != "" {
		kids := keySet.Key(parsedToken.Headers[0].KeyID)
		if len(kids) > 0 {
			return parsedToken.Claims(kids[0].Public().Key, out)
		}
	}
	// Fall back: try all keys.
	for _, k := range keySet.Keys {
		if err := parsedToken.Claims(k.Public().Key, out); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no matching key found")
}

// evaluateScopePolicy parses a scope string ("type:name:action1,action2"),
// evaluates CEL policies for each action, and returns the granted actions.
func evaluateScopePolicy(ps *policySet, tokenMap map[string]any, scope string) (resourceActions, bool, error) {
	// scope format: "repository:myimage:pull,push" or "repository:myimage:pull"
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 {
		return resourceActions{}, false, fmt.Errorf("invalid scope format: %q", scope)
	}
	resType, resName, actionsStr := parts[0], parts[1], parts[2]
	requestedActions := strings.Split(actionsStr, ",")

	var grantedActions []string
	for _, action := range requestedActions {
		action = strings.TrimSpace(action)
		if action == "" {
			continue
		}
		requestMap := map[string]any{
			"type":       resType,
			"repository": resName,
			"actions":    []string{action},
		}
		granted, err := evaluatePolicies(ps.policies, tokenMap, requestMap)
		if err != nil {
			logrus.Warnf("kubeoidc/token: policy eval error for %s:%s:%s: %v", resType, resName, action, err)
			continue
		}
		if granted {
			grantedActions = append(grantedActions, action)
		}
	}

	if len(grantedActions) == 0 {
		return resourceActions{}, false, nil
	}
	return resourceActions{
		Type:    resType,
		Name:    resName,
		Actions: grantedActions,
	}, true, nil
}

// startSigningKeyReloader polls path on interval and atomically replaces the
// signingKeyState when the file changes. On parse error the previous key stays
// active so in-flight tokens continue to validate.
func startSigningKeyReloader(path string, interval time.Duration, ptr *atomic.Pointer[signingKeyState]) {
	var lastHash [32]byte
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			data, err := os.ReadFile(path)
			if err != nil {
				logrus.Warnf("kubeoidc: signing key reloader cannot read %q: %v", path, err)
				continue
			}
			hash := sha256.Sum256(data)
			if hash == lastHash {
				continue
			}
			key, _, err := loadOrGenerateSigningKey(path)
			if err != nil {
				logrus.Warnf("kubeoidc: signing key reloader failed to load %q: %v — keeping previous key", path, err)
				continue
			}
			ptr.Store(&signingKeyState{
				privateKey: key,
				publicKey:  &key.PublicKey,
				keyID:      path,
			})
			lastHash = hash
			logrus.Infof("kubeoidc: reloaded signing key from %q", path)
		}
	}()
}
