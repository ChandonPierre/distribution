package coreweave

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
	CatalogPrefixes []string          `json:"catalog_prefixes,omitempty"`
}

// resourceActions mirrors the Docker token spec access claim element.
type resourceActions struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// signingKeyState holds a key pair that can be atomically replaced on hot-reload.
type signingKeyState struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	keyID      string
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

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generating ephemeral signing key: %w", err)
	}
	logrus.Warn("coreweave: no signing_key configured — using ephemeral key; tokens will be invalidated on restart")
	return key, "", nil
}

// startSigningKeyReloader polls path on interval and atomically replaces the
// signingKeyState when the file changes.
func startSigningKeyReloader(path string, interval time.Duration, ptr *atomic.Pointer[signingKeyState]) {
	var lastHash [32]byte
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			data, err := os.ReadFile(path)
			if err != nil {
				logrus.Warnf("coreweave: signing key reloader cannot read %q: %v", path, err)
				continue
			}
			hash := sha256.Sum256(data)
			if hash == lastHash {
				continue
			}
			key, _, err := loadOrGenerateSigningKey(path)
			if err != nil {
				logrus.Warnf("coreweave: signing key reloader failed to load %q: %v — keeping previous key", path, err)
				continue
			}
			ptr.Store(&signingKeyState{
				privateKey: key,
				publicKey:  &key.PublicKey,
				keyID:      path,
			})
			lastHash = hash
			logrus.Infof("coreweave: reloaded signing key from %q", path)
		}
	}()
}

// tokenEndpointHandler serves GET/POST /auth/token following the Docker Registry
// Token Authentication specification. Credentials are validated by calling the
// CoreWeave WhoAmI API via the parent accessController.
type tokenEndpointHandler struct {
	ac          *accessController
	realm       string // used in WWW-Authenticate Basic challenges
	service     string
	issuer      string
	tokenExpiry time.Duration
	signingKey  *atomic.Pointer[signingKeyState]
}

// ServeHTTP implements http.Handler.
func (h *tokenEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	service := q.Get("service")
	if service == "" {
		service = h.service
	}
	// When subdomain namespacing is enabled the auth challenge repoints the
	// realm to the subdomain host (e.g. foo.registry.example.com/auth/token).
	// Derive the namespace from this request's own Host header.
	namespace := subdomainNamespace(r.Host, h.realm)
	// scope may be repeated (scope=a&scope=b) or space-separated within one
	// parameter (scope=a+b). Split on spaces to normalise both forms.
	var scopes []string
	for _, s := range q["scope"] {
		scopes = append(scopes, strings.Fields(s)...)
	}

	// Docker sends Basic auth where the password is the CoreWeave bearer token.
	// An anonymous request (no Authorization header) is allowed so that policies
	// without principal checks (e.g. public pull) can still match.
	_, password, ok := r.BasicAuth()
	if !ok && r.Header.Get("Authorization") != "" {
		http.Error(w, "invalid credentials: malformed authorization header", http.StatusUnauthorized)
		return
	}
	if ok && password == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", h.realm))
		http.Error(w, "basic auth required", http.StatusUnauthorized)
		return
	}

	anonymous := !ok

	// Resolve the principal from the CoreWeave bearer token.
	var principalMap map[string]any
	if password != "" {
		p, err := h.ac.resolvePrincipal(r.Context(), password)
		if err != nil {
			logrus.Warnf("coreweave/token: whoami failed: %v", err)
			http.Error(w, "invalid credentials: authentication failed", http.StatusUnauthorized)
			return
		}
		principalMap = p.toMap()
	}

	ps := h.ac.policySet.Load()

	var grantedAccess []resourceActions
	for _, scope := range scopes {
		scope = qualifyScope(scope, namespace)
		if scope == "registry:catalog:*" {
			if !anonymous || len(catalogPrefixesForPrincipal(ps, principalMap)) > 0 {
				grantedAccess = append(grantedAccess, resourceActions{
					Type:    "registry",
					Name:    "catalog",
					Actions: []string{"*"},
				})
			}
			continue
		}
		ra, granted, err := evaluateScopeForPrincipal(ps, principalMap, scope)
		if err != nil {
			logrus.Warnf("coreweave/token: policy error for scope %q: %v", scope, err)
			continue
		}
		if granted {
			grantedAccess = append(grantedAccess, ra)
		}
	}

	if anonymous && len(grantedAccess) == 0 {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", h.realm))
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}

	// Issue the registry JWT.
	now := time.Now()
	var sub string
	if principalMap != nil {
		if uid, ok := principalMap["uid"].(string); ok {
			sub = uid
		}
	}

	// Log every token issuance so operators have an audit trail of who got what.
	{
		fields := logrus.Fields{
			"sub":       sub,
			"namespace": namespace,
			"anonymous": anonymous,
		}
		if principalMap != nil {
			if orgUID, ok := principalMap["org_uid"].(string); ok && orgUID != "" {
				fields["org_uid"] = orgUID
			}
		}
		var grantedScopes []string
		for _, ra := range grantedAccess {
			grantedScopes = append(grantedScopes, ra.Type+":"+ra.Name+":"+strings.Join(ra.Actions, ","))
		}
		fields["scopes"] = grantedScopes
		logrus.WithFields(fields).Info("coreweave/token: access granted")
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
		CatalogPrefixes: catalogPrefixesForPrincipal(ps, principalMap),
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
		logrus.Errorf("coreweave/token: signer creation failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	rawToken, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		logrus.Errorf("coreweave/token: token serialization failed: %v", err)
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
		logrus.Warnf("coreweave/token: writing response: %v", err)
	}
}

// qualifyScope prepends namespace to the repository component of a scope string
// when the repository name is not already rooted at the namespace prefix.
// It is a no-op when namespace is empty or the scope is already qualified.
// E.g. "repository:image:pull" + "foo" → "repository:foo/image:pull"
//
//	"repository:bar/image:pull" + "foo" → "repository:foo/bar/image:pull"
//	"repository:foo/image:pull" + "foo" → unchanged
func qualifyScope(scope, namespace string) string {
	if namespace == "" {
		return scope
	}
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 {
		return scope
	}
	if parts[0] == "repository" && !strings.HasPrefix(parts[1], namespace+"/") {
		return "repository:" + namespace + "/" + parts[1] + ":" + parts[2]
	}
	return scope
}

// evaluateScopeForPrincipal parses a scope string and evaluates CEL policies
// against a principal map, returning the granted actions.
func evaluateScopeForPrincipal(ps *policySet, principalMap map[string]any, scope string) (resourceActions, bool, error) {
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
		granted, err := evaluatePolicies(ps.policies, principalMap, requestMap)
		if err != nil {
			logrus.Warnf("coreweave/token: policy eval error for %s:%s:%s: %v", resType, resName, action, err)
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
