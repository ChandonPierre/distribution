package kubeoidc

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/distribution/distribution/v3/registry/auth"
)

func init() {
	if err := auth.Register("kubeoidc", auth.InitFunc(newAccessController)); err != nil {
		logrus.Errorf("kubeoidc: failed to register auth provider: %v", err)
	}
}

// config holds the configuration for the kubeoidc auth provider.
type config struct {
	Realm                 string         `mapstructure:"realm"`
	Service               string         `mapstructure:"service"`
	Issuers               []string       `mapstructure:"issuers"`
	InsecureSkipTLSVerify bool           `mapstructure:"insecure_skip_tls_verify"`
	JWKSRefreshInterval   string         `mapstructure:"jwks_refresh_interval"`
	PolicyFile            string         `mapstructure:"policy_file"`
	PolicyReloadInterval  string         `mapstructure:"policy_reload_interval"`
	Policies              []policyConfig `mapstructure:"policies"`

	// Token endpoint configuration.
	// SigningKey is an optional path to a PEM-encoded ECDSA private key used
	// to sign registry-issued tokens. If omitted, an ephemeral key is generated
	// at startup (tokens are invalidated on restart).
	SigningKey  string `mapstructure:"signing_key"`
	// TokenExpiry is the lifetime of registry-issued tokens (default "5m").
	TokenExpiry string `mapstructure:"token_expiry"`
	// TokenIssuer is the "iss" claim value in registry-issued tokens.
	// Defaults to the value of Service.
	TokenIssuer string `mapstructure:"token_issuer"`
}

// policyConfig is the raw parsed form from YAML/config.
type policyConfig struct {
	Name       string `mapstructure:"name" yaml:"name"`
	Expression string `mapstructure:"expression" yaml:"expression"`

	// CatalogPrefix is a static repository name prefix. When set, the policy
	// engine probes the main expression with request["repository"]=CatalogPrefix
	// at token issuance; if the expression grants access, CatalogPrefix is
	// embedded in the catalog_prefixes JWT claim.
	//
	// Use CatalogPrefixExpression instead when the prefix must be derived from
	// the token itself (e.g. the tenant namespace stored in a JWT claim).
	CatalogPrefix string `mapstructure:"catalog_prefix" yaml:"catalog_prefix"`

	// CatalogPrefixExpression is a CEL expression that is evaluated against
	// the token map and must return a non-empty string. That string is used as
	// the catalog prefix for this caller. Useful when the tenant identifier
	// comes from a JWT claim rather than being known statically.
	//
	// Example: token["kubernetes.io/serviceaccount/namespace"]
	CatalogPrefixExpression string `mapstructure:"catalog_prefix_expression" yaml:"catalog_prefix_expression"`

	// CatalogFullAccess, when true, grants unrestricted /v2/_catalog access
	// to any token that satisfies the main policy expression. No prefix
	// filtering is applied; the caller sees every repository in the registry.
	// Takes precedence over catalog_prefix and catalog_prefix_expression.
	CatalogFullAccess bool `mapstructure:"catalog_full_access" yaml:"catalog_full_access"`

	// NamespaceCreate, when true, grants namespace:*:create access to any token
	// that satisfies the main policy expression. Enables PUT /management/namespaces/{name}.
	NamespaceCreate bool `mapstructure:"namespace_create" yaml:"namespace_create"`

	// NamespaceDelete, when true, grants namespace:*:delete access to any token
	// that satisfies the main policy expression. Enables DELETE /management/namespaces/{name}.
	NamespaceDelete bool `mapstructure:"namespace_delete" yaml:"namespace_delete"`
}

// accessController implements auth.AccessController for Kubernetes OIDC service account tokens.
type accessController struct {
	realm       string
	service     string
	issuerCache *issuerCacheMap
	policySet   atomic.Pointer[policySet]

	// tokenEndpoint is non-nil when the built-in token exchange endpoint is active.
	tokenEndpoint *tokenEndpointHandler
	// signingKey holds the current key pair used to sign and verify registry-issued tokens.
	// It is atomically replaced on hot-reload so both signing and verification stay in sync.
	signingKey atomic.Pointer[signingKeyState]
	// tokenIssuer is the expected "iss" value for registry-issued tokens.
	tokenIssuer string
}

// Errors used and exported by this package.
var (
	ErrTokenRequired     = errors.New("authorization token required")
	ErrMalformedToken    = errors.New("malformed token")
	ErrInvalidToken      = errors.New("invalid token")
	ErrInsufficientScope = errors.New("insufficient scope")
)

// authChallenge implements auth.Challenge.
type authChallenge struct {
	err     error
	realm   string
	service string
	scope   string
}

var _ auth.Challenge = authChallenge{}

func (c authChallenge) Error() string {
	return c.err.Error()
}

func (c authChallenge) Status() int {
	return http.StatusUnauthorized
}

func (c authChallenge) SetHeaders(_ *http.Request, w http.ResponseWriter) {
	str := fmt.Sprintf("Bearer realm=%q,service=%q", c.realm, c.service)
	if c.scope != "" {
		str = fmt.Sprintf("%s,scope=%q", str, c.scope)
	}
	switch c.err {
	case ErrInvalidToken, ErrMalformedToken:
		str = fmt.Sprintf("%s,error=%q", str, "invalid_token")
	case ErrInsufficientScope:
		str = fmt.Sprintf("%s,error=%q", str, "insufficient_scope")
	}
	w.Header().Add("WWW-Authenticate", str)
}

// scopeString serializes access items into "type:name:action type:name:action" format.
func scopeString(accessItems []auth.Access) string {
	if len(accessItems) == 0 {
		return ""
	}
	parts := make([]string, 0, len(accessItems))
	for _, a := range accessItems {
		parts = append(parts, fmt.Sprintf("%s:%s:%s", a.Type, a.Name, a.Action))
	}
	return strings.Join(parts, " ")
}

// toStringSlice converts a JSON-decoded audience value (which may be a single
// string or a []interface{} of strings) into a []string for CEL evaluation.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			if s, ok := el.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

// newAccessController creates a kubeoidc accessController from the given options map.
func newAccessController(options map[string]any) (auth.AccessController, error) {
	var cfg config
	if err := mapstructure.Decode(options, &cfg); err != nil {
		return nil, fmt.Errorf("kubeoidc: failed to decode config: %w", err)
	}

	if cfg.Realm == "" {
		return nil, errors.New("kubeoidc: realm is required")
	}
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("kubeoidc: at least one issuer is required")
	}

	refreshInterval := time.Hour
	if cfg.JWKSRefreshInterval != "" {
		d, err := time.ParseDuration(cfg.JWKSRefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("kubeoidc: invalid jwks_refresh_interval: %w", err)
		}
		refreshInterval = d
	}

	reloadInterval := 30 * time.Second
	if cfg.PolicyReloadInterval != "" {
		d, err := time.ParseDuration(cfg.PolicyReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("kubeoidc: invalid policy_reload_interval: %w", err)
		}
		reloadInterval = d
	}

	tokenExpiry := 5 * time.Minute
	if cfg.TokenExpiry != "" {
		d, err := time.ParseDuration(cfg.TokenExpiry)
		if err != nil {
			return nil, fmt.Errorf("kubeoidc: invalid token_expiry: %w", err)
		}
		tokenExpiry = d
	}

	tokenIssuer := cfg.TokenIssuer
	if tokenIssuer == "" {
		tokenIssuer = cfg.Service
	}

	httpClient := newHTTPClient(cfg.InsecureSkipTLSVerify)
	issuerCache := newIssuerCacheMap(cfg.Issuers, refreshInterval, httpClient)

	// Prevent routing collisions: if tokenIssuer matches a trusted OIDC issuer
	// (exactly or via a wildcard prefix), SA tokens from that issuer would be
	// incorrectly routed to the registry-JWT validation path and fail.
	if tokenIssuer != "" && issuerCache.isTrusted(tokenIssuer) {
		return nil, fmt.Errorf("kubeoidc: token_issuer %q conflicts with a trusted OIDC issuer; use a distinct value (e.g. the registry hostname)", tokenIssuer)
	}

	celEnv, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("kubeoidc: failed to create CEL environment: %w", err)
	}

	var policyCfgs []policyConfig
	if cfg.PolicyFile != "" {
		policyCfgs, err = loadPolicyFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("kubeoidc: loading policy file: %w", err)
		}
	} else {
		policyCfgs = cfg.Policies
	}

	compiled, err := compilePolicies(policyCfgs, celEnv)
	if err != nil {
		return nil, fmt.Errorf("kubeoidc: compiling policies: %w", err)
	}

	// Load or generate the signing key for the built-in token endpoint.
	initialKey, keyID, err := loadOrGenerateSigningKey(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("kubeoidc: signing key: %w", err)
	}

	ac := &accessController{
		realm:       cfg.Realm,
		service:     cfg.Service,
		issuerCache: issuerCache,
		tokenIssuer: tokenIssuer,
	}
	ac.signingKey.Store(&signingKeyState{
		privateKey: initialKey,
		publicKey:  &initialKey.PublicKey,
		keyID:      keyID,
	})
	ac.policySet.Store(&policySet{policies: compiled})

	if cfg.PolicyFile != "" {
		startPolicyReloader(cfg.PolicyFile, reloadInterval, &ac.policySet, celEnv)
	}
	if cfg.SigningKey != "" {
		startSigningKeyReloader(cfg.SigningKey, reloadInterval, &ac.signingKey)
	}

	ac.tokenEndpoint = &tokenEndpointHandler{
		ac:          ac,
		service:     cfg.Service,
		issuer:      tokenIssuer,
		tokenExpiry: tokenExpiry,
		signingKey:  &ac.signingKey,
	}

	return ac, nil
}

// TokenHandler returns the built-in token endpoint HTTP handler.
// It implements auth.TokenEndpointer so the registry can register it automatically.
func (ac *accessController) TokenHandler() http.Handler {
	return ac.tokenEndpoint
}

// Authorized checks whether the bearer token in the request grants access to the given resources.
func (ac *accessController) Authorized(req *http.Request, accessItems ...auth.Access) (*auth.Grant, error) {
	challenge := authChallenge{
		realm:   ac.realm,
		service: ac.service,
		scope:   scopeString(accessItems),
	}

	// Extract bearer token.
	prefix, rawToken, ok := strings.Cut(req.Header.Get("Authorization"), " ")
	if !ok || rawToken == "" || !strings.EqualFold(prefix, "bearer") {
		challenge.err = ErrTokenRequired
		return nil, challenge
	}

	// Parse the signed JWT (without verifying signature yet).
	parsedToken, err := jwt.ParseSigned(rawToken, defaultSigningAlgorithms)
	if err != nil {
		challenge.err = ErrMalformedToken
		return nil, challenge
	}

	// Extract issuer from unverified claims to locate the right verification path.
	var unverified jwt.Claims
	if err := parsedToken.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		challenge.err = ErrMalformedToken
		return nil, challenge
	}

	// Registry-issued tokens (from our own token endpoint) have iss == tokenIssuer.
	// Validate them with the local signing key and check their embedded access claims.
	if unverified.Issuer == ac.tokenIssuer && ac.signingKey.Load() != nil {
		return ac.authorizeRegistryToken(parsedToken, unverified.Issuer, accessItems, challenge)
	}

	// SA tokens: look up (or initialize) the JWKS cache for this issuer.
	cache, err := ac.issuerCache.getCache(unverified.Issuer)
	if err != nil {
		challenge.err = ErrInvalidToken
		return nil, challenge
	}

	// Get the current key set.
	keySet := cache.getKeys()

	// Find the key by key ID.
	var signingKey *jose.JSONWebKey
	if len(parsedToken.Headers) > 0 && parsedToken.Headers[0].KeyID != "" {
		kids := keySet.Key(parsedToken.Headers[0].KeyID)
		if len(kids) == 0 {
			// Unknown kid: trigger a synchronous re-fetch once.
			if err := cache.syncRefresh(); err != nil {
				logrus.Warnf("kubeoidc: sync JWKS refresh failed: %v", err)
			}
			keySet = cache.getKeys()
			kids = keySet.Key(parsedToken.Headers[0].KeyID)
		}
		if len(kids) > 0 {
			signingKey = &kids[0]
		}
	}

	// Try each key in the set if no kid matched specifically.
	var claims jwt.Claims
	if signingKey != nil {
		if err := parsedToken.Claims(signingKey.Public().Key, &claims); err != nil {
			challenge.err = ErrInvalidToken
			return nil, challenge
		}
	} else {
		// No kid in token header or kid not found — try all keys.
		verified := false
		for _, k := range keySet.Keys {
			if err := parsedToken.Claims(k.Public().Key, &claims); err == nil {
				verified = true
				break
			}
		}
		if !verified {
			challenge.err = ErrInvalidToken
			return nil, challenge
		}
	}

	// Validate standard claims: issuer, audience, expiry.
	expected := jwt.Expected{
		Issuer: unverified.Issuer,
	}
	if ac.service != "" {
		expected.AnyAudience = jwt.Audience{ac.service}
	}
	if err := claims.ValidateWithLeeway(expected, 60*time.Second); err != nil {
		challenge.err = ErrInvalidToken
		return nil, challenge
	}

	// Build the CEL token map from the full raw payload so that policies can
	// access any claim — not just iss/sub/aud. The signature is already verified
	// above so it is safe to read the payload without re-verification.
	var tokenMap map[string]any
	if err := parsedToken.UnsafeClaimsWithoutVerification(&tokenMap); err != nil {
		challenge.err = ErrInvalidToken
		return nil, challenge
	}
	// Normalise the "aud" field: the JWT spec allows it to be a single string
	// or an array. go-jose decodes it as []interface{} but we normalise to
	// []string so CEL policies can use consistent list operations.
	if raw, ok := tokenMap["aud"]; ok {
		tokenMap["aud"] = toStringSlice(raw)
	}

	// Inject the X-Org-Id value from the JWKS endpoint response as a synthetic
	// claim so policies can make decisions based on issuer-level org identity
	// without encoding it in every token. Accessible as token["org_id"].
	if orgID := cache.getOrgID(); orgID != "" {
		tokenMap["org_id"] = orgID
	}

	// Load the current policy set atomically.
	ps := ac.policySet.Load()

	// Each access item must be independently approved by at least one policy.
	grantedResources := make([]auth.Resource, 0, len(accessItems))
	for _, access := range accessItems {
		var granted bool
		var err error

		if access.Type == "namespace" && access.Action == "create" {
			// namespace:*:create is granted by policies with namespace_create: true
			// whose main expression matches the token. access.Name is forwarded so
			// expressions can validate the target namespace name.
			granted = namespaceCreateGranted(ps.policies, tokenMap, access.Name)
		} else if access.Type == "namespace" && access.Action == "delete" {
			// namespace:*:delete is granted by policies with namespace_delete: true.
			granted = namespaceDeleteGranted(ps.policies, tokenMap, access.Name)
		} else {
			requestMap := map[string]any{
				"type":       access.Type,
				"repository": access.Name,
				"actions":    []string{access.Action},
			}
			granted, err = evaluatePolicies(ps.policies, tokenMap, requestMap)
		}

		if err != nil {
			challenge.err = ErrInsufficientScope
			return nil, challenge
		}
		if !granted {
			challenge.err = ErrInsufficientScope
			return nil, challenge
		}
		grantedResources = append(grantedResources, access.Resource)
	}

	return &auth.Grant{
		User:      auth.UserInfo{Name: claims.Subject},
		Resources: grantedResources,
	}, nil
}

// catalogPrefixesForToken returns the set of catalog repository prefixes that
// the given token map is permitted to see, based on policies that opt in via
// catalog_prefix or catalog_prefix_expression.
//
// Two evaluation strategies are supported per policy:
//
//   - catalog_prefix_expression (preferred): the CEL expression is evaluated
//     against the token and must return a non-empty string. That string becomes
//     the prefix. This supports tenant namespaces stored in JWT claims.
//
//   - catalog_prefix (static fallback): the main policy expression is probed
//     with request["repository"]=<prefix>. If access is granted, the static
//     prefix is included.
//
// Returns a non-nil slice so callers can distinguish "nothing granted" from
// "no filtering in effect" (nil).
func catalogPrefixesForToken(ps *policySet, tokenMap map[string]any) []string {
	seen := make(map[string]struct{})
	var prefixes []string

	for _, p := range ps.policies {
		// Full-access path: if the policy expression matches, skip all prefix
		// filtering and return nil so the caller sees the entire catalog.
		if p.catalogFullAccess {
			requestMap := map[string]any{
				"type":       "registry",
				"repository": "",
				"actions":    []string{"*"},
			}
			if granted, err := evaluatePolicies([]*compiledPolicy{p}, tokenMap, requestMap); err == nil && granted {
				return nil
			}
			continue
		}

		var prefix string

		switch {
		case p.catalogPrefixProgram != nil:
			// Dynamic path: evaluate the prefix expression against the token.
			out, _, err := p.catalogPrefixProgram.Eval(map[string]any{
				"token":   tokenMap,
				"request": map[string]any{},
			})
			if err != nil {
				logrus.Warnf("kubeoidc: policy %q catalog_prefix_expression eval error: %v", p.name, err)
				continue
			}
			s, ok := out.Value().(string)
			if !ok || s == "" {
				continue
			}
			// Confirm the token actually grants access under this policy by
			// probing the main expression with repository=<prefix>/. Without
			// this check a token from a different issuer could still produce
			// a non-empty prefix string and leak catalog entries.
			probeMap := map[string]any{
				"type":       "repository",
				"repository": s + "/",
				"actions":    []string{"pull"},
			}
			if granted, err := evaluatePolicies([]*compiledPolicy{p}, tokenMap, probeMap); err != nil || !granted {
				continue
			}
			prefix = s

		case p.catalogPrefix != "":
			// Static path: probe the main expression with the fixed prefix.
			requestMap := map[string]any{
				"type":       "repository",
				"repository": p.catalogPrefix,
				"actions":    []string{"pull"},
			}
			granted, err := evaluatePolicies([]*compiledPolicy{p}, tokenMap, requestMap)
			if err != nil || !granted {
				continue
			}
			prefix = p.catalogPrefix

		default:
			continue
		}

		if _, dup := seen[prefix]; !dup {
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
	}

	if prefixes == nil {
		return []string{}
	}
	return prefixes
}

// authorizeRegistryToken validates a registry-issued JWT (from the built-in token endpoint)
// and checks that its embedded access claims cover the requested accessItems.
func (ac *accessController) authorizeRegistryToken(
	parsedToken *jwt.JSONWebToken,
	issuer string,
	accessItems []auth.Access,
	challenge authChallenge,
) (*auth.Grant, error) {
	var claims registryClaims
	if err := parsedToken.Claims(ac.signingKey.Load().publicKey, &claims); err != nil {
		challenge.err = ErrInvalidToken
		return nil, challenge
	}

	expected := jwt.Expected{
		Issuer:      issuer,
		AnyAudience: jwt.Audience{ac.service},
	}
	if err := claims.ValidateWithLeeway(expected, 60*time.Second); err != nil {
		challenge.err = ErrInvalidToken
		return nil, challenge
	}

	// Build a set of granted access from the token's "access" claim.
	type accessKey struct{ typ, name, action string }
	granted := make(map[accessKey]struct{})
	for _, ra := range claims.Access {
		for _, action := range ra.Actions {
			granted[accessKey{ra.Type, ra.Name, action}] = struct{}{}
		}
	}

	// Every requested access item must be covered by the token.
	grantedResources := make([]auth.Resource, 0, len(accessItems))
	for _, item := range accessItems {
		if _, ok := granted[accessKey{item.Type, item.Name, item.Action}]; !ok {
			challenge.err = ErrInsufficientScope
			return nil, challenge
		}
		grantedResources = append(grantedResources, item.Resource)
	}

	return &auth.Grant{
		User:            auth.UserInfo{Name: claims.Subject},
		Resources:       grantedResources,
		CatalogPrefixes: claims.CatalogPrefixes,
	}, nil
}
