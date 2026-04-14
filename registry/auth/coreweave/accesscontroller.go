// Package coreweave provides a registry auth provider that validates requests
// by calling the CoreWeave WhoAmI API and evaluating CEL policies against the
// returned principal (uid, org_uid, groups, console_actions).
//
// Configuration example:
//
//	auth:
//	  coreweave:
//	    realm: https://registry.example.com
//	    service: registry.example.com
//	    whoami_url: https://api.coreweave.com/v1beta1/auth/whoami
//	    whoami_timeout: 10s
//	    whoami_cache_ttl: 5m       # fresh cache TTL; requires redis_url
//	    whoami_stale_ttl: 1h       # stale fallback TTL (served when WhoAmI is unreachable)
//	    redis_url: redis://localhost:6379
//	    policy_file: /etc/registry/policy.yaml
//	    policy_reload_interval: 30s
//	    # OR inline policies:
//	    policies:
//	      - name: org-members
//	        expression: 'principal["org_uid"] == "my-org"'
//	        catalog_full_access: true
//	      - name: users
//	        expression: '"registry-pull" in principal["groups"]'
//	        catalog_prefix_expression: 'principal["uid"]'
package coreweave

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/mitchellh/mapstructure"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/distribution/distribution/v3/registry/auth"
)

func init() {
	if err := auth.Register("coreweave", auth.InitFunc(newAccessController)); err != nil {
		logrus.Errorf("coreweave: failed to register auth provider: %v", err)
	}
}

const (
	defaultWhoAmIURL      = "https://api.coreweave.com/v1beta1/auth/whoami"
	defaultWhoAmITimeout  = 10 * time.Second
	defaultWhoAmICacheTTL = 5 * time.Minute
	defaultWhoAmIStaleTTL = 1 * time.Hour

	// whoAmIFreshKeyPrefix keys hold the principal for at most whoami_cache_ttl.
	whoAmIFreshKeyPrefix = "cw:whoami:f:"
	// whoAmIStaleKeyPrefix keys hold the principal for at most whoami_stale_ttl and
	// are served as a fallback when the WhoAmI endpoint is unreachable.
	whoAmIStaleKeyPrefix = "cw:whoami:s:"
)

// errTokenRejected is returned by callWhoAmI when the server explicitly rejects
// the token with a 401 or 403. Stale principal data must NOT be served in this case.
var errTokenRejected = errors.New("whoami: token rejected by server")

// transientWhoAmIError wraps a network-level failure from httpClient.Do
// (e.g. connection refused, timeout). Only these errors permit the stale
// cache fallback. HTTP error responses (4xx, 5xx) and body parse failures
// are not transient — the server was reachable and returned a definitive
// answer — so they must not serve stale data.
type transientWhoAmIError struct{ err error }

func (e *transientWhoAmIError) Error() string { return e.err.Error() }
func (e *transientWhoAmIError) Unwrap() error { return e.err }

// config holds the configuration for the coreweave auth provider.
type config struct {
	Realm   string `mapstructure:"realm"`
	Service string `mapstructure:"service"`

	// WhoAmI endpoint settings.
	WhoAmIURL     string `mapstructure:"whoami_url"`
	WhoAmITimeout string `mapstructure:"whoami_timeout"`

	// Redis-backed WhoAmI response cache.
	// If RedisURL is empty, WhoAmI responses are not cached.
	RedisURL       string `mapstructure:"redis_url"`
	WhoAmICacheTTL string `mapstructure:"whoami_cache_ttl"`
	// WhoAmIStaleTTL is the TTL for the stale fallback cache entry.
	// Stale entries are returned when the WhoAmI endpoint is unreachable but
	// NOT when the server explicitly rejects the token (401/403).
	WhoAmIStaleTTL string `mapstructure:"whoami_stale_ttl"`

	// Policy configuration. PolicyFile takes precedence over Policies.
	PolicyFile           string         `mapstructure:"policy_file"`
	PolicyReloadInterval string         `mapstructure:"policy_reload_interval"`
	Policies             []policyConfig `mapstructure:"policies"`

	// Token endpoint configuration.
	// SigningKey is an optional path to a PEM-encoded ECDSA P-256 private key.
	// If omitted, an ephemeral key is generated at startup (tokens are
	// invalidated on restart and cannot be shared across replicas).
	SigningKey string `mapstructure:"signing_key"`
	// TokenExpiry is the lifetime of registry-issued tokens (default "5m").
	TokenExpiry string `mapstructure:"token_expiry"`
	// TokenIssuer is the "iss" claim in registry-issued tokens.
	// Defaults to the value of Service.
	TokenIssuer string `mapstructure:"token_issuer"`
}

// principal holds the fields from a CoreWeave WhoAmI response that are
// exposed to CEL policy expressions as principal["uid"], principal["org_uid"],
// principal["groups"], and principal["console_actions"].
type principal struct {
	Uid            string   `json:"uid"`
	OrgUid         string   `json:"orgUid"`
	Groups         []string `json:"groups"`
	ConsoleActions []string `json:"consoleActions"`
}

// whoAmIResponse is the JSON envelope returned by the CoreWeave WhoAmI API.
type whoAmIResponse struct {
	Principal *principal `json:"principal"`
}

// toMap converts the principal into the map[string]any that CEL policies
// receive as the "principal" variable.
func (p *principal) toMap() map[string]any {
	groups := make([]any, len(p.Groups))
	for i, g := range p.Groups {
		groups[i] = g
	}
	actions := make([]any, len(p.ConsoleActions))
	for i, a := range p.ConsoleActions {
		actions[i] = a
	}
	return map[string]any{
		"uid":             p.Uid,
		"org_uid":         p.OrgUid,
		"groups":          groups,
		"console_actions": actions,
	}
}

// principalCacher is a minimal cache interface for WhoAmI principal responses.
// It separates the caching contract from the Redis implementation, enabling
// in-process test doubles without a live Redis instance.
type principalCacher interface {
	load(ctx context.Context, key string) (*principal, bool)
	store(ctx context.Context, key string, p *principal, ttl time.Duration)
	// delete removes one or more keys atomically (single Redis DEL command).
	delete(ctx context.Context, keys ...string) error
}

// redisCache implements principalCacher using a Redis connection pool.
type redisCache struct{ pool redis.UniversalClient }

func (rc *redisCache) load(ctx context.Context, key string) (*principal, bool) {
	raw, err := rc.pool.Get(ctx, key).Bytes()
	if err != nil {
		return nil, false
	}
	var p principal
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false
	}
	return &p, true
}

func (rc *redisCache) store(ctx context.Context, key string, p *principal, ttl time.Duration) {
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	_ = rc.pool.Set(ctx, key, raw, ttl).Err()
}

func (rc *redisCache) delete(ctx context.Context, keys ...string) error {
	return rc.pool.Del(ctx, keys...).Err()
}

// accessController implements auth.AccessController for CoreWeave tokens.
type accessController struct {
	realm      string
	service    string
	httpClient *http.Client
	whoAmIURL  string
	cache      principalCacher // nil when Redis is not configured
	cacheTTL   time.Duration
	staleTTL   time.Duration
	sfGroup    singleflight.Group // deduplicates concurrent WhoAmI calls for the same token
	policySet  atomic.Pointer[policySet]

	// tokenEndpoint is non-nil when the built-in token exchange endpoint is active.
	tokenEndpoint *tokenEndpointHandler
	// signingKey holds the current key pair used to sign and verify registry-issued tokens.
	signingKey atomic.Pointer[signingKeyState]
	// tokenIssuer is the expected "iss" value for registry-issued tokens.
	tokenIssuer string
}

// Errors returned as auth challenges.
var (
	errTokenRequired     = errors.New("authorization token required")
	errWhoAmIFailed      = errors.New("token validation failed")
	errInsufficientScope = errors.New("insufficient scope")
)

// authChallenge implements auth.Challenge.
type authChallenge struct {
	err     error
	realm   string
	service string
	scope   string
}

var _ auth.Challenge = authChallenge{}

func (c authChallenge) Error() string { return c.err.Error() }

func (c authChallenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	realm := c.realm
	if r != nil && subdomainNamespace(r.Host, c.realm) != "" {
		// Replace the realm host with the request's subdomain host so that
		// browser token requests are same-origin, avoiding CORS preflight
		// failures. The token endpoint derives the namespace from its own
		// r.Host. E.g. realm "https://registry.example.com/auth/token"
		// becomes "https://foo.registry.example.com/auth/token".
		if u, err := url.Parse(c.realm); err == nil {
			reqHost, port, _ := net.SplitHostPort(r.Host)
			if reqHost == "" {
				reqHost = r.Host
			}
			if port != "" {
				u.Host = reqHost + ":" + port
			} else {
				u.Host = reqHost
			}
			realm = u.String()
		}
	}
	str := fmt.Sprintf("Bearer realm=%q,service=%q", realm, c.service)
	if c.scope != "" {
		str += fmt.Sprintf(",scope=%q", c.scope)
	}
	switch c.err {
	case errWhoAmIFailed:
		str += `,error="invalid_token"`
	case errInsufficientScope:
		str += `,error="insufficient_scope"`
	}
	w.Header().Add("WWW-Authenticate", str)
}

// subdomainNamespace returns the subdomain label of reqHost if it is a
// single-label direct subdomain of the realm's host, otherwise "".
// E.g. reqHost="foo.example.com",
//
//	realm="https://foo.example.com/auth/token"
//
// returns "foo".
func subdomainNamespace(reqHost, realm string) string {
	u, err := url.Parse(realm)
	if err != nil || u.Host == "" {
		return ""
	}
	realmHost, _, _ := net.SplitHostPort(u.Host)
	if realmHost == "" {
		realmHost = u.Host
	}
	reqHostname, _, _ := net.SplitHostPort(reqHost)
	if reqHostname == "" {
		reqHostname = reqHost
	}
	suffix := "." + strings.ToLower(realmHost)
	lower := strings.ToLower(reqHostname)
	if !strings.HasSuffix(lower, suffix) {
		return ""
	}
	ns := reqHostname[:len(reqHostname)-len(suffix)]
	if strings.Contains(ns, ".") {
		return "" // not a direct subdomain
	}
	return ns
}

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

func newAccessController(options map[string]any) (auth.AccessController, error) {
	var cfg config
	if err := mapstructure.Decode(options, &cfg); err != nil {
		return nil, fmt.Errorf("coreweave: failed to decode config: %w", err)
	}

	if cfg.Realm == "" {
		return nil, errors.New("coreweave: realm is required")
	}

	whoAmIURL := cfg.WhoAmIURL
	if whoAmIURL == "" {
		whoAmIURL = defaultWhoAmIURL
	}

	whoAmITimeout := defaultWhoAmITimeout
	if cfg.WhoAmITimeout != "" {
		d, err := time.ParseDuration(cfg.WhoAmITimeout)
		if err != nil {
			return nil, fmt.Errorf("coreweave: invalid whoami_timeout: %w", err)
		}
		whoAmITimeout = d
	}

	cacheTTL := defaultWhoAmICacheTTL
	if cfg.WhoAmICacheTTL != "" {
		d, err := time.ParseDuration(cfg.WhoAmICacheTTL)
		if err != nil {
			return nil, fmt.Errorf("coreweave: invalid whoami_cache_ttl: %w", err)
		}
		cacheTTL = d
	}

	staleTTL := defaultWhoAmIStaleTTL
	if cfg.WhoAmIStaleTTL != "" {
		d, err := time.ParseDuration(cfg.WhoAmIStaleTTL)
		if err != nil {
			return nil, fmt.Errorf("coreweave: invalid whoami_stale_ttl: %w", err)
		}
		staleTTL = d
	}

	if cacheTTL <= 0 {
		return nil, errors.New("coreweave: whoami_cache_ttl must be positive")
	}
	if staleTTL < cacheTTL {
		return nil, errors.New("coreweave: whoami_stale_ttl must be >= whoami_cache_ttl")
	}

	reloadInterval := 30 * time.Second
	if cfg.PolicyReloadInterval != "" {
		d, err := time.ParseDuration(cfg.PolicyReloadInterval)
		if err != nil {
			return nil, fmt.Errorf("coreweave: invalid policy_reload_interval: %w", err)
		}
		reloadInterval = d
	}

	celEnv, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("coreweave: failed to create CEL environment: %w", err)
	}

	var policyCfgs []policyConfig
	if cfg.PolicyFile != "" {
		policyCfgs, err = loadPolicyFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("coreweave: loading policy file: %w", err)
		}
	} else {
		policyCfgs = cfg.Policies
	}

	compiled, err := compilePolicies(policyCfgs, celEnv)
	if err != nil {
		return nil, fmt.Errorf("coreweave: compiling policies: %w", err)
	}

	tokenExpiry := 5 * time.Minute
	if cfg.TokenExpiry != "" {
		d, err := time.ParseDuration(cfg.TokenExpiry)
		if err != nil {
			return nil, fmt.Errorf("coreweave: invalid token_expiry: %w", err)
		}
		tokenExpiry = d
	}

	tokenIssuer := cfg.TokenIssuer
	if tokenIssuer == "" {
		tokenIssuer = cfg.Service
	}

	var cache principalCacher
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("coreweave: invalid redis_url: %w", err)
		}
		cache = &redisCache{pool: redis.NewClient(opt)}
	}

	initialKey, keyID, err := loadOrGenerateSigningKey(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("coreweave: signing key: %w", err)
	}

	ac := &accessController{
		realm:       cfg.Realm,
		service:     cfg.Service,
		whoAmIURL:   whoAmIURL,
		httpClient:  &http.Client{Timeout: whoAmITimeout},
		cache:       cache,
		cacheTTL:    cacheTTL,
		staleTTL:    staleTTL,
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
		realm:       cfg.Realm,
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

// SetRedisClient implements auth.RedisInjectable. When the application has a
// shared Redis pool, app.go calls this before serving begins, allowing the
// provider to share the existing connection instead of opening a separate one
// via redis_url. If client is not a redis.UniversalClient the call is ignored.
// A nil client clears any existing cache.
func (ac *accessController) SetRedisClient(client any) {
	if client == nil {
		ac.cache = nil
		return
	}
	rc, ok := client.(redis.UniversalClient)
	if !ok {
		return
	}
	ac.cache = &redisCache{pool: rc}
}

// Authorized calls the CoreWeave WhoAmI API (with Redis caching) and evaluates
// CEL policies against the returned principal.
// Registry-issued JWTs (from the built-in token endpoint) are verified locally
// against the signing key and bypass the WhoAmI call entirely.
func (ac *accessController) Authorized(r *http.Request, accessItems ...auth.Access) (*auth.Grant, error) {
	challenge := authChallenge{
		realm:   ac.realm,
		service: ac.service,
		scope:   scopeString(accessItems),
	}

	// Extract bearer token.
	prefix, rawToken, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || rawToken == "" || !strings.EqualFold(strings.TrimSpace(prefix), "bearer") {
		challenge.err = errTokenRequired
		return nil, challenge
	}
	rawToken = strings.TrimSpace(rawToken)

	// Fast path: registry-issued JWT (from our own token endpoint).
	// These are JWTs with iss == tokenIssuer, signed with our signing key.
	// Verify locally to avoid an unnecessary WhoAmI call.
	if ac.tokenIssuer != "" {
		if parsed, parseErr := josejwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES256}); parseErr == nil {
			var unverified josejwt.Claims
			if err := parsed.UnsafeClaimsWithoutVerification(&unverified); err == nil && unverified.Issuer == ac.tokenIssuer {
				return ac.authorizeRegistryToken(parsed, accessItems, challenge)
			}
		}
	}

	// Resolve the principal via the WhoAmI API (cache → live call).
	p, err := ac.resolvePrincipal(r.Context(), rawToken)
	if err != nil {
		logrus.Warnf("coreweave: whoami failed: %v", err)
		challenge.err = errWhoAmIFailed
		return nil, challenge
	}

	principalMap := p.toMap()
	ps := ac.policySet.Load()

	// Evaluate each access item against the policies.
	grantedResources := make([]auth.Resource, 0, len(accessItems))
	for _, access := range accessItems {
		var granted bool

		switch {
		case access.Type == "namespace" && access.Action == "create":
			granted = namespaceCreateGranted(ps.policies, principalMap, access.Name)
		case access.Type == "namespace" && access.Action == "delete":
			granted = namespaceDeleteGranted(ps.policies, principalMap, access.Name)
		default:
			requestMap := map[string]any{
				"type":       access.Type,
				"repository": access.Name,
				"actions":    []string{access.Action},
			}
			granted, err = evaluatePolicies(ps.policies, principalMap, requestMap)
			if err != nil {
				challenge.err = errInsufficientScope
				return nil, challenge
			}
		}

		if !granted {
			challenge.err = errInsufficientScope
			return nil, challenge
		}
		grantedResources = append(grantedResources, access.Resource)
	}

	// Build catalog prefixes for this principal.
	catalogPrefixes := catalogPrefixesForPrincipal(ps, principalMap)

	return &auth.Grant{
		User:            auth.UserInfo{Name: p.Uid},
		Resources:       grantedResources,
		CatalogPrefixes: catalogPrefixes,
	}, nil
}

// authorizeRegistryToken validates a registry-issued JWT (from the built-in token
// endpoint) and checks that its embedded access claims cover the requested items.
func (ac *accessController) authorizeRegistryToken(
	parsedToken *josejwt.JSONWebToken,
	accessItems []auth.Access,
	challenge authChallenge,
) (*auth.Grant, error) {
	var claims registryClaims
	if err := parsedToken.Claims(ac.signingKey.Load().publicKey, &claims); err != nil {
		challenge.err = errWhoAmIFailed
		return nil, challenge
	}

	expected := josejwt.Expected{
		Issuer:      ac.tokenIssuer,
		AnyAudience: josejwt.Audience{ac.service},
	}
	if err := claims.ValidateWithLeeway(expected, 60*time.Second); err != nil {
		challenge.err = errWhoAmIFailed
		return nil, challenge
	}

	type accessKey struct{ typ, name, action string }
	granted := make(map[accessKey]struct{})
	for _, ra := range claims.Access {
		for _, action := range ra.Actions {
			granted[accessKey{ra.Type, ra.Name, action}] = struct{}{}
		}
	}

	grantedResources := make([]auth.Resource, 0, len(accessItems))
	for _, item := range accessItems {
		if _, ok := granted[accessKey{item.Type, item.Name, item.Action}]; !ok {
			challenge.err = errInsufficientScope
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

// resolvePrincipal returns the principal for rawToken using a two-phase cache strategy:
//
//  1. Fresh cache (whoAmIFreshKeyPrefix, TTL = cacheTTL): serves the principal without
//     calling the WhoAmI API.
//  2. WhoAmI API call: on success, writes both the fresh and stale cache entries.
//  3. Stale cache (whoAmIStaleKeyPrefix, TTL = staleTTL): consulted only when the
//     WhoAmI call fails with a transient error (network failure, 5xx). A token
//     explicitly rejected by the server (401/403) never falls back to stale data.
func (ac *accessController) resolvePrincipal(ctx context.Context, rawToken string) (*principal, error) {
	tokenHash := hashToken(rawToken)

	// Phase 1: fresh cache hit.
	if ac.cache != nil {
		if p, ok := ac.cache.load(ctx, whoAmIFreshKeyPrefix+tokenHash); ok {
			return p, nil
		}
	}

	// Phase 2: deduplicated WhoAmI call. Cache writes and rejection eviction
	// run inside the closure so they execute exactly once per flight, not once
	// per waiter. Context is intentionally not propagated into the closure: the
	// singleflight result is shared across callers whose contexts may cancel
	// independently, so we use context.Background to avoid cancelling the shared
	// flight when the first waiter's context is cancelled.
	v, err, _ := ac.sfGroup.Do(tokenHash, func() (any, error) {
		p, callErr := ac.callWhoAmI(context.Background(), rawToken)
		if callErr != nil {
			if errors.Is(callErr, errTokenRejected) && ac.cache != nil {
				// Explicit rejection (401/403): evict both cache tiers so the revoked
				// token cannot be served from stale during a future WhoAmI outage.
				if delErr := ac.cache.delete(ctx, whoAmIFreshKeyPrefix+tokenHash, whoAmIStaleKeyPrefix+tokenHash); delErr != nil {
					logrus.Warnf("coreweave: failed to evict cache entries for rejected token: %v", delErr)
				}
			}
			return nil, callErr
		}
		if ac.cache != nil {
			ac.cache.store(ctx, whoAmIFreshKeyPrefix+tokenHash, p, ac.cacheTTL)
			ac.cache.store(ctx, whoAmIStaleKeyPrefix+tokenHash, p, ac.staleTTL)
		}
		return p, nil
	})
	if err != nil {
		// Phase 3: stale fallback — only for genuine network-level failures.
		// HTTP error responses (4xx, 5xx) and parse errors are not transient:
		// the server was reachable and returned a definitive answer.
		var transErr *transientWhoAmIError
		if ac.cache != nil && errors.As(err, &transErr) {
			if stale, ok := ac.cache.load(ctx, whoAmIStaleKeyPrefix+tokenHash); ok {
				logrus.Warnf("coreweave: whoami unreachable, serving stale principal: %v", err)
				return stale, nil
			}
		}
		return nil, err
	}

	return v.(*principal), nil
}

// callWhoAmI calls the CoreWeave WhoAmI API with the given bearer token.
// It returns errTokenRejected for 401/403 responses so that resolvePrincipal
// knows not to fall back to stale cache data.
func (ac *accessController) callWhoAmI(ctx context.Context, rawToken string) (*principal, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ac.whoAmIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building whoami request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Accept", "application/json")

	resp, err := ac.httpClient.Do(req)
	if err != nil {
		// Network-level failure: connection refused, timeout, etc. Wrap as
		// transient so resolvePrincipal knows it may serve stale data.
		return nil, &transientWhoAmIError{err: fmt.Errorf("calling whoami: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errTokenRejected
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("whoami returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed whoAmIResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding whoami response: %w", err)
	}
	if parsed.Principal == nil {
		return nil, errors.New("whoami response missing principal")
	}
	return parsed.Principal, nil
}

// hashToken returns the hex-encoded SHA-256 of the raw bearer token.
// The token is never stored directly.
func hashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}
