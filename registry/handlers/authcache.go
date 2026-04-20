package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/registry/auth"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var _ auth.AccessController = (*cachingAccessController)(nil)

const (
	// authCacheKeyPrefix namespaces all auth grant cache entries.
	authCacheKeyPrefix = "authgrant::"
	// authCacheDefaultTTL is used when the token expiry cannot be parsed.
	authCacheDefaultTTL = 5 * time.Minute
	// authCacheExpiryMargin is subtracted from the token's exp claim so the
	// cache entry expires slightly before the token itself.
	authCacheExpiryMargin = 30 * time.Second
)

// cachingAccessController wraps any auth.AccessController and caches
// successful authorization grants in Redis, keyed by a hash of the raw bearer
// token and the requested access scope. The underlying controller is called on
// every cache miss.
type cachingAccessController struct {
	inner auth.AccessController
	pool  redis.UniversalClient
}

// wrapWithAuthCache wraps ac with a Redis-backed grant cache.
// If pool is nil the original controller is returned unchanged.
func wrapWithAuthCache(ac auth.AccessController, pool redis.UniversalClient) auth.AccessController {
	if pool == nil {
		return ac
	}
	return &cachingAccessController{inner: ac, pool: pool}
}

// Authorized checks Redis for a cached grant. On a miss it calls the inner
// controller and caches successful results for the remainder of the token's
// validity window.
func (c *cachingAccessController) Authorized(r *http.Request, accessItems ...auth.Access) (*auth.Grant, error) {
	rawToken := extractBearerToken(r)
	if rawToken == "" {
		// No bearer token — pass through directly (will fail fast in inner).
		return c.inner.Authorized(r, accessItems...)
	}

	cacheKey := authGrantCacheKey(rawToken, accessItems)

	// Hot path: try the cache first.
	if grant, ok := c.loadGrant(r.Context(), cacheKey); ok {
		dcontext.GetLogger(r.Context()).Debug("auth_cache: hit")
		return grant, nil
	}
	dcontext.GetLogger(r.Context()).Debug("auth_cache: miss")

	// Cold path: call inner controller.
	grant, err := c.inner.Authorized(r, accessItems...)
	if err != nil {
		return nil, err
	}

	// Cache the grant for the remaining token lifetime.
	ttl := jwtRemainingTTL(rawToken)
	if ttl > 0 {
		c.storeGrant(r.Context(), cacheKey, grant, ttl)
	}

	return grant, nil
}

// loadGrant deserializes a cached grant from Redis.
func (c *cachingAccessController) loadGrant(ctx context.Context, key string) (*auth.Grant, bool) {
	raw, err := c.pool.Get(ctx, key).Bytes()
	if err != nil {
		return nil, false
	}
	var g auth.Grant
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, false
	}
	return &g, true
}

// storeGrant serializes a grant into Redis with the given TTL.
func (c *cachingAccessController) storeGrant(ctx context.Context, key string, grant *auth.Grant, ttl time.Duration) {
	raw, err := json.Marshal(grant)
	if err != nil {
		return
	}
	if err := c.pool.Set(ctx, key, raw, ttl).Err(); err != nil {
		logrus.WithError(err).Warn("auth_cache: redis write failed")
	}
}

// authGrantCacheKey produces a collision-resistant cache key from the raw
// bearer token and the requested access items.
func authGrantCacheKey(rawToken string, accessItems []auth.Access) string {
	scope := sortedScopeString(accessItems)
	h := sha256.Sum256([]byte(rawToken + "\x00" + scope))
	return authCacheKeyPrefix + hex.EncodeToString(h[:])
}

// sortedScopeString encodes access items deterministically.
func sortedScopeString(items []auth.Access) string {
	parts := make([]string, len(items))
	for i, a := range items {
		parts[i] = fmt.Sprintf("%s:%s:%s:%s", a.Type, a.Class, a.Name, a.Action)
	}
	// Items arrive in a fixed order from the router — no sort needed, but
	// using a stable separator means order changes would create distinct keys
	// (also correct behaviour: different scopes should have separate entries).
	return strings.Join(parts, " ")
}

// extractBearerToken returns the raw JWT from the Authorization header.
// It supports both "Bearer <JWT>" and the Basic-auth form where the password
// field holds the JWT (username is ignored).
// Returns "" if the header is absent, malformed, or does not yield a JWT.
func extractBearerToken(r *http.Request) string {
	prefix, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok {
		return ""
	}
	switch {
	case strings.EqualFold(prefix, "bearer"):
		return strings.TrimSpace(raw)
	case strings.EqualFold(prefix, "basic"):
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return ""
		}
		// The JWT is carried in the password (everything after the first colon).
		_, pw, hasSep := strings.Cut(string(decoded), ":")
		if !hasSep {
			return ""
		}
		return strings.TrimSpace(pw)
	}
	return ""
}

// jwtRemainingTTL decodes the `exp` claim from the JWT body without verifying
// the signature and returns how long the token remains valid minus the safety
// margin. Returns authCacheDefaultTTL if parsing fails.
func jwtRemainingTTL(rawToken string) time.Duration {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return authCacheDefaultTTL
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return authCacheDefaultTTL
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil || claims.Exp == 0 {
		return authCacheDefaultTTL
	}
	ttl := time.Until(time.Unix(claims.Exp, 0)) - authCacheExpiryMargin
	if ttl <= 0 {
		return 0
	}
	return ttl
}
