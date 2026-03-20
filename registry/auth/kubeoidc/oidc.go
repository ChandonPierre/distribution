package kubeoidc

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
)

// defaultSigningAlgorithms are the algorithms accepted for Kubernetes SA tokens.
// Kubernetes never uses symmetric signing.
var defaultSigningAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
}

// oidcDiscoveryDocument is the minimal subset of an OIDC discovery document we need.
type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// jwksCache holds the JWKS for a single issuer, with a stale-while-revalidate model.
type jwksCache struct {
	mu           sync.RWMutex
	keys         *jose.JSONWebKeySet
	fetchedAt    time.Time
	refreshEvery time.Duration
	httpClient   *http.Client
	jwksURI      string
	refreshing   bool // guards against thundering herd on background re-fetch
}

// issuerCacheMap manages per-issuer JWKS caches.
type issuerCacheMap struct {
	mu             sync.RWMutex
	caches         map[string]*jwksCache
	trustedIssuers map[string]bool
	refreshEvery   time.Duration
	httpClient     *http.Client
}

// newIssuerCacheMap creates a new issuerCacheMap with the given trusted issuers.
// Caches are lazily populated on first use.
func newIssuerCacheMap(trustedIssuers []string, refresh time.Duration, client *http.Client) *issuerCacheMap {
	trusted := make(map[string]bool, len(trustedIssuers))
	for _, iss := range trustedIssuers {
		trusted[iss] = true
	}
	return &issuerCacheMap{
		caches:         make(map[string]*jwksCache),
		trustedIssuers: trusted,
		refreshEvery:   refresh,
		httpClient:     client,
	}
}

// getCache returns the JWKS cache for the given issuer, initializing it lazily if needed.
// Returns an error if the issuer is not in the trusted list.
func (m *issuerCacheMap) getCache(issuer string) (*jwksCache, error) {
	if !m.trustedIssuers[issuer] {
		return nil, fmt.Errorf("kubeoidc: issuer %q is not in the trusted issuers list", issuer)
	}

	m.mu.RLock()
	if c, ok := m.caches[issuer]; ok {
		m.mu.RUnlock()
		return c, nil
	}
	m.mu.RUnlock()

	// Double-checked locking.
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.caches[issuer]; ok {
		return c, nil
	}
	c, err := newJWKSCache(issuer, m.refreshEvery, m.httpClient)
	if err != nil {
		return nil, err
	}
	m.caches[issuer] = c
	return c, nil
}

// newJWKSCache performs OIDC discovery for the issuer and does an initial JWKS fetch.
func newJWKSCache(issuer string, refresh time.Duration, client *http.Client) (*jwksCache, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("kubeoidc: OIDC discovery for %q: %w", issuer, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubeoidc: OIDC discovery for %q returned HTTP %d", issuer, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("kubeoidc: reading OIDC discovery body for %q: %w", issuer, err)
	}

	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("kubeoidc: parsing OIDC discovery for %q: %w", issuer, err)
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("kubeoidc: OIDC discovery for %q has no jwks_uri", issuer)
	}

	c := &jwksCache{
		refreshEvery: refresh,
		httpClient:   client,
		jwksURI:      doc.JWKSURI,
	}
	if err := c.fetchAndStore(); err != nil {
		return nil, err
	}
	return c, nil
}

// fetchAndStore fetches the JWKS from the remote endpoint and updates the cache.
func (c *jwksCache) fetchAndStore() error {
	resp, err := c.httpClient.Get(c.jwksURI)
	if err != nil {
		return fmt.Errorf("kubeoidc: fetching JWKS from %q: %w", c.jwksURI, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kubeoidc: JWKS endpoint %q returned HTTP %d", c.jwksURI, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("kubeoidc: reading JWKS body from %q: %w", c.jwksURI, err)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return fmt.Errorf("kubeoidc: parsing JWKS from %q: %w", c.jwksURI, err)
	}

	c.mu.Lock()
	c.keys = &keySet
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// getKeys returns the current JWKS. If the cache is stale, a background refresh is triggered.
// Never blocks the caller (stale-while-revalidate model).
func (c *jwksCache) getKeys() *jose.JSONWebKeySet {
	c.mu.RLock()
	keys := c.keys
	stale := time.Since(c.fetchedAt) > c.refreshEvery
	refreshing := c.refreshing
	c.mu.RUnlock()

	if stale && !refreshing {
		c.mu.Lock()
		if !c.refreshing {
			c.refreshing = true
			go func() {
				if err := c.fetchAndStore(); err != nil {
					logrus.Warnf("kubeoidc: background JWKS refresh failed: %v", err)
				}
				c.mu.Lock()
				c.refreshing = false
				c.mu.Unlock()
			}()
		}
		c.mu.Unlock()
	}

	return keys
}

// syncRefresh forces a synchronous JWKS refresh. Used when a key ID is not found.
func (c *jwksCache) syncRefresh() error {
	return c.fetchAndStore()
}

// newHTTPClient creates an HTTP client with optional TLS verification skip.
func newHTTPClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}
