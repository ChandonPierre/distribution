// Package chain provides a registry auth provider that tries a list of
// providers in order, returning the first successful grant. This lets
// operators support multiple credential types (e.g. Kubernetes OIDC tokens
// and htpasswd) on the same registry without a separate token service.
//
// Configuration example:
//
//	auth:
//	  chain:
//	    providers:
//	      - type: kubeoidc
//	        realm: https://registry.example.com/auth/token
//	        service: registry.example.com
//	        issuers: ["https://kubernetes.default.svc"]
//	        policy_file: /etc/registry/policy.yaml
//	      - type: htpasswd
//	        realm: Registry
//	        path: /etc/registry/htpasswd
package chain

import (
	"fmt"
	"net/http"

	"github.com/distribution/distribution/v3/registry/auth"
)

func init() {
	if err := auth.Register("chain", auth.InitFunc(newChainAccessController)); err != nil {
		panic("chain auth: failed to register: " + err.Error())
	}
}

type chainAccessController struct {
	providers []auth.AccessController
}

func newChainAccessController(options map[string]any) (auth.AccessController, error) {
	rawProviders, ok := normalizeValue(options["providers"]).([]any)
	if !ok || len(rawProviders) == 0 {
		return nil, fmt.Errorf("chain auth: 'providers' must be a non-empty list")
	}

	controllers := make([]auth.AccessController, 0, len(rawProviders))
	for i, rp := range rawProviders {
		pm, ok := normalizeValue(rp).(map[string]any)
		if !ok {
			return nil, fmt.Errorf("chain auth: providers[%d] must be a map", i)
		}
		typ, ok := pm["type"].(string)
		if !ok || typ == "" {
			return nil, fmt.Errorf("chain auth: providers[%d] missing required 'type' key", i)
		}
		if typ == "chain" {
			return nil, fmt.Errorf("chain auth: providers[%d]: nested chain is not allowed", i)
		}
		params := make(map[string]any, len(pm))
		for k, v := range pm {
			if k != "type" {
				params[k] = normalizeValue(v)
			}
		}
		ac, err := auth.GetAccessController(typ, params)
		if err != nil {
			return nil, fmt.Errorf("chain auth: providers[%d] (%s): %w", i, typ, err)
		}
		controllers = append(controllers, ac)
	}

	return &chainAccessController{providers: controllers}, nil
}

// Authorized tries each provider in order. The first successful grant is
// returned. If a provider returns an auth.Challenge the next provider is
// tried. Any non-Challenge error short-circuits the chain immediately. If
// all providers challenge, the last challenge is returned.
func (c *chainAccessController) Authorized(r *http.Request, access ...auth.Access) (*auth.Grant, error) {
	var lastChallenge auth.Challenge
	for _, p := range c.providers {
		grant, err := p.Authorized(r, access...)
		if err == nil {
			return grant, nil
		}
		if ch, ok := err.(auth.Challenge); ok {
			lastChallenge = ch
			continue
		}
		// Non-challenge error (misconfiguration, network failure, etc.) — fail fast.
		return nil, err
	}
	return nil, lastChallenge
}

// normalizeValue recursively converts map[interface{}]interface{} and
// []interface{} values produced by go-yaml v2 into map[string]any and []any
// so that downstream code can use standard type assertions.
func normalizeValue(v any) any {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]any, len(val))
		for k, elem := range val {
			if ks, ok := k.(string); ok {
				out[ks] = normalizeValue(elem)
			}
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, elem := range val {
			out[k] = normalizeValue(elem)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = normalizeValue(elem)
		}
		return out
	}
	return v
}

// SetRedisClient implements auth.RedisInjectable by propagating the shared
// Redis client to every inner provider that supports the interface.
func (c *chainAccessController) SetRedisClient(client any) {
	for _, p := range c.providers {
		if ri, ok := p.(auth.RedisInjectable); ok {
			ri.SetRedisClient(client)
		}
	}
}

// TokenHandler implements auth.TokenEndpointer by trying each inner provider
// that supports the interface in order. A provider that returns 401 causes the
// next provider to be tried; any other status (including 200) is final. This
// allows the chain to serve both kubeoidc SA-JWT credentials and CoreWeave
// opaque tokens from a single /auth/token endpoint.
// If no inner provider is configured, a 501 handler is returned.
func (c *chainAccessController) TokenHandler() http.Handler {
	var handlers []http.Handler
	for _, p := range c.providers {
		if te, ok := p.(auth.TokenEndpointer); ok {
			handlers = append(handlers, te.TokenHandler())
		}
	}
	if len(handlers) == 0 {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no token endpoint configured in chain", http.StatusNotImplemented)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i, h := range handlers {
			rec := &bufferedResponseWriter{header: make(http.Header)}
			h.ServeHTTP(rec, r)
			if rec.code != http.StatusUnauthorized || i == len(handlers)-1 {
				// Success, or last provider — write whatever we got.
				for k, vs := range rec.header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(rec.code)
				_, _ = w.Write(rec.buf)
				return
			}
			// 401 from this provider — try the next one.
		}
	})
}

// bufferedResponseWriter captures an http.Handler's response so the chain can
// inspect the status code before deciding whether to forward it or try the
// next provider.
type bufferedResponseWriter struct {
	header http.Header
	code   int
	buf    []byte
}

func (b *bufferedResponseWriter) Header() http.Header { return b.header }
func (b *bufferedResponseWriter) WriteHeader(code int) {
	if b.code == 0 {
		b.code = code
	}
}
func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	if b.code == 0 {
		b.code = http.StatusOK
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}
