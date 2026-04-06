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
	rawProviders, ok := options["providers"].([]any)
	if !ok || len(rawProviders) == 0 {
		return nil, fmt.Errorf("chain auth: 'providers' must be a non-empty list")
	}

	controllers := make([]auth.AccessController, 0, len(rawProviders))
	for i, rp := range rawProviders {
		pm, ok := rp.(map[string]any)
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
				params[k] = v
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

// SetRedisClient implements auth.RedisInjectable by propagating the shared
// Redis client to every inner provider that supports the interface.
func (c *chainAccessController) SetRedisClient(client any) {
	for _, p := range c.providers {
		if ri, ok := p.(auth.RedisInjectable); ok {
			ri.SetRedisClient(client)
		}
	}
}

// TokenHandler implements auth.TokenEndpointer by delegating to the first
// inner provider that supports the interface. If no inner provider does,
// a 501 handler is returned so that the /auth/token endpoint exists but
// clearly communicates that no token issuer is configured in the chain.
func (c *chainAccessController) TokenHandler() http.Handler {
	for _, p := range c.providers {
		if te, ok := p.(auth.TokenEndpointer); ok {
			return te.TokenHandler()
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no token endpoint configured in chain", http.StatusNotImplemented)
	})
}
