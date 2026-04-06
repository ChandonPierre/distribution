package coreweave

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// compiledPolicy holds a pre-compiled CEL program for a single policy.
// Policies are evaluated against a "principal" map (derived from the WhoAmI
// response) and a "request" map (type, repository, actions).
type compiledPolicy struct {
	name    string
	program cel.Program

	// catalogPrefix is a static repository name prefix. The main expression is
	// probed with request["repository"]=catalogPrefix to decide inclusion.
	catalogPrefix string

	// catalogPrefixProgram is compiled from catalog_prefix_expression. When
	// non-nil it is evaluated against the principal map and its string result
	// is used directly as the catalog prefix.
	catalogPrefixProgram cel.Program

	// catalogFullAccess, when true, grants unrestricted /v2/_catalog access
	// to any principal matching the main expression.
	catalogFullAccess bool

	// namespaceCreate, when true, grants namespace:*:create to any principal
	// matching the main expression.
	namespaceCreate bool

	// namespaceDelete, when true, grants namespace:*:delete to any principal
	// matching the main expression.
	namespaceDelete bool
}

// policySet is an atomically replaceable set of compiled CEL policies.
type policySet struct {
	policies []*compiledPolicy
}

// policyFileContent is the YAML structure for the policy file.
type policyFileContent struct {
	Policies []policyConfig `yaml:"policies"`
}

// policyConfig is the raw parsed form from YAML/config.
type policyConfig struct {
	Name       string `mapstructure:"name"       yaml:"name"`
	Expression string `mapstructure:"expression" yaml:"expression"`

	CatalogPrefix           string `mapstructure:"catalog_prefix"            yaml:"catalog_prefix"`
	CatalogPrefixExpression string `mapstructure:"catalog_prefix_expression" yaml:"catalog_prefix_expression"`
	CatalogFullAccess       bool   `mapstructure:"catalog_full_access"       yaml:"catalog_full_access"`

	NamespaceCreate bool `mapstructure:"namespace_create" yaml:"namespace_create"`
	NamespaceDelete bool `mapstructure:"namespace_delete" yaml:"namespace_delete"`
}

// newCELEnv creates the shared CEL environment. Policies receive:
//   - principal — map derived from the WhoAmI response (uid, org_uid, groups, console_actions)
//   - request   — map with type, repository, actions
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.Strings(),
		cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// compilePolicies compiles a list of policyConfig into compiledPolicy.
func compilePolicies(cfgs []policyConfig, env *cel.Env) ([]*compiledPolicy, error) {
	compiled := make([]*compiledPolicy, 0, len(cfgs))
	for _, cfg := range cfgs {
		ast, iss := env.Compile(cfg.Expression)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("policy %q compile error: %w", cfg.Name, iss.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("policy %q program error: %w", cfg.Name, err)
		}
		cp := &compiledPolicy{
			name:              cfg.Name,
			program:           prg,
			catalogPrefix:     cfg.CatalogPrefix,
			catalogFullAccess: cfg.CatalogFullAccess,
			namespaceCreate:   cfg.NamespaceCreate,
			namespaceDelete:   cfg.NamespaceDelete,
		}
		if cfg.CatalogPrefixExpression != "" {
			pAst, pIss := env.Compile(cfg.CatalogPrefixExpression)
			if pIss != nil && pIss.Err() != nil {
				return nil, fmt.Errorf("policy %q catalog_prefix_expression compile error: %w", cfg.Name, pIss.Err())
			}
			cp.catalogPrefixProgram, err = env.Program(pAst)
			if err != nil {
				return nil, fmt.Errorf("policy %q catalog_prefix_expression program error: %w", cfg.Name, err)
			}
		}
		compiled = append(compiled, cp)
	}
	return compiled, nil
}

// evaluatePolicies evaluates each policy in order against the principal and
// request maps. Returns true if any policy's expression evaluates to true.
func evaluatePolicies(policies []*compiledPolicy, principal, request map[string]any) (bool, error) {
	for _, policy := range policies {
		out, _, err := policy.program.Eval(map[string]any{
			"principal": principal,
			"request":   request,
		})
		if err != nil {
			logrus.Warnf("coreweave: policy %q eval error: %v", policy.name, err)
			continue
		}
		if granted, ok := out.Value().(bool); ok && granted {
			return true, nil
		}
	}
	return false, nil
}

// catalogPrefixesForPrincipal returns the set of catalog prefixes the
// principal is permitted to see. Returns nil for full (unfiltered) access.
func catalogPrefixesForPrincipal(ps *policySet, principalMap map[string]any) []string {
	seen := make(map[string]struct{})
	var prefixes []string

	for _, p := range ps.policies {
		if p.catalogFullAccess {
			requestMap := map[string]any{
				"type":       "registry",
				"repository": "",
				"actions":    []string{"*"},
			}
			if granted, err := evaluatePolicies([]*compiledPolicy{p}, principalMap, requestMap); err == nil && granted {
				return nil // full access
			}
			continue
		}

		var prefix string

		switch {
		case p.catalogPrefixProgram != nil:
			out, _, err := p.catalogPrefixProgram.Eval(map[string]any{
				"principal": principalMap,
				"request":   map[string]any{},
			})
			if err != nil {
				logrus.Warnf("coreweave: policy %q catalog_prefix_expression eval error: %v", p.name, err)
				continue
			}
			s, ok := out.Value().(string)
			if !ok || s == "" {
				continue
			}
			// Confirm access under the main expression before including.
			probeMap := map[string]any{
				"type":       "repository",
				"repository": s + "/",
				"actions":    []string{"pull"},
			}
			if granted, err := evaluatePolicies([]*compiledPolicy{p}, principalMap, probeMap); err != nil || !granted {
				continue
			}
			prefix = s

		case p.catalogPrefix != "":
			probeMap := map[string]any{
				"type":       "repository",
				"repository": p.catalogPrefix,
				"actions":    []string{"pull"},
			}
			if granted, err := evaluatePolicies([]*compiledPolicy{p}, principalMap, probeMap); err != nil || !granted {
				continue
			}
			prefix = p.catalogPrefix

		default:
			continue
		}

		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
	}

	if len(prefixes) == 0 {
		return []string{} // non-nil empty = no repos visible
	}
	return prefixes
}

// namespaceCreateGranted reports whether any namespace_create policy matches
// for the given namespace name. namespaceName is set as request["repository"]
// so expressions can validate it (e.g.
// request["repository"].startsWith(principal["org_uid"])).
func namespaceCreateGranted(policies []*compiledPolicy, principalMap map[string]any, namespaceName string) bool {
	requestMap := map[string]any{
		"type":       "namespace",
		"repository": namespaceName,
		"actions":    []string{"create"},
	}
	for _, p := range policies {
		if !p.namespaceCreate {
			continue
		}
		if granted, err := evaluatePolicies([]*compiledPolicy{p}, principalMap, requestMap); err == nil && granted {
			return true
		}
	}
	return false
}

// namespaceDeleteGranted reports whether any namespace_delete policy matches
// for the given namespace name. namespaceName is set as request["repository"]
// so expressions can restrict which namespaces a principal may delete.
func namespaceDeleteGranted(policies []*compiledPolicy, principalMap map[string]any, namespaceName string) bool {
	requestMap := map[string]any{
		"type":       "namespace",
		"repository": namespaceName,
		"actions":    []string{"delete"},
	}
	for _, p := range policies {
		if !p.namespaceDelete {
			continue
		}
		if granted, err := evaluatePolicies([]*compiledPolicy{p}, principalMap, requestMap); err == nil && granted {
			return true
		}
	}
	return false
}

// loadPolicyFile reads a YAML policy file.
func loadPolicyFile(path string) ([]policyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", path, err)
	}
	var content policyFileContent
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("parsing policy file %q: %w", path, err)
	}
	return content.Policies, nil
}

// startPolicyReloader polls a policy file and atomically replaces the policySet.
func startPolicyReloader(path string, interval time.Duration, ptr *atomic.Pointer[policySet], env *cel.Env) {
	var lastHash [32]byte
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			data, err := os.ReadFile(path)
			if err != nil {
				logrus.Warnf("coreweave: policy reloader cannot read %q: %v", path, err)
				continue
			}
			hash := sha256.Sum256(data)
			if hash == lastHash {
				continue
			}
			var content policyFileContent
			if err := yaml.Unmarshal(data, &content); err != nil {
				logrus.Warnf("coreweave: policy reloader failed to parse %q: %v", path, err)
				continue
			}
			compiled, err := compilePolicies(content.Policies, env)
			if err != nil {
				logrus.Warnf("coreweave: policy reloader compile error in %q: %v — keeping previous policies", path, err)
				continue
			}
			ptr.Store(&policySet{policies: compiled})
			lastHash = hash
			logrus.Infof("coreweave: reloaded %d policies from %q", len(compiled), path)
		}
	}()
}
