package kubeoidc

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
type compiledPolicy struct {
	name    string
	program cel.Program

	// catalogPrefix is a static prefix. catalogPrefixesForToken probes the
	// main program with this prefix to decide whether to include it.
	catalogPrefix string

	// catalogPrefixProgram is compiled from catalog_prefix_expression. When
	// non-nil it is evaluated against the token map and its string result is
	// used directly as the catalog prefix, without probing the main program.
	catalogPrefixProgram cel.Program

	// catalogFullAccess, when true, grants unrestricted catalog access to any
	// token matching the main expression (no prefix filtering).
	catalogFullAccess bool

	// namespaceCreate, when true, grants namespace:*:create to any token
	// matching the main expression.
	namespaceCreate bool

	// namespaceDelete, when true, grants namespace:*:delete to any token
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

// newCELEnv creates the shared CEL environment with token and request variables.
// The ext.Strings() library is included to enable string operations such as
// substring(), split(), replace(), and lowerAscii() in policy expressions.
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.Strings(),
		cel.Variable("token", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// compilePolicies compiles a list of policyConfig into compiledPolicy using the given CEL env.
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

// evaluatePolicies evaluates each policy in order. Returns true if any policy grants access.
// token and request are map[string]any inputs matching the CEL variable types.
func evaluatePolicies(policies []*compiledPolicy, token, request map[string]any) (bool, error) {
	for _, policy := range policies {
		out, _, err := policy.program.Eval(map[string]any{
			"token":   token,
			"request": request,
		})
		if err != nil {
			logrus.Warnf("kubeoidc: policy %q eval error: %v", policy.name, err)
			continue
		}
		if granted, ok := out.Value().(bool); ok && granted {
			return true, nil
		}
	}
	return false, nil
}

// namespaceCreateGranted reports whether any policy with namespace_create: true
// has its main expression satisfied by the given token, granting the caller the
// ability to create the named namespace via the management API.
// namespaceName is set as request["repository"] so expressions can validate it
// (e.g. request["repository"].startsWith(token["org_id"])).
func namespaceCreateGranted(policies []*compiledPolicy, tokenMap map[string]any, namespaceName string) bool {
	requestMap := map[string]any{
		"type":       "namespace",
		"repository": namespaceName,
		"actions":    []string{"create"},
	}
	for _, p := range policies {
		if !p.namespaceCreate {
			continue
		}
		if granted, err := evaluatePolicies([]*compiledPolicy{p}, tokenMap, requestMap); err == nil && granted {
			return true
		}
	}
	return false
}

// namespaceDeleteGranted reports whether any policy with namespace_delete: true
// has its main expression satisfied by the given token.
// namespaceName is set as request["repository"] so expressions can restrict
// which namespaces a principal is permitted to delete.
func namespaceDeleteGranted(policies []*compiledPolicy, tokenMap map[string]any, namespaceName string) bool {
	requestMap := map[string]any{
		"type":       "namespace",
		"repository": namespaceName,
		"actions":    []string{"delete"},
	}
	for _, p := range policies {
		if !p.namespaceDelete {
			continue
		}
		if granted, err := evaluatePolicies([]*compiledPolicy{p}, tokenMap, requestMap); err == nil && granted {
			return true
		}
	}
	return false
}

// loadPolicyFile reads a YAML file and returns its policy list.
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

// startPolicyReloader polls a policy file and atomically replaces the policySet when valid.
// If a reload produces a compile error, the previous policySet remains active.
func startPolicyReloader(path string, interval time.Duration, ptr *atomic.Pointer[policySet], env *cel.Env) {
	var lastHash [32]byte
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			data, err := os.ReadFile(path)
			if err != nil {
				logrus.Warnf("kubeoidc: policy reloader cannot read %q: %v", path, err)
				continue
			}
			hash := sha256.Sum256(data)
			if hash == lastHash {
				continue
			}
			var content policyFileContent
			if err := yaml.Unmarshal(data, &content); err != nil {
				logrus.Warnf("kubeoidc: policy reloader failed to parse %q: %v", path, err)
				continue
			}
			compiled, err := compilePolicies(content.Policies, env)
			if err != nil {
				logrus.Warnf("kubeoidc: policy reloader compile error in %q: %v — keeping previous policies", path, err)
				continue
			}
			ptr.Store(&policySet{policies: compiled})
			lastHash = hash
			logrus.Infof("kubeoidc: reloaded %d policies from %q", len(compiled), path)
		}
	}()
}
