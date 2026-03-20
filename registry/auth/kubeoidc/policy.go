package kubeoidc

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// compiledPolicy holds a pre-compiled CEL program for a single policy.
type compiledPolicy struct {
	name    string
	program cel.Program
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
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
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
		compiled = append(compiled, &compiledPolicy{name: cfg.Name, program: prg})
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
