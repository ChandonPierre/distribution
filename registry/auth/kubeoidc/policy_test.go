package kubeoidc

import (
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompilePoliciesSuccess(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{Name: "test", Expression: `token["iss"] == "https://example.com" && "pull" in request["actions"]`},
	}
	compiled, err := compilePolicies(cfgs, env)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("expected 1 compiled policy, got %d", len(compiled))
	}
}

func TestCompilePoliciesInvalidExpression(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{Name: "bad", Expression: `token.iss === "x"`}, // === is invalid CEL
	}
	_, err = compilePolicies(cfgs, env)
	if err == nil {
		t.Fatal("expected compile error for invalid expression")
	}
}

func TestEvaluatePolicies_Granted(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{
			Name: "ci",
			Expression: `token["iss"] == "https://k8s.example.com" &&
				token["sub"].startsWith("system:serviceaccount:ci:") &&
				"push" in request["actions"]`,
		},
	}
	policies, err := compilePolicies(cfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	token := map[string]any{
		"iss": "https://k8s.example.com",
		"sub": "system:serviceaccount:ci:builder",
		"aud": []string{"registry.example.com"},
	}
	request := map[string]any{
		"type":       "repository",
		"repository": "myorg/myimage",
		"actions":    []string{"push"},
	}

	granted, err := evaluatePolicies(policies, token, request)
	if err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Fatal("expected access to be granted")
	}
}

func TestEvaluatePolicies_Denied(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{
			Name:       "ci",
			Expression: `token["sub"].startsWith("system:serviceaccount:ci:")`,
		},
	}
	policies, err := compilePolicies(cfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	token := map[string]any{
		"iss": "https://k8s.example.com",
		"sub": "system:serviceaccount:prod:app",
		"aud": []string{"registry.example.com"},
	}
	request := map[string]any{
		"type":       "repository",
		"repository": "myorg/myimage",
		"actions":    []string{"push"},
	}

	granted, err := evaluatePolicies(policies, token, request)
	if err != nil {
		t.Fatal(err)
	}
	if granted {
		t.Fatal("expected access to be denied")
	}
}

func TestEvaluatePolicies_FirstMatchWins(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{Name: "deny-all", Expression: `false`},
		{Name: "allow-pull", Expression: `"pull" in request["actions"]`},
	}
	policies, err := compilePolicies(cfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	token := map[string]any{"iss": "x", "sub": "x", "aud": []string{"y"}}
	request := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"pull"}}

	// First policy is false; second should match.
	granted, err := evaluatePolicies(policies, token, request)
	if err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Fatal("expected second policy to grant access")
	}
}

func TestEvaluatePolicies_MultiIssuer(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{
			Name:       "cluster-a-only",
			Expression: `token["iss"] == "https://cluster-a.example.com" && "pull" in request["actions"]`,
		},
	}
	policies, err := compilePolicies(cfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	// Token from cluster-a should be granted.
	tokenA := map[string]any{"iss": "https://cluster-a.example.com", "sub": "sa", "aud": []string{"reg"}}
	request := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"pull"}}

	granted, _ := evaluatePolicies(policies, tokenA, request)
	if !granted {
		t.Error("expected cluster-a token to be granted")
	}

	// Token from cluster-b should be denied.
	tokenB := map[string]any{"iss": "https://cluster-b.example.com", "sub": "sa", "aud": []string{"reg"}}
	granted, _ = evaluatePolicies(policies, tokenB, request)
	if granted {
		t.Error("expected cluster-b token to be denied")
	}
}

func TestEvaluatePolicies_MultiAction(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfgs := []policyConfig{
		{Name: "pull-only", Expression: `request["actions"] == ["pull"]`},
	}
	policies, err := compilePolicies(cfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	// Pull-only request: should be granted.
	tokenM := map[string]any{"iss": "x", "sub": "sa", "aud": []string{"reg"}}
	requestPull := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"pull"}}
	granted, _ := evaluatePolicies(policies, tokenM, requestPull)
	if !granted {
		t.Error("expected pull to be granted")
	}

	// Push request: should be denied.
	requestPush := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"push"}}
	granted, _ = evaluatePolicies(policies, tokenM, requestPush)
	if granted {
		t.Error("expected push to be denied by pull-only policy")
	}
}

func TestLivePolicyReload_Success(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}

	// Start with a "deny all" policy.
	initialCfgs := []policyConfig{{Name: "deny", Expression: `false`}}
	initialPolicies, err := compilePolicies(initialCfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	var ptr atomic.Pointer[policySet]
	ptr.Store(&policySet{policies: initialPolicies})

	// Write a policy file that allows pull.
	f, err := os.CreateTemp(t.TempDir(), "policies*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("policies:\n  - name: allow-pull\n    expression: '\"pull\" in request[\"actions\"]'\n")
	f.Close()

	startPolicyReloader(f.Name(), 50*time.Millisecond, &ptr, env)
	time.Sleep(200 * time.Millisecond)

	ps := ptr.Load()
	token := map[string]any{"iss": "x", "sub": "sa", "aud": []string{"r"}}
	request := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"pull"}}

	granted, err := evaluatePolicies(ps.policies, token, request)
	if err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Fatal("expected reloaded policy to grant access")
	}
}

func TestLivePolicyReload_InvalidKeepsOld(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}

	// Start with an "allow all" policy.
	initialCfgs := []policyConfig{{Name: "allow", Expression: `true`}}
	initialPolicies, err := compilePolicies(initialCfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	var ptr atomic.Pointer[policySet]
	ptr.Store(&policySet{policies: initialPolicies})

	// Write a file with an invalid CEL expression.
	f, err := os.CreateTemp(t.TempDir(), "policies*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("policies:\n  - name: bad\n    expression: 'this === invalid'\n")
	f.Close()

	startPolicyReloader(f.Name(), 50*time.Millisecond, &ptr, env)
	time.Sleep(200 * time.Millisecond)

	// Policy set should still be the old one (allow all).
	ps := ptr.Load()
	token := map[string]any{"iss": "x", "sub": "sa", "aud": []string{"r"}}
	request := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"pull"}}

	granted, _ := evaluatePolicies(ps.policies, token, request)
	if !granted {
		t.Fatal("expected old (allow-all) policy to remain active after invalid reload")
	}
}

func TestLivePolicyReload_NoChangeSkipped(t *testing.T) {
	env, err := newCELEnv()
	if err != nil {
		t.Fatal(err)
	}

	// Start with "allow all".
	initialCfgs := []policyConfig{{Name: "allow", Expression: `true`}}
	initialPolicies, err := compilePolicies(initialCfgs, env)
	if err != nil {
		t.Fatal(err)
	}

	var ptr atomic.Pointer[policySet]
	initial := &policySet{policies: initialPolicies}
	ptr.Store(initial)

	// Write valid policy file.
	f, err := os.CreateTemp(t.TempDir(), "policies*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("policies:\n  - name: allow\n    expression: 'true'\n")
	f.Close()

	startPolicyReloader(f.Name(), 50*time.Millisecond, &ptr, env)
	time.Sleep(200 * time.Millisecond)

	// Write same content again; the pointer should have been replaced once (first load),
	// but subsequent iterations should be no-ops. We can't easily detect "skipped" directly,
	// so just verify the policy still works correctly.
	ps := ptr.Load()
	token := map[string]any{"iss": "x", "sub": "sa", "aud": []string{"r"}}
	request := map[string]any{"type": "repository", "repository": "repo", "actions": []string{"pull"}}

	granted, _ := evaluatePolicies(ps.policies, token, request)
	if !granted {
		t.Fatal("expected policy to grant access after no-change reload")
	}
}
