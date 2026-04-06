package chain

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/distribution/distribution/v3/registry/auth"
)

// mockController is a simple AccessController for testing.
type mockController struct {
	grant *auth.Grant
	err   error
	calls int
}

func (m *mockController) Authorized(_ *http.Request, _ ...auth.Access) (*auth.Grant, error) {
	m.calls++
	return m.grant, m.err
}

// mockChallenge implements auth.Challenge.
type mockChallenge struct{ msg string }

func (c mockChallenge) Error() string { return c.msg }
func (c mockChallenge) SetHeaders(_ *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer realm=\"test\"")
}

// mockTokenEndpointer adds TokenHandler to a mockController.
type mockTokenEndpointer struct {
	mockController
	handler http.Handler
}

func (m *mockTokenEndpointer) TokenHandler() http.Handler { return m.handler }

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFirstGrantWins(t *testing.T) {
	grant := &auth.Grant{User: auth.UserInfo{Name: "alice"}}
	a := &mockController{grant: grant}
	b := &mockController{grant: &auth.Grant{User: auth.UserInfo{Name: "bob"}}}
	c := &chainAccessController{providers: []auth.AccessController{a, b}}

	got, err := c.Authorized(newRequest(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.User.Name != "alice" {
		t.Errorf("expected alice, got %s", got.User.Name)
	}
	if b.calls != 0 {
		t.Error("second provider should not have been called")
	}
}

func TestChallengeSkipsToNext(t *testing.T) {
	grant := &auth.Grant{User: auth.UserInfo{Name: "alice"}}
	a := &mockController{err: mockChallenge{"unauthorized"}}
	b := &mockController{grant: grant}
	c := &chainAccessController{providers: []auth.AccessController{a, b}}

	got, err := c.Authorized(newRequest(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.User.Name != "alice" {
		t.Errorf("expected alice, got %s", got.User.Name)
	}
	if a.calls != 1 || b.calls != 1 {
		t.Errorf("expected both providers called once, got a=%d b=%d", a.calls, b.calls)
	}
}

func TestAllChallengeReturnsLast(t *testing.T) {
	ch1 := mockChallenge{"first"}
	ch2 := mockChallenge{"second"}
	a := &mockController{err: ch1}
	b := &mockController{err: ch2}
	c := &chainAccessController{providers: []auth.AccessController{a, b}}

	_, err := c.Authorized(newRequest(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ch auth.Challenge
	if !errors.As(err, &ch) {
		t.Fatalf("expected auth.Challenge, got %T: %v", err, err)
	}
	if err.Error() != "second" {
		t.Errorf("expected last challenge %q, got %q", "second", err.Error())
	}
}

func TestNonChallengeErrorFailsFast(t *testing.T) {
	hardErr := errors.New("network failure")
	a := &mockController{err: hardErr}
	b := &mockController{grant: &auth.Grant{}}
	c := &chainAccessController{providers: []auth.AccessController{a, b}}

	_, err := c.Authorized(newRequest(t))
	if !errors.Is(err, hardErr) {
		t.Errorf("expected hard error, got %v", err)
	}
	if b.calls != 0 {
		t.Error("second provider should not have been called after non-challenge error")
	}
}

func TestTokenHandlerDelegatesToFirst(t *testing.T) {
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	a := &mockController{err: mockChallenge{"ch"}} // no TokenHandler
	b := &mockTokenEndpointer{
		mockController: mockController{grant: &auth.Grant{}},
		handler:        sentinel,
	}
	c := &chainAccessController{providers: []auth.AccessController{a, b}}

	h := c.TokenHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newRequest(t))
	if w.Code != http.StatusTeapot {
		t.Errorf("expected 418 from delegated handler, got %d", w.Code)
	}
}

func TestTokenHandlerNoEndpointer(t *testing.T) {
	a := &mockController{}
	c := &chainAccessController{providers: []auth.AccessController{a}}

	h := c.TokenHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newRequest(t))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}
}

func TestNewChainMissingProviders(t *testing.T) {
	_, err := newChainAccessController(map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing providers key")
	}
}

func TestNewChainMissingType(t *testing.T) {
	_, err := newChainAccessController(map[string]any{
		"providers": []any{
			map[string]any{"realm": "test"},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing type key")
	}
}

func TestNewChainNestedChainRejected(t *testing.T) {
	_, err := newChainAccessController(map[string]any{
		"providers": []any{
			map[string]any{"type": "chain"},
		},
	})
	if err == nil {
		t.Fatal("expected error for nested chain")
	}
}
