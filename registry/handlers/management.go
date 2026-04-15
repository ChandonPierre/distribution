package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/registry/auth"
	registrymiddleware "github.com/distribution/distribution/v3/registry/middleware/registry"
)

// setupManagementRoutes registers the management API routes on app.router under
// the /management/ prefix. These routes provide admin/control-plane operations
// and are separate from the OCI /v2/ data-plane routes.
func (app *App) setupManagementRoutes() {
	app.router.PathPrefix("/management/namespaces/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/management/namespaces/"
		name := strings.TrimSuffix(r.URL.Path[len(prefix):], "/")
		if name == "" {
			http.Error(w, "namespace name required", http.StatusBadRequest)
			return
		}
		if strings.ContainsRune(name, '/') {
			http.Error(w, "namespace name must not contain slashes", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodDelete:
			// handled below
		default:
			w.Header().Set("Allow", "PUT, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := &namespaceHandler{app: app, name: name}
		h.ServeHTTP(w, r)
	})
}

// namespaceHandler handles PUT /management/namespaces/{name}.
type namespaceHandler struct {
	app  *App
	name string
}

func (h *namespaceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := "create"
	if r.Method == http.MethodDelete {
		action = "delete"
	}

	// Authorise using the same access controller as v2 routes. For kubeoidc,
	// namespace_create / namespace_delete policy flags grant the respective
	// actions to matching tokens. For token auth, callers include
	// namespace:{name}:create or namespace:{name}:delete in scope.
	if h.app.accessController != nil {
		grant, err := h.app.accessController.Authorized(r,
			auth.Access{
				Resource: auth.Resource{Type: "namespace", Name: h.name},
				Action:   action,
			},
		)
		if err != nil {
			if challenge, ok := err.(auth.Challenge); ok {
				dcontext.GetLogger(r.Context()).Warnf("error authorizing context: %v", err)
				challenge.SetHeaders(r, w)
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				dcontext.GetLogger(r.Context()).Warnf("forbidden: namespace %s %s: %v", action, h.name, err)
				http.Error(w, "forbidden", http.StatusForbidden)
			}
			return
		}
		_ = grant
	}

	provisioner, ok := h.app.registry.(registrymiddleware.NamespaceProvisioner)
	if !ok {
		http.Error(w, "namespace provisioning not supported by this registry", http.StatusNotImplemented)
		return
	}

	if r.Method == http.MethodDelete {
		h.handleDelete(w, r, provisioner)
	} else {
		h.handleCreate(w, r, provisioner)
	}
}

func (h *namespaceHandler) handleCreate(w http.ResponseWriter, r *http.Request, p registrymiddleware.NamespaceProvisioner) {
	err := p.CreateNamespace(r.Context(), h.name)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, fmt.Sprintf("%q", h.name)) && strings.Contains(msg, "must"):
			http.Error(w, msg, http.StatusBadRequest)
		case strings.Contains(msg, "BucketAlreadyExists"):
			http.Error(w, fmt.Sprintf("bucket %q is owned by a different account", h.name), http.StatusConflict)
		default:
			http.Error(w, fmt.Sprintf("failed to create namespace: %v", err), http.StatusInternalServerError)
		}
		return
	}
	dcontext.GetLoggerWithField(r.Context(), "namespace", h.name).Info("management: namespace created")
	w.WriteHeader(http.StatusCreated)
}

func (h *namespaceHandler) handleDelete(w http.ResponseWriter, r *http.Request, p registrymiddleware.NamespaceProvisioner) {
	err := p.DeleteNamespace(r.Context(), h.name)
	if err != nil {
		var notEmpty registrymiddleware.ErrNamespaceNotEmpty
		var notFound registrymiddleware.ErrNamespaceNotFound
		switch {
		case errors.As(err, &notEmpty):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.As(err, &notFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		default:
			http.Error(w, fmt.Sprintf("failed to delete namespace: %v", err), http.StatusInternalServerError)
		}
		return
	}
	dcontext.GetLoggerWithField(r.Context(), "namespace", h.name).Info("management: namespace deleted")
	w.WriteHeader(http.StatusNoContent)
}
