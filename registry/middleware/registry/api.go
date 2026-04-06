package middleware

import "context"

// NamespaceProvisioner is optionally implemented by registry middlewares
// that can provision and deprovision storage for a namespace on demand.
type NamespaceProvisioner interface {
	CreateNamespace(ctx context.Context, name string) error
	// DeleteNamespace removes the backing storage for a namespace.
	// Implementations must return ErrNamespaceNotEmpty if the bucket/store
	// still contains objects, so callers can map it to 409 Conflict.
	DeleteNamespace(ctx context.Context, name string) error
}

// ErrNamespaceNotEmpty is returned by DeleteNamespace when the backing store
// is not empty and the implementation refuses to force-delete it.
type ErrNamespaceNotEmpty struct{ Name string }

func (e ErrNamespaceNotEmpty) Error() string {
	return "namespace " + e.Name + " is not empty"
}

// ErrNamespaceNotFound is returned by DeleteNamespace when the namespace does
// not exist.
type ErrNamespaceNotFound struct{ Name string }

func (e ErrNamespaceNotFound) Error() string {
	return "namespace " + e.Name + " not found"
}
