package middleware

import (
	"context"
	"fmt"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/storage"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
)

// InitFunc is the type of a RegistryMiddleware factory function and is
// used to register the constructor for different RegistryMiddleware backends.
type InitFunc func(ctx context.Context, registry distribution.Namespace, driver storagedriver.StorageDriver, options map[string]any) (distribution.Namespace, error)

var (
	middlewares     map[string]InitFunc
	registryoptions []storage.RegistryOption
)

// Register is used to register an InitFunc for
// a RegistryMiddleware backend with the given name.
func Register(name string, initFunc InitFunc) error {
	if middlewares == nil {
		middlewares = make(map[string]InitFunc)
	}
	if _, exists := middlewares[name]; exists {
		return fmt.Errorf("name already registered: %s", name)
	}

	middlewares[name] = initFunc

	return nil
}

// Get constructs a RegistryMiddleware with the given options using the named backend.
func Get(ctx context.Context, name string, options map[string]any, registry distribution.Namespace, driver storagedriver.StorageDriver) (distribution.Namespace, error) {
	if middlewares != nil {
		if initFunc, exists := middlewares[name]; exists {
			return initFunc(ctx, registry, driver, options)
		}
	}

	return nil, fmt.Errorf("no registry middleware registered with name: %s", name)
}

// RegisterOptions adds more options to RegistryOption list. Options get applied before
// any other configuration-based options.
func RegisterOptions(options ...storage.RegistryOption) error {
	registryoptions = append(registryoptions, options...)
	return nil
}

// GetRegistryOptions returns list of RegistryOption.
func GetRegistryOptions() []storage.RegistryOption {
	return registryoptions
}

type contextKey struct{}

// WithRegistryOptions stores a complete RegistryOption slice in the context so
// that registry middleware initialised via Get (e.g. namespaceds3) can retrieve
// the full set assembled by the application, including options such as
// BlobDescriptorCacheProvider that are added after RegisterOptions is called.
func WithRegistryOptions(ctx context.Context, opts []storage.RegistryOption) context.Context {
	return context.WithValue(ctx, contextKey{}, opts)
}

// RegistryOptionsFromContext returns the RegistryOption slice stored by
// WithRegistryOptions, or the globally registered options when none has been
// stored in the context.
func RegistryOptionsFromContext(ctx context.Context) []storage.RegistryOption {
	if opts, ok := ctx.Value(contextKey{}).([]storage.RegistryOption); ok {
		return opts
	}
	return registryoptions
}
