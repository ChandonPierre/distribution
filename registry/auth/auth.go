// Package auth defines a standard interface for request access controllers.
//
// An access controller has a simple interface with a single `Authorized`
// method which checks that a given request is authorized to perform one or
// more actions on one or more resources. This method should return a non-nil
// error if the request is not authorized.
//
// An implementation registers its access controller by name with a constructor
// which accepts an options map for configuring the access controller.
//
//	options := map[string]interface{}{"sillySecret": "whysosilly?"}
//	accessController, _ := auth.GetAccessController("silly", options)
//
// This `accessController` can then be used in a request handler like so:
//
//	func updateOrder(w http.ResponseWriter, r *http.Request) {
//		orderNumber := r.FormValue("orderNumber")
//		resource := auth.Resource{Type: "customerOrder", Name: orderNumber}
//		access := auth.Access{Resource: resource, Action: "update"}
//
//		if ctx, err := accessController.Authorized(r, access); err != nil {
//			if challenge, ok := err.(auth.Challenge) {
//				// Let the challenge write the response.
//				challenge.SetHeaders(r, w)
//				w.WriteHeader(http.StatusUnauthorized)
//				return
//			} else {
//				// Some other error.
//			}
//		}
//	}
package auth

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrInvalidCredential is returned when the auth token does not authenticate correctly.
	ErrInvalidCredential = errors.New("invalid authorization credential")

	// ErrAuthenticationFailure returned when authentication fails.
	ErrAuthenticationFailure = errors.New("authentication failure")
)

// InitFunc is the type of an AccessController factory function and is used
// to register the constructor for different AccessController backends.
type InitFunc func(options map[string]any) (AccessController, error)

var accessControllers map[string]InitFunc

func init() {
	accessControllers = make(map[string]InitFunc)
}

// UserInfo carries information about
// an authenticated/authorized client.
type UserInfo struct {
	Name string
}

// Resource describes a resource by type and name.
type Resource struct {
	Type  string
	Class string
	Name  string
}

// Access describes a specific action that is
// requested or allowed for a given resource.
type Access struct {
	Resource
	Action string
}

// Grant describes the permitted level of access for an authorized request.
type Grant struct {
	User      UserInfo   // The authenticated user for the request.
	Resources []Resource // The list of resources which have been authorized for the request.
	// CatalogPrefixes restricts /v2/_catalog responses to repositories that
	// start with one of these prefixes. A nil slice means no filtering (all
	// repositories are visible). A non-nil empty slice means catalog access is
	// granted but no repositories match (e.g. empty-prefix policy).
	CatalogPrefixes []string
}

// Challenge is a special error type which is used for HTTP 401 Unauthorized
// responses and is able to write the response with WWW-Authenticate challenge
// header values based on the error.
type Challenge interface {
	error

	// SetHeaders prepares the request to conduct a challenge response by
	// adding the an HTTP challenge header on the response message. Callers
	// are expected to set the appropriate HTTP status code (e.g. 401)
	// themselves.
	SetHeaders(r *http.Request, w http.ResponseWriter)
}

// AccessController controls access to registry resources based on a request
// and required access levels for a request. Implementations can support both
// complete denial and http authorization challenges.
type AccessController interface {
	// Authorized determines if the request is granted access. If one or more
	// Access structs are provided, the requested access will be compared with
	// what is available to the request.
	//
	// Return a Grant to grant the request access. Return an error to deny
	// access. The error may be of type Challenge, in which case the caller may
	// have the Challenge handle the request or choose what action to take based
	// on the Challenge header or response status.
	Authorized(r *http.Request, access ...Access) (*Grant, error)
}

// CredentialAuthenticator is an object which is able to authenticate credentials
type CredentialAuthenticator interface {
	AuthenticateUser(username, password string) error
}

// TokenEndpointer is an optional interface that an AccessController may implement
// to expose a built-in token endpoint (e.g. GET /auth/token).
// When the registry detects this interface, it registers the handler on the
// configured token path so that standard Docker clients can exchange credentials
// for a short-lived registry JWT without a separate token service.
type TokenEndpointer interface {
	// TokenHandler returns an http.Handler that serves the token endpoint.
	// The path at which it is registered is determined by the registry.
	TokenHandler() http.Handler
}

// RedisInjectable may be implemented by an AccessController to receive the
// application's shared Redis client after construction. The client argument
// will be of type redis.UniversalClient (from github.com/redis/go-redis/v9).
// This method is called at most once, before the server begins serving requests.
// Providers that implement this interface use the injected client instead of
// opening their own connection when the app already has Redis configured.
type RedisInjectable interface {
	SetRedisClient(client any)
}

// Register is used to register an InitFunc for
// an AccessController backend with the given name.
func Register(name string, initFunc InitFunc) error {
	if _, exists := accessControllers[name]; exists {
		return fmt.Errorf("name already registered: %s", name)
	}

	accessControllers[name] = initFunc

	return nil
}

// GetAccessController constructs an AccessController
// with the given options using the named backend.
func GetAccessController(name string, options map[string]any) (AccessController, error) {
	if initFunc, exists := accessControllers[name]; exists {
		return initFunc(options)
	}

	return nil, fmt.Errorf("no access controller registered with name: %s", name)
}
