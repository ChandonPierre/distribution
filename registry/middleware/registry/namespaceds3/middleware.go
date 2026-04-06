// Package namespaceds3 provides a registry middleware that routes each
// namespace to its own S3 bucket. The bucket name equals the namespace name.
// It is intended for use with subdomain-based namespacing, where the namespace
// is the first path component of every repository name (e.g. "myns/repo").
package namespaceds3

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"maps"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	distribution "github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/internal/dcontext"
	registrymiddleware "github.com/distribution/distribution/v3/registry/middleware/registry"
	"github.com/distribution/distribution/v3/registry/proxy"
	"github.com/distribution/distribution/v3/registry/storage"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
)

const (
	defaultMaxCacheSize  = 256
	defaultPurgeAge      = 168 * time.Hour // 1 week
	defaultPurgeInterval = 24 * time.Hour
)

func init() {
	if err := registrymiddleware.Register("namespaceds3", newNamespacedS3Registry); err != nil {
		panic(fmt.Sprintf("namespaceds3: failed to register middleware: %v", err))
	}
}

// namespacedS3Registry wraps a distribution.Namespace and routes Repository,
// Repositories, Blobs, BlobStatter, Remove, and Close calls to per-namespace
// registries, each backed by an S3 driver whose bucket equals the namespace name.
// Optionally, a request header selects a named S3 endpoint config, allowing
// different endpoints (and credentials) per request while keeping bucket=namespace.
// A separate redirectheader option enables per-request redirect vs proxy selection.
// When presignendpoint is configured, presigned URL generation uses a second S3
// driver built from those overrides instead of the normal endpoint.
type namespacedS3Registry struct {
	distribution.Namespace // fallback for non-namespace / single-component names

	s3Params        map[string]any            // base S3 params (no bucket, no endpoint overrides)
	registryOpts    []storage.RegistryOption
	endpointHeader  string                    // request header name for endpoint selection, e.g. "X-Storage-Region"
	endpoints       map[string]map[string]any // named endpoint param overrides keyed by header value
	redirectHeader  string                    // if set, presence of this header on a request triggers S3 redirect
	presignEndpoint map[string]any            // param overrides applied to the presigned-URL driver (default path only)

	cache *lruCache
}

func newNamespacedS3Registry(
	ctx context.Context,
	registry distribution.Namespace,
	_ storagedriver.StorageDriver,
	options map[string]any,
) (distribution.Namespace, error) {
	if _, hasBucket := options["bucket"]; hasBucket {
		return nil, fmt.Errorf("namespaceds3: do not set 'bucket' in options — it is derived from the namespace name")
	}

	maxSize := defaultMaxCacheSize
	if v, ok := options["maxcachesize"]; ok {
		switch n := v.(type) {
		case int:
			maxSize = n
		case int64:
			maxSize = int(n)
		case float64:
			maxSize = int(n)
		default:
			return nil, fmt.Errorf("namespaceds3: maxcachesize must be an integer, got %T", v)
		}
		if maxSize <= 0 {
			return nil, fmt.Errorf("namespaceds3: maxcachesize must be positive")
		}
	}

	purgeAge, purgeInterval, purgeDryRun, purgeEnabled, err := parsePurgeOptions(options)
	if err != nil {
		return nil, err
	}

	// Parse endpoint routing config.
	endpointHeader, _ := options["endpointheader"].(string)
	var endpoints map[string]map[string]any
	if v, ok := options["endpoints"]; ok {
		raw, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("namespaceds3: endpoints must be a map")
		}
		endpoints = make(map[string]map[string]any, len(raw))
		for k, val := range raw {
			block, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("namespaceds3: endpoint %q must be a map", k)
			}
			if _, hasBucket := block["bucket"]; hasBucket {
				return nil, fmt.Errorf("namespaceds3: endpoint %q must not set 'bucket'", k)
			}
			endpoints[k] = block
		}
	}

	// Parse redirect-vs-proxy header config.
	redirectHeader, _ := options["redirectheader"].(string)

	// Parse presign endpoint overrides. When set, presigned URL generation uses
	// a separate S3 driver built from these params merged on top of the base
	// params. Only applies on the default (no endpointheader) request path.
	var presignEndpoint map[string]any
	if v, ok := options["presignendpoint"]; ok {
		raw, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("namespaceds3: presignendpoint must be a map")
		}
		if _, hasBucket := raw["bucket"]; hasBucket {
			return nil, fmt.Errorf("namespaceds3: presignendpoint must not set 'bucket'")
		}
		presignEndpoint = raw
	}

	// Strip middleware-only keys before passing params to the S3 driver factory.
	// The S3 driver ignores unknown keys rather than erroring, so these deletes
	// are not strictly required for correctness. They are defensive: s3Params is
	// also used as the base map in mergedParamsFor, so keeping it clean ensures
	// endpoint override blocks only see real S3 params when merged in.
	s3Params := make(map[string]any, len(options))
	maps.Copy(s3Params, options)
	delete(s3Params, "maxcachesize")
	delete(s3Params, "purgeage")
	delete(s3Params, "purgeinterval")
	delete(s3Params, "purgedryrun")
	delete(s3Params, "purgeenabled")
	delete(s3Params, "endpointheader")
	delete(s3Params, "endpoints")
	delete(s3Params, "redirectheader")
	delete(s3Params, "presignendpoint")

	// If redirect-header routing is configured, enable the redirect path on all
	// per-namespace registries. The conditionalRedirectDriver wrapper then gates
	// actual presigned-URL generation on the presence of the header per request.
	registryOpts := registrymiddleware.GetRegistryOptions()
	if redirectHeader != "" {
		registryOpts = append(registryOpts, storage.EnableRedirect)
	}

	nsReg := &namespacedS3Registry{
		Namespace:       registry,
		s3Params:        s3Params,
		registryOpts:    registryOpts,
		endpointHeader:  endpointHeader,
		endpoints:       endpoints,
		redirectHeader:  redirectHeader,
		presignEndpoint: presignEndpoint,
		cache:           newLRUCache(maxSize),
	}

	if purgeEnabled {
		startNamespacePurger(ctx, nsReg.cache, purgeAge, purgeInterval, purgeDryRun)
	}

	return nsReg, nil
}

// parsePurgeOptions extracts upload-purge settings from middleware options.
// Keys: purgeage (duration string), purgeinterval (duration string),
// purgedryrun (bool), purgeenabled (bool).
func parsePurgeOptions(options map[string]any) (age, interval time.Duration, dryRun, enabled bool, err error) {
	age = defaultPurgeAge
	interval = defaultPurgeInterval
	enabled = true

	if v, ok := options["purgeage"]; ok {
		s, ok := v.(string)
		if !ok {
			return 0, 0, false, false, fmt.Errorf("namespaceds3: purgeage must be a duration string")
		}
		age, err = time.ParseDuration(s)
		if err != nil {
			return 0, 0, false, false, fmt.Errorf("namespaceds3: invalid purgeage: %w", err)
		}
	}
	if v, ok := options["purgeinterval"]; ok {
		s, ok := v.(string)
		if !ok {
			return 0, 0, false, false, fmt.Errorf("namespaceds3: purgeinterval must be a duration string")
		}
		interval, err = time.ParseDuration(s)
		if err != nil {
			return 0, 0, false, false, fmt.Errorf("namespaceds3: invalid purgeinterval: %w", err)
		}
	}
	if v, ok := options["purgedryrun"]; ok {
		dryRun, ok = v.(bool)
		if !ok {
			return 0, 0, false, false, fmt.Errorf("namespaceds3: purgedryrun must be a bool")
		}
	}
	if v, ok := options["purgeenabled"]; ok {
		enabled, ok = v.(bool)
		if !ok {
			return 0, 0, false, false, fmt.Errorf("namespaceds3: purgeenabled must be a bool")
		}
	}
	return age, interval, dryRun, enabled, nil
}

// startNamespacePurger starts a single background goroutine that periodically
// calls storage.PurgeUploads on every namespace driver currently in the cache.
// It mirrors the jitter behaviour of the main registry's upload purger.
// The goroutine exits when ctx is cancelled (i.e. when the app shuts down).
func startNamespacePurger(ctx context.Context, cache *lruCache, age, interval time.Duration, dryRun bool) {
	log := dcontext.GetLogger(ctx)
	go func() {
		randInt, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
		if err != nil {
			randInt = big.NewInt(0)
		}
		jitter := time.Duration(randInt.Int64()%60) * time.Minute
		log.Infof("namespaceds3: upload purger starting in %s", jitter)

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			olderThan := time.Now().Add(-age)
			for _, d := range cache.allDrivers() {
				storage.PurgeUploads(ctx, d, olderThan, !dryRun)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Repository routes to the per-namespace S3 registry when the repository name
// contains a namespace prefix (e.g. "myns/repo"). Single-component names fall
// back to the wrapped base registry.
func (r *namespacedS3Registry) Repository(ctx context.Context, name reference.Named) (distribution.Repository, error) {
	ns := namespaceFromRef(name)
	if ns == "" {
		return r.Namespace.Repository(ctx, name)
	}
	nsReg, err := r.getOrCreate(ctx, ns)
	if err != nil {
		return nil, err
	}
	return nsReg.Repository(ctx, name)
}

// Repositories routes to the per-namespace S3 registry when
// "subdomain.namespace" is present in the context (set by the subdomain
// namespacing middleware). Falls back to the base registry otherwise.
func (r *namespacedS3Registry) Repositories(ctx context.Context, repos []string, last string) (int, error) {
	ns := dcontext.GetStringValue(ctx, "subdomain.namespace")
	if ns == "" {
		return r.Namespace.Repositories(ctx, repos, last)
	}
	nsReg, err := r.getOrCreate(ctx, ns)
	if err != nil {
		return 0, err
	}
	return nsReg.Repositories(ctx, repos, last)
}

// Blobs returns a BlobEnumerator that aggregates across all currently-cached
// namespace registries plus the base registry. This is used by garbage
// collection to enumerate blobs eligible for deletion.
//
// Note: namespaces that have not yet received a request (cold cache) will not
// be included. For complete per-namespace GC, run MarkAndSweep against each
// namespace registry individually using its own S3 driver.
func (r *namespacedS3Registry) Blobs() distribution.BlobEnumerator {
	return &multiNamespaceBlobEnumerator{r: r}
}

// BlobStatter returns a context-aware BlobStatter that routes Stat calls to
// the per-namespace registry when "subdomain.namespace" is in the context, and
// falls back to the base registry otherwise.
func (r *namespacedS3Registry) BlobStatter() distribution.BlobStatter {
	return &contextualBlobStatter{r: r}
}

// Remove implements distribution.RepositoryRemover by routing the delete to
// the per-namespace registry. Without this, app.registry.(RepositoryRemover)
// fails at startup and all DELETE /v2/<name>/ requests silently do nothing.
func (r *namespacedS3Registry) Remove(ctx context.Context, name reference.Named) error {
	ns := namespaceFromRef(name)
	if ns == "" {
		remover, ok := r.Namespace.(distribution.RepositoryRemover)
		if !ok {
			return fmt.Errorf("namespaceds3: base registry does not support repository removal")
		}
		return remover.Remove(ctx, name)
	}
	nsReg, err := r.getOrCreate(ctx, ns)
	if err != nil {
		return err
	}
	remover, ok := nsReg.(distribution.RepositoryRemover)
	if !ok {
		return fmt.Errorf("namespaceds3: namespace registry for %q does not support repository removal", ns)
	}
	return remover.Remove(ctx, name)
}

// Close implements proxy.Closer by forwarding to the base registry if it
// supports graceful shutdown. Per-namespace registries are stateless (no
// persistent connections beyond the S3 HTTP pool) so only the base needs
// to be closed.
func (r *namespacedS3Registry) Close() error {
	if c, ok := r.Namespace.(proxy.Closer); ok {
		return c.Close()
	}
	return nil
}

// getOrCreate returns the cached distribution.Namespace for (ns, endpointKey),
// creating it (and its backing S3 driver) if not already cached. The cache key
// is a composite of ns and the endpoint key derived from the request header,
// separated by a null byte that cannot appear in either component.
func (r *namespacedS3Registry) getOrCreate(ctx context.Context, ns string) (distribution.Namespace, error) {
	endpointKey := r.endpointKeyFromCtx(ctx)
	cacheKey := ns + "\x00" + endpointKey

	reg, _, err := r.cache.getOrCreate(cacheKey, func() (distribution.Namespace, storagedriver.StorageDriver, error) {
		params := r.mergedParamsFor(ns, endpointKey)
		d, err := factory.Create(ctx, "s3aws", params)
		if err != nil {
			return nil, nil, fmt.Errorf("namespaceds3: creating S3 driver for %q/%q: %w", ns, endpointKey, err)
		}

		var drv storagedriver.StorageDriver = d
		if r.redirectHeader != "" {
			crd := &conditionalRedirectDriver{StorageDriver: d, header: r.redirectHeader}
			// When presignendpoint is configured and no named endpoint is in play,
			// build a second S3 driver pointed at the presign endpoint so that
			// RedirectURL uses different credentials/endpoint from normal traffic.
			if len(r.presignEndpoint) > 0 && endpointKey == "" {
				presignParams := r.presignParamsFor(ns, endpointKey)
				pd, err := factory.Create(ctx, "s3aws", presignParams)
				if err != nil {
					return nil, nil, fmt.Errorf("namespaceds3: creating presign S3 driver for %q: %w", ns, err)
				}
				crd.presignDriver = pd
			}
			drv = crd
		}

		reg, err := storage.NewRegistry(ctx, drv, r.registryOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("namespaceds3: creating registry for %q/%q: %w", ns, endpointKey, err)
		}
		return reg, drv, nil
	})
	return reg, err
}

// endpointKeyFromCtx reads the configured endpoint-selection header from the
// HTTP request stored in ctx. Returns "" if endpoint routing is not configured
// or no request is available.
func (r *namespacedS3Registry) endpointKeyFromCtx(ctx context.Context) string {
	if r.endpointHeader == "" || len(r.endpoints) == 0 {
		return ""
	}
	req, _ := ctx.Value("http.request").(*http.Request)
	if req == nil {
		return ""
	}
	return req.Header.Get(r.endpointHeader)
}

// mergedParamsFor builds the S3 driver parameters for a given (namespace,
// endpointKey) pair. Base params are copied, endpoint overrides are applied on
// top, and bucket is always set to ns.
func (r *namespacedS3Registry) mergedParamsFor(ns, endpointKey string) map[string]any {
	params := make(map[string]any, len(r.s3Params)+1)
	maps.Copy(params, r.s3Params)
	if endpointKey != "" {
		if block, ok := r.endpoints[endpointKey]; ok {
			maps.Copy(params, block)
		}
	}
	params["bucket"] = ns
	return params
}

// presignParamsFor builds S3 driver parameters for presigned URL generation.
// When a named endpoint is selected (endpointKey != ""), that endpoint already
// handles both normal and presigned traffic — no extra override is applied.
// On the default (no-header) path, presignEndpoint overrides are merged on top
// of the base params to point presigned URLs at a different S3 endpoint.
func (r *namespacedS3Registry) presignParamsFor(ns, endpointKey string) map[string]any {
	params := r.mergedParamsFor(ns, endpointKey)
	if endpointKey == "" && len(r.presignEndpoint) > 0 {
		maps.Copy(params, r.presignEndpoint)
	}
	return params
}

// CreateNamespace provisions an S3 bucket for the given namespace name.
// If the bucket already exists and is owned by the configured AWS account,
// the call is idempotent and returns nil.
// Returns an error if the name is invalid, the bucket is owned by a different
// account, or the AWS API call fails.
// Implements registrymiddleware.NamespaceProvisioner.
func (r *namespacedS3Registry) CreateNamespace(ctx context.Context, name string) error {
	if err := validateNamespaceName(name); err != nil {
		return err
	}
	endpointKey := r.endpointKeyFromCtx(ctx)
	params := r.mergedParamsFor(name, endpointKey)

	s3Client, err := buildS3Client(params)
	if err != nil {
		return fmt.Errorf("namespaceds3 CreateNamespace: %w", err)
	}

	input := &s3.CreateBucketInput{Bucket: aws.String(name)}
	region, _ := params["region"].(string)
	if region != "" && region != "us-east-1" {
		// us-east-1 must NOT include LocationConstraint (AWS API requirement).
		input.CreateBucketConfiguration = &s3.CreateBucketConfiguration{
			LocationConstraint: aws.String(region),
		}
	}

	_, err = s3Client.CreateBucketWithContext(ctx, input)
	if isAlreadyOwnedByYou(err) {
		return nil // idempotent — bucket exists and belongs to this account
	}
	return err
}

// DeleteNamespace removes the S3 bucket for the given namespace.
// Returns ErrNamespaceNotEmpty if the bucket still contains objects, and
// ErrNamespaceNotFound if the bucket does not exist.
// Implements registrymiddleware.NamespaceProvisioner.
func (r *namespacedS3Registry) DeleteNamespace(ctx context.Context, name string) error {
	if err := validateNamespaceName(name); err != nil {
		return err
	}
	endpointKey := r.endpointKeyFromCtx(ctx)
	params := r.mergedParamsFor(name, endpointKey)

	s3Client, err := buildS3Client(params)
	if err != nil {
		return fmt.Errorf("namespaceds3 DeleteNamespace: %w", err)
	}

	_, err = s3Client.DeleteBucketWithContext(ctx, &s3.DeleteBucketInput{Bucket: aws.String(name)})
	if err != nil {
		if ae, ok := err.(awserr.Error); ok {
			switch ae.Code() {
			case "BucketNotEmpty":
				return registrymiddleware.ErrNamespaceNotEmpty{Name: name}
			case "NoSuchBucket":
				return registrymiddleware.ErrNamespaceNotFound{Name: name}
			}
		}
		return fmt.Errorf("namespaceds3 DeleteNamespace: %w", err)
	}

	// Evict the cached registry entry so subsequent requests don't attempt to
	// use a driver backed by the now-deleted bucket.
	cacheKey := name + "\x00" + endpointKey
	r.cache.evict(cacheKey)

	return nil
}

// buildS3Client constructs an *s3.S3 client from a driver parameter map.
// It reads the same keys as the s3-aws driver (accesskey, secretkey, region,
// regionendpoint, secure, skipverify, forcepathstyle, sessiontoken).
func buildS3Client(params map[string]any) (*s3.S3, error) {
	accessKey, _ := params["accesskey"].(string)
	secretKey, _ := params["secretkey"].(string)
	sessionToken, _ := params["sessiontoken"].(string)
	region, _ := params["region"].(string)
	regionEndpoint, _ := params["regionendpoint"].(string)

	awsConfig := aws.NewConfig()
	if accessKey != "" && secretKey != "" {
		awsConfig = awsConfig.WithCredentials(
			credentials.NewStaticCredentials(accessKey, secretKey, sessionToken),
		)
	}
	if regionEndpoint != "" {
		awsConfig = awsConfig.WithEndpoint(regionEndpoint)
	}
	if region != "" {
		awsConfig = awsConfig.WithRegion(region)
	}

	secure := parseBoolParam(params, "secure", true)
	awsConfig = awsConfig.WithDisableSSL(!secure)

	if parseBoolParam(params, "skipverify", false) {
		awsConfig = awsConfig.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		})
	}

	awsConfig = awsConfig.WithS3ForcePathStyle(parseBoolParam(params, "forcepathstyle", false))

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("buildS3Client: new session: %w", err)
	}
	return s3.New(sess), nil
}

// parseBoolParam reads a bool or string param from the map with a default.
func parseBoolParam(params map[string]any, key string, def bool) bool {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch s := v.(type) {
	case bool:
		return s
	case string:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return def
		}
		return b
	}
	return def
}

// validateNamespaceName enforces S3 bucket naming rules: 3–63 characters,
// lowercase alphanumeric and hyphens only, no leading/trailing/consecutive hyphens.
func validateNamespaceName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return fmt.Errorf("namespace name %q: must be 3–63 characters", name)
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("namespace name %q: must not start or end with a hyphen", name)
	}
	if strings.Contains(name, "--") {
		return fmt.Errorf("namespace name %q: must not contain consecutive hyphens", name)
	}
	for _, r := range name {
		if !('a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '-') {
			return fmt.Errorf("namespace name %q: must contain only lowercase letters, digits, and hyphens", name)
		}
	}
	return nil
}

// isAlreadyOwnedByYou reports whether err is the AWS BucketAlreadyOwnedByYou error.
func isAlreadyOwnedByYou(err error) bool {
	if err == nil {
		return false
	}
	if ae, ok := err.(awserr.Error); ok {
		return ae.Code() == "BucketAlreadyOwnedByYou"
	}
	return false
}

// namespaceFromRef extracts the first path component of the repository name.
// For "myns/repo" returns "myns". For a single-component name returns "".
func namespaceFromRef(name reference.Named) string {
	path := reference.Path(name)
	if i := strings.IndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return ""
}

// --- BlobEnumerator aggregator ---

// multiNamespaceBlobEnumerator enumerates blobs across the base registry and
// all currently-cached namespace registries, deduplicating by digest.
type multiNamespaceBlobEnumerator struct {
	r *namespacedS3Registry
}

func (e *multiNamespaceBlobEnumerator) Enumerate(ctx context.Context, ingester func(digest.Digest) error) error {
	seen := make(map[digest.Digest]struct{})
	wrap := func(dgst digest.Digest) error {
		if _, ok := seen[dgst]; ok {
			return nil
		}
		seen[dgst] = struct{}{}
		return ingester(dgst)
	}

	// Base registry first.
	if err := e.r.Namespace.Blobs().Enumerate(ctx, wrap); err != nil {
		return err
	}

	// All cached namespace registries.
	for _, nsReg := range e.r.cache.allNamespaces() {
		if err := nsReg.Blobs().Enumerate(ctx, wrap); err != nil {
			return err
		}
	}
	return nil
}

// --- BlobStatter router ---

// contextualBlobStatter routes Stat calls to the namespace registry indicated
// by "subdomain.namespace" in the context, falling back to the base registry.
type contextualBlobStatter struct {
	r *namespacedS3Registry
}

func (s *contextualBlobStatter) Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error) {
	ns := dcontext.GetStringValue(ctx, "subdomain.namespace")
	if ns == "" {
		return s.r.Namespace.BlobStatter().Stat(ctx, dgst)
	}
	nsReg, err := s.r.getOrCreate(ctx, ns)
	if err != nil {
		return distribution.Descriptor{}, err
	}
	return nsReg.BlobStatter().Stat(ctx, dgst)
}

// --- Conditional redirect driver ---

// conditionalRedirectDriver wraps a StorageDriver and gates redirect on the
// presence of a request header. If the header is present (non-empty), RedirectURL
// is called on presignDriver (when configured) or the embedded StorageDriver,
// potentially returning a presigned S3 URL that triggers an HTTP 307 redirect.
// If the header is absent, "" is returned and the blobserver proxies bytes
// through the registry. All other StorageDriver methods are promoted unchanged.
//
// presignDriver is non-nil when presignendpoint is configured and the default
// (no endpointheader) path is in use. It points at a different S3 endpoint
// and/or credentials optimised for generating public-facing presigned URLs.
type conditionalRedirectDriver struct {
	storagedriver.StorageDriver         // handles all normal storage operations
	presignDriver storagedriver.StorageDriver // used only for RedirectURL; nil = use embedded driver
	header        string
}

func (d *conditionalRedirectDriver) RedirectURL(r *http.Request, path string) (string, error) {
	if r.Header.Get(d.header) == "" {
		return "", nil // header absent → proxy
	}
	if d.presignDriver != nil {
		return d.presignDriver.RedirectURL(r, path)
	}
	return d.StorageDriver.RedirectURL(r, path)
}

// --- Cache ---

type cacheEntry struct {
	key    string // composite cache key: namespace + "\x00" + endpointKey
	reg    distribution.Namespace
	driver storagedriver.StorageDriver // retained for upload purging
}

// lruCache is a size-bounded cache of (namespace, endpoint) driver instances.
//
// Hot path (cache hit): sync.Map.Load — zero contention, no mutex.
// Cold path (cache miss): singleflight coalesces concurrent creation for the
// same key so only one S3 driver is built; others wait and share the result.
// Eviction: a narrow mutex guards insertion-order bookkeeping and is never
// held during driver creation. Eviction order is FIFO (not strict LRU) because
// hits no longer update order — acceptable since the cap is a memory safety
// bound, not a cache efficiency mechanism.
type lruCache struct {
	maxSize int
	items   sync.Map           // string → *cacheEntry; concurrent reads
	sf      singleflight.Group // per-key creation coalescing

	mu    sync.Mutex // guards order and byKey only
	order *list.List // *cacheEntry in insertion order (front = newest)
	byKey map[string]*list.Element
}

func newLRUCache(maxSize int) *lruCache {
	return &lruCache{
		maxSize: maxSize,
		order:   list.New(),
		byKey:   make(map[string]*list.Element),
	}
}

// getOrCreate returns the cached entry for key. On a miss at most one create()
// call runs; concurrent misses for the same key wait and share the result.
func (c *lruCache) getOrCreate(key string, create func() (distribution.Namespace, storagedriver.StorageDriver, error)) (distribution.Namespace, storagedriver.StorageDriver, error) {
	// Hot path: no lock, no contention.
	if v, ok := c.items.Load(key); ok {
		e := v.(*cacheEntry)
		return e.reg, e.driver, nil
	}

	// Cold path: at most one create() runs per key; others wait and share.
	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Re-check after winning the singleflight slot — a concurrent goroutine
		// may have just finished creating the same entry.
		if v, ok := c.items.Load(key); ok {
			return v, nil
		}
		reg, driver, err := create()
		if err != nil {
			return nil, err
		}
		entry := &cacheEntry{key: key, reg: reg, driver: driver}

		// Eviction bookkeeping — mutex held for microseconds, never during I/O.
		c.mu.Lock()
		for c.order.Len() >= c.maxSize {
			back := c.order.Back()
			if back == nil {
				break
			}
			evicted := c.order.Remove(back).(*cacheEntry)
			delete(c.byKey, evicted.key)
			c.items.Delete(evicted.key)
		}
		el := c.order.PushFront(entry)
		c.byKey[key] = el
		c.mu.Unlock()

		// Make visible to future hot-path loads only after bookkeeping is done.
		c.items.Store(key, entry)
		return entry, nil
	})
	if err != nil {
		return nil, nil, err
	}
	entry := v.(*cacheEntry)
	return entry.reg, entry.driver, nil
}

// evict removes a single entry from the cache by key, if present.
func (c *lruCache) evict(key string) {
	c.mu.Lock()
	if el, ok := c.byKey[key]; ok {
		c.order.Remove(el)
		delete(c.byKey, key)
	}
	c.mu.Unlock()
	c.items.Delete(key)
}

// allNamespaces returns all cached distribution.Namespace instances.
func (c *lruCache) allNamespaces() []distribution.Namespace {
	var regs []distribution.Namespace
	c.items.Range(func(_, v any) bool {
		regs = append(regs, v.(*cacheEntry).reg)
		return true
	})
	return regs
}

// allDrivers returns all cached storage drivers, used by the upload purger.
func (c *lruCache) allDrivers() []storagedriver.StorageDriver {
	var drivers []storagedriver.StorageDriver
	c.items.Range(func(_, v any) bool {
		drivers = append(drivers, v.(*cacheEntry).driver)
		return true
	})
	return drivers
}
