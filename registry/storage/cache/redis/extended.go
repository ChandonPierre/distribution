package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/redis/go-redis/v9"
)

const (
	defaultTagListTTL = 60 * time.Second
	defaultCatalogTTL = 5 * time.Minute
)

// AppCache provides manifest content, tag-to-digest, tag-list, and catalog
// caching via Redis. All misses and Redis errors are non-fatal: callers fall
// through to the storage backend on any cache failure.
type AppCache struct {
	pool       redis.UniversalClient
	tagListTTL time.Duration
	catalogTTL time.Duration
}

// NewAppCache constructs an AppCache backed by the given Redis client.
func NewAppCache(pool redis.UniversalClient) *AppCache {
	return &AppCache{
		pool:       pool,
		tagListTTL: defaultTagListTTL,
		catalogTTL: defaultCatalogTTL,
	}
}

// ─── Manifest content cache (no TTL — content-addressed, immutable) ──────────

type manifestEntry struct {
	ContentType string `json:"ct"`
	Payload     []byte `json:"p"`
}

func manifestKey(dgst digest.Digest) string {
	return "manifest::" + dgst.String()
}

// GetManifest returns the cached content-type and payload for a manifest
// digest. Returns ("", nil, nil) on a cache miss or any Redis error.
func (c *AppCache) GetManifest(ctx context.Context, dgst digest.Digest) (ct string, payload []byte, err error) {
	raw, redisErr := c.pool.Get(ctx, manifestKey(dgst)).Bytes()
	if redisErr != nil {
		return "", nil, nil
	}
	var entry manifestEntry
	if jsonErr := json.Unmarshal(raw, &entry); jsonErr != nil {
		return "", nil, nil
	}
	return entry.ContentType, entry.Payload, nil
}

// SetManifest stores the manifest content permanently (no TTL — manifests are
// content-addressed and never change).
func (c *AppCache) SetManifest(ctx context.Context, dgst digest.Digest, ct string, payload []byte) error {
	entry := manifestEntry{ContentType: ct, Payload: payload}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return c.pool.Set(ctx, manifestKey(dgst), raw, 0).Err()
}

// DeleteManifest evicts a manifest from the cache.
func (c *AppCache) DeleteManifest(ctx context.Context, dgst digest.Digest) error {
	return c.pool.Del(ctx, manifestKey(dgst)).Err()
}

// ─── Tag → digest cache (write-through, invalidated on push/untag) ───────────

func tagKey(repo, tag string) string {
	return "tag::" + repo + "::" + tag
}

// GetTag returns the cached digest for the given repo and tag. Returns
// ("", nil) on a miss or error.
func (c *AppCache) GetTag(ctx context.Context, repo, tag string) (digest.Digest, error) {
	val, err := c.pool.Get(ctx, tagKey(repo, tag)).Result()
	if err != nil {
		return "", nil
	}
	dgst := digest.Digest(val)
	if err := dgst.Validate(); err != nil {
		return "", nil
	}
	return dgst, nil
}

// SetTag writes a tag→digest mapping with no TTL.
func (c *AppCache) SetTag(ctx context.Context, repo, tag string, dgst digest.Digest) error {
	return c.pool.Set(ctx, tagKey(repo, tag), dgst.String(), 0).Err()
}

// DeleteTag evicts a single tag entry.
func (c *AppCache) DeleteTag(ctx context.Context, repo, tag string) error {
	return c.pool.Del(ctx, tagKey(repo, tag)).Err()
}

// ─── Tag list cache (short TTL, invalidated on push/untag) ───────────────────

func tagListKey(repo string) string {
	return "tags::" + repo
}

// GetTagList returns the cached full tag list for a repo. Returns (nil, nil)
// on a miss or error.
func (c *AppCache) GetTagList(ctx context.Context, repo string) ([]string, error) {
	raw, err := c.pool.Get(ctx, tagListKey(repo)).Bytes()
	if err != nil {
		return nil, nil
	}
	var tags []string
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil, nil
	}
	return tags, nil
}

// SetTagList stores the full tag list with a short TTL.
func (c *AppCache) SetTagList(ctx context.Context, repo string, tags []string) error {
	raw, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	return c.pool.Set(ctx, tagListKey(repo), raw, c.tagListTTL).Err()
}

// InvalidateTagList evicts the tag list for a repo so the next read
// re-fetches from storage.
func (c *AppCache) InvalidateTagList(ctx context.Context, repo string) error {
	return c.pool.Del(ctx, tagListKey(repo)).Err()
}

// ─── Catalog cache (short TTL) ────────────────────────────────────────────────

func catalogCacheKey(key string) string {
	return "catalog::" + key
}

// GetCatalog returns the cached catalog for the given key. Returns (nil, nil)
// on a miss or error. key distinguishes different catalog views (e.g. "global"
// or "ns::myns").
func (c *AppCache) GetCatalog(ctx context.Context, key string) ([]string, error) {
	raw, err := c.pool.Get(ctx, catalogCacheKey(key)).Bytes()
	if err != nil {
		return nil, nil
	}
	var repos []string
	if err := json.Unmarshal(raw, &repos); err != nil {
		return nil, nil
	}
	return repos, nil
}

// SetCatalog stores the catalog for the given key with a short TTL.
func (c *AppCache) SetCatalog(ctx context.Context, key string, repos []string) error {
	raw, err := json.Marshal(repos)
	if err != nil {
		return err
	}
	return c.pool.Set(ctx, catalogCacheKey(key), raw, c.catalogTTL).Err()
}
