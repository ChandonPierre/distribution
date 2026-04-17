package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

func emit(format string, a ...any) {
	fmt.Printf(format+"\n", a...)
}

// GCOpts contains options for garbage collector
type GCOpts struct {
	DryRun         bool
	RemoveUntagged bool
	Quiet          bool
	Workers        int // number of concurrent manifest workers; 0 or 1 = sequential
	// GracePeriod skips deletion of blobs whose last-modified time is more
	// recent than this duration. Set to a value longer than the longest
	// expected blob-upload-to-manifest-put window (e.g. 1h) to prevent GC
	// from deleting blobs that were uploaded concurrently with the mark phase.
	GracePeriod time.Duration
}

// ManifestDel contains manifest structure which will be deleted
type ManifestDel struct {
	Name   string
	Digest digest.Digest
	Tags   []string
}

// MarkAndSweep performs a mark and sweep of registry data
func MarkAndSweep(ctx context.Context, storageDriver driver.StorageDriver, registry distribution.Namespace, opts GCOpts) error {
	repositoryEnumerator, ok := registry.(distribution.RepositoryEnumerator)
	if !ok {
		return fmt.Errorf("unable to convert Namespace to RepositoryEnumerator")
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 1
	}

	// mark
	var mu sync.Mutex
	markSet := make(map[digest.Digest]struct{})
	deleteLayerSet := make(map[string][]digest.Digest)
	manifestArr := make([]ManifestDel, 0)

	err := repositoryEnumerator.Enumerate(ctx, func(repoName string) error {
		if !opts.Quiet {
			emit(repoName)
		}

		named, err := reference.WithName(repoName)
		if err != nil {
			return fmt.Errorf("failed to parse repo name %s: %v", repoName, err)
		}
		repository, err := registry.Repository(ctx, named)
		if err != nil {
			return fmt.Errorf("failed to construct repository: %v", err)
		}

		manifestService, err := repository.Manifests(ctx)
		if err != nil {
			return fmt.Errorf("failed to construct manifest service: %v", err)
		}

		manifestEnumerator, ok := manifestService.(distribution.ManifestEnumerator)
		if !ok {
			return fmt.Errorf("unable to convert ManifestService into ManifestEnumerator")
		}

		// Collect all manifest digests for this repository first, then process
		// them in parallel. This avoids holding the enumerator open while
		// issuing concurrent storage requests.
		var dgsts []digest.Digest
		err = manifestEnumerator.Enumerate(ctx, func(dgst digest.Digest) error {
			dgsts = append(dgsts, dgst)
			return nil
		})
		if err != nil {
			// In certain situations such as unfinished uploads, deleting all
			// tags in S3 or removing the _manifests folder manually, this
			// error may be of type PathNotFound.
			//
			// In these cases we can continue marking other manifests safely.
			if _, ok := err.(driver.PathNotFoundError); !ok {
				return err
			}
		}

		// Process manifests with a bounded worker pool.
		g, gctx := errgroup.WithContext(ctx)
		sem := semaphore.NewWeighted(int64(workers))
		for _, dgst := range dgsts {
			if err := sem.Acquire(gctx, 1); err != nil {
				return err
			}
			g.Go(func() error {
				defer sem.Release(1)
				return markManifest(gctx, dgst, repoName, repository, manifestService, &mu, markSet, &manifestArr, opts)
			})
		}
		if err := g.Wait(); err != nil {
			return err
		}

		blobService := repository.Blobs(ctx)
		layerEnumerator, ok := blobService.(distribution.ManifestEnumerator)
		if !ok {
			return errors.New("unable to convert BlobService into ManifestEnumerator")
		}

		var deleteLayers []digest.Digest
		err = layerEnumerator.Enumerate(ctx, func(dgst digest.Digest) error {
			mu.Lock()
			_, marked := markSet[dgst]
			mu.Unlock()
			if !marked {
				deleteLayers = append(deleteLayers, dgst)
			}
			return nil
		})
		if len(deleteLayers) > 0 {
			deleteLayerSet[repoName] = deleteLayers
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to mark: %v", err)
	}

	manifestArr = unmarkReferencedManifest(manifestArr, markSet, opts.Quiet)

	// sweep
	vacuum := NewVacuum(ctx, storageDriver)
	if !opts.DryRun {
		for _, obj := range manifestArr {
			err = vacuum.RemoveManifest(obj.Name, obj.Digest, obj.Tags)
			if err != nil {
				return fmt.Errorf("failed to delete manifest %s: %v", obj.Digest, err)
			}
		}
	}
	blobService := registry.Blobs()
	deleteSet := make(map[digest.Digest]struct{})
	err = blobService.Enumerate(ctx, func(dgst digest.Digest) error {
		// check if digest is in markSet. If not, delete it!
		mu.Lock()
		_, marked := markSet[dgst]
		mu.Unlock()
		if !marked {
			deleteSet[dgst] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error enumerating blobs: %v", err)
	}
	if !opts.Quiet {
		emit("\n%d blobs marked, %d blobs and %d manifests eligible for deletion", len(markSet), len(deleteSet), len(manifestArr))
	}
	for dgst := range deleteSet {
		if opts.GracePeriod > 0 {
			blobPath, err := pathFor(blobDataPathSpec{digest: dgst})
			if err != nil {
				return fmt.Errorf("failed to build path for blob %s: %v", dgst, err)
			}
			fi, err := storageDriver.Stat(ctx, blobPath)
			if err != nil {
				if _, ok := err.(driver.PathNotFoundError); ok {
					// already gone; skip
					continue
				}
				return fmt.Errorf("failed to stat blob %s: %v", dgst, err)
			}
			if age := time.Since(fi.ModTime()); age < opts.GracePeriod {
				if !opts.Quiet {
					emit("blob %s skipped (age %s < grace period %s)", dgst, age.Round(time.Second), opts.GracePeriod)
				}
				continue
			}
		}
		if !opts.Quiet {
			emit("blob eligible for deletion: %s", dgst)
		}
		if opts.DryRun {
			continue
		}
		err = vacuum.RemoveBlob(string(dgst))
		if err != nil {
			return fmt.Errorf("failed to delete blob %s: %v", dgst, err)
		}
	}

	for repo, dgsts := range deleteLayerSet {
		for _, dgst := range dgsts {
			if !opts.Quiet {
				emit("%s: layer link eligible for deletion: %s", repo, dgst)
			}
			if opts.DryRun {
				continue
			}
			err = vacuum.RemoveLayer(repo, dgst)
			if err != nil {
				return fmt.Errorf("failed to delete layer link %s of repo %s: %v", dgst, repo, err)
			}
		}
	}

	return err
}

// markManifest marks a single manifest digest and all blobs it references.
// It is safe to call concurrently; all shared state is protected by mu.
func markManifest(ctx context.Context, dgst digest.Digest, repoName string,
	repository distribution.Repository, manifestService distribution.ManifestService,
	mu *sync.Mutex, markSet map[digest.Digest]struct{},
	manifestArr *[]ManifestDel, opts GCOpts) error {

	if opts.RemoveUntagged {
		// fetch all tags where this manifest is the latest one
		tags, err := repository.Tags(ctx).Lookup(ctx, v1.Descriptor{Digest: dgst})
		if err != nil {
			return fmt.Errorf("failed to retrieve tags for digest %v: %v", dgst, err)
		}
		if len(tags) == 0 {
			// fetch all tags from repository
			// all of these tags could contain manifest in history
			// which means that we need check (and delete) those references when deleting manifest
			allTags, err := repository.Tags(ctx).All(ctx)
			if err != nil {
				if _, ok := err.(distribution.ErrRepositoryUnknown); ok {
					if !opts.Quiet {
						emit("manifest tags path of repository %s does not exist", repoName)
					}
					return nil
				}
				return fmt.Errorf("failed to retrieve tags %v", err)
			}
			mu.Lock()
			*manifestArr = append(*manifestArr, ManifestDel{Name: repoName, Digest: dgst, Tags: allTags})
			mu.Unlock()
			return nil
		}
	}

	// Early exit: if this digest was already marked (e.g., referenced by a manifest
	// index in another repo, or a duplicate in this repo), skip the manifest Get()
	// entirely. The ingester in markManifestReferences already deduplicates blobs,
	// but this check avoids the more expensive manifest fetch at the outer level.
	mu.Lock()
	_, alreadyMarked := markSet[dgst]
	if !alreadyMarked {
		markSet[dgst] = struct{}{}
	}
	mu.Unlock()

	if alreadyMarked {
		return nil
	}

	if !opts.Quiet {
		emit("%s: marking manifest %s ", repoName, dgst)
	}

	return markManifestReferences(dgst, manifestService, ctx, func(d digest.Digest) bool {
		mu.Lock()
		defer mu.Unlock()
		_, marked := markSet[d]
		if !marked {
			markSet[d] = struct{}{}
			if !opts.Quiet {
				emit("%s: marking blob %s", repoName, d)
			}
		}
		return marked
	})
}

// unmarkReferencedManifest filters out manifest present in markSet
func unmarkReferencedManifest(manifestArr []ManifestDel, markSet map[digest.Digest]struct{}, quietOutput bool) []ManifestDel {
	filtered := make([]ManifestDel, 0)
	for _, obj := range manifestArr {
		if _, ok := markSet[obj.Digest]; !ok {
			if !quietOutput {
				emit("manifest eligible for deletion: %s", obj)
			}

			filtered = append(filtered, obj)
		}
	}
	return filtered
}

// markManifestReferences marks the manifest references
func markManifestReferences(dgst digest.Digest, manifestService distribution.ManifestService, ctx context.Context, ingester func(digest.Digest) bool) error {
	manifest, err := manifestService.Get(ctx, dgst)
	if err != nil {
		return fmt.Errorf("failed to retrieve manifest for digest %v: %v", dgst, err)
	}

	descriptors := manifest.References()
	for _, descriptor := range descriptors {

		// do not visit references if already marked
		if ingester(descriptor.Digest) {
			continue
		}

		if ok, _ := manifestService.Exists(ctx, descriptor.Digest); ok {
			err := markManifestReferences(descriptor.Digest, manifestService, ctx, ingester)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
