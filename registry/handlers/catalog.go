package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/gorilla/handlers"
)

const defaultReturnedEntries = 100

func catalogDispatcher(ctx *Context, r *http.Request) http.Handler {
	catalogHandler := &catalogHandler{
		Context: ctx,
	}

	return handlers.MethodHandler{
		http.MethodGet: http.HandlerFunc(catalogHandler.GetCatalog),
	}
}

type catalogHandler struct {
	*Context
}

type catalogAPIResponse struct {
	Repositories []string `json:"repositories"`
}

func (ch *catalogHandler) GetCatalog(w http.ResponseWriter, r *http.Request) {
	moreEntries := true

	q := r.URL.Query()
	lastEntry := q.Get("last")

	// In subdomain-namespacing mode, scope the catalog to the current namespace
	// and translate the client-supplied pagination cursor into storage space.
	if ns := getSubdomainNamespace(ch.Context); ns != "" {
		if lastEntry != "" {
			lastEntry = ns + "/" + lastEntry
		}
		existing := getCatalogPrefixes(ch.Context)
		var scopedPrefixes []string
		if existing == nil {
			scopedPrefixes = []string{ns + "/"}
		} else {
			for _, p := range existing {
				if strings.HasPrefix(p, ns+"/") {
					scopedPrefixes = append(scopedPrefixes, p)
				} else if p == ns || strings.HasPrefix(ns+"/", p) {
					scopedPrefixes = append(scopedPrefixes, ns+"/")
				}
			}
			if scopedPrefixes == nil {
				scopedPrefixes = []string{} // non-nil empty = no repos visible
			}
		}
		ch.Context.Context = withCatalogPrefixes(ch.Context.Context, scopedPrefixes)
	}

	entries := defaultReturnedEntries
	maximumConfiguredEntries := ch.App.Config.Catalog.MaxEntries

	// parse n, if n is negative abort with an error
	if n := q.Get("n"); n != "" {
		parsedMax, err := strconv.Atoi(n)
		if err != nil || parsedMax < 0 {
			ch.Errors = append(ch.Errors, errcode.ErrorCodePaginationNumberInvalid.WithDetail(map[string]string{"n": n}))
			return
		}

		// if a client requests more than it's allowed to receive
		if parsedMax > maximumConfiguredEntries {
			ch.Errors = append(ch.Errors, errcode.ErrorCodePaginationNumberInvalid.WithDetail(map[string]int{"n": parsedMax}))
			return
		}
		entries = parsedMax
	}

	// then enforce entries to be between 0 & maximumConfiguredEntries
	// max(0, min(entries, maximumConfiguredEntries))
	if entries < 0 || entries > maximumConfiguredEntries {
		entries = maximumConfiguredEntries
	}

	repos := make([]string, entries)
	filled := 0

	// entries is guaranteed to be >= 0 and < maximumConfiguredEntries
	if entries == 0 {
		moreEntries = false
	} else if prefixes := getCatalogPrefixes(ch.Context); prefixes != nil {
		// Prefix-filtered path: seek the storage cursor to each prefix in sorted
		// order so we skip irrelevant repos instead of scanning from position 0.
		// No Link header is emitted because the raw storage cursor cannot be
		// safely exposed after in-memory filtering.
		moreEntries = false

		sortedPrefixes := append([]string(nil), prefixes...)
		sort.Strings(sortedPrefixes)

		page := make([]string, entries)
		seen := make(map[string]struct{})

		for _, pfx := range sortedPrefixes {
			if filled >= entries {
				break
			}
			pfxEnd := pfx + "\xff"
			// Setting cursor = pfx starts the scan just after the bare prefix
			// string. Repo names always contain a path separator (e.g. "ns/img"),
			// so they sort after "ns" and will not be skipped.
			cursor := pfx
			for filled < entries {
				n, err := ch.App.registry.Repositories(ch.Context, page, cursor)
				pastPrefix := false
				for _, repo := range page[:n] {
					if strings.HasPrefix(repo, pfx) {
						if _, dup := seen[repo]; !dup {
							repos[filled] = repo
							seen[repo] = struct{}{}
							filled++
							if filled == entries {
								break
							}
						}
					} else if repo > pfxEnd {
						pastPrefix = true
						break
					}
				}
				if pastPrefix || n == 0 {
					break
				}
				if err != nil {
					_, pathNotFound := err.(driver.PathNotFoundError)
					if err != io.EOF && !pathNotFound {
						ch.Errors = append(ch.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
						return
					}
					break
				}
				cursor = page[n-1]
				if cursor >= pfxEnd {
					break
				}
			}
		}
	} else {
		returnedRepositories, err := ch.App.registry.Repositories(ch.Context, repos, lastEntry)
		if err != nil {
			_, pathNotFound := err.(driver.PathNotFoundError)
			if err != io.EOF && !pathNotFound {
				ch.Errors = append(ch.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
				return
			}
			// err is either io.EOF or not PathNotFoundError
			moreEntries = false
		}
		filled = returnedRepositories
	}

	// In subdomain-namespacing mode, strip the namespace prefix from returned
	// repository names so clients see only the repo component.
	if ns := getSubdomainNamespace(ch.Context); ns != "" {
		nsSlash := ns + "/"
		for i, repo := range repos[:filled] {
			repos[i] = strings.TrimPrefix(repo, nsSlash)
		}
	}

	w.Header().Set("Content-Type", "application/json")

	// Add a link header if there are more entries to retrieve
	if moreEntries {
		lastEntry = repos[filled-1]
		urlStr, err := createLinkEntry(r.URL.String(), entries, lastEntry)
		if err != nil {
			ch.Errors = append(ch.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
			return
		}
		w.Header().Set("Link", urlStr)
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(catalogAPIResponse{
		Repositories: repos[0:filled],
	}); err != nil {
		ch.Errors = append(ch.Errors, errcode.ErrorCodeUnknown.WithDetail(err))
		return
	}
}

// Use the original URL from the request to create a new URL for
// the link header
func createLinkEntry(origURL string, maxEntries int, lastEntry string) (string, error) {
	calledURL, err := url.Parse(origURL)
	if err != nil {
		return "", err
	}

	v := url.Values{}
	v.Add("n", strconv.Itoa(maxEntries))
	v.Add("last", lastEntry)

	calledURL.RawQuery = v.Encode()

	calledURL.Fragment = ""
	urlStr := fmt.Sprintf("<%s>; rel=\"next\"", calledURL.String())

	return urlStr, nil
}
