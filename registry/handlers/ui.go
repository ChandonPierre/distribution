package handlers

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:ui/dist
var uiFS embed.FS

// uiHandler returns an http.Handler that serves the compiled UI static files
// from the embedded filesystem under the /ui/ path prefix.
func uiHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect /ui → /ui/ without relying on gorilla StrictSlash, which
		// would cause a loop when combined with PathPrefix registration.
		if r.URL.Path == "/ui" {
			http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
			return
		}
		// Strip /ui/ prefix so the file server sees paths relative to dist/.
		r2 := r.Clone(r.Context())
		r2.URL.Path = r.URL.Path[len("/ui/"):]
		if r2.URL.Path == "" {
			r2.URL.Path = "/"
		}
		// If the path corresponds to a real asset (JS, CSS, etc.) serve it directly.
		// Otherwise fall back to index.html so the React router can handle the route.
		if _, err := sub.Open(r2.URL.Path); err != nil {
			r2.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r2)
	})
}
