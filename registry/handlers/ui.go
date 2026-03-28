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
	return http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
}
