package server

import (
	"embed"
	"net/http"
)

// web/favicon.ico is a copy of assets/favicon.ico, because go:embed cannot
// reach above the package directory. TestFaviconMatchesAsset fails when the
// two drift.
//
//go:embed web/index.html web/favicon.ico
var webFS embed.FS

// registerWebUI adds the root handler that serves the embedded web UI, and
// the favicon a browser requests beside it. Both pass through the same
// middleware chain and read scope: routeScope exempts neither.
func (s *Server) registerWebUI() {
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		_, _ = w.Write(data)
	})
	s.mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := webFS.ReadFile("web/favicon.ico")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		// private: the response sat behind the read scope, so no shared
		// cache may hand it to a caller who never authenticated.
		w.Header().Set("Cache-Control", "private, max-age=86400")
		_, _ = w.Write(data)
	})
}
