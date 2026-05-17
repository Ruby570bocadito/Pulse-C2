package handlers

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// serveSPA serves the Vue.js SPA frontend.
func (r *Router) serveSPA(mux *http.ServeMux) {
	distPath := r.findWebDist()
	if distPath == "" {
		return
	}

	fileServer := http.FileServer(http.Dir(distPath))
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/api/") {
			http.NotFound(w, req)
			return
		}
		path := filepath.Join(distPath, filepath.Clean(req.URL.Path))
		if _, err := os.Stat(path); err == nil {
			fileServer.ServeHTTP(w, req)
			return
		}
		http.ServeFile(w, req, filepath.Join(distPath, "index.html"))
	})
	log.Printf("[WEB] Serving SPA from %s", distPath)
}

func (r *Router) findWebDist() string {
	candidates := []string{
		"web/dist",
		"../../web/dist",
		"../../../web/dist",
	}
	for _, p := range candidates {
		if info, err := os.Stat(filepath.Join(p, "index.html")); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}
