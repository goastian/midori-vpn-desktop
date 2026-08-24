package rpc

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

func setBrowserSecurityHeaders(w http.ResponseWriter) {
	setLocalSecurityHeaders(w)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
}

func (s *Server) browserUIHandler() http.Handler {
	root := os.DirFS(s.uiDir)
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setBrowserSecurityHeaders(w)
		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "." || cleanPath == "" {
			cleanPath = "index.html"
		}
		info, err := fs.Stat(root, cleanPath)
		if err != nil || info.IsDir() {
			cleanPath = "index.html"
		}
		if cleanPath == "index.html" {
			contents, openErr := fs.ReadFile(root, cleanPath)
			if openErr != nil {
				if errors.Is(openErr, fs.ErrNotExist) {
					http.Error(w, "ui_not_installed", http.StatusServiceUnavailable)
					return
				}
				http.Error(w, "ui_unavailable", http.StatusInternalServerError)
				return
			}
			stat, statErr := fs.Stat(root, cleanPath)
			if statErr != nil {
				http.Error(w, "ui_unavailable", http.StatusInternalServerError)
				return
			}
			http.ServeContent(w, r, "index.html", stat.ModTime(), bytes.NewReader(contents))
			return
		}
		r.URL.Path = "/" + cleanPath
		files.ServeHTTP(w, r)
	})
}
