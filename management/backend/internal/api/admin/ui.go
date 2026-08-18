// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package admin

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

// mountUI serves the built single-page frontend.
func (s *Server) mountUI(r chi.Router) {
	if s.ui == nil {
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w,
				"open-appsec Manager API is running, but no web UI is embedded in this build.\n"+
					"Build the frontend with `npm run build` in management/frontend and rebuild.\n")
		})
		return
	}

	fileServer := http.FileServer(http.FS(s.ui))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		// An unmatched /api path is a genuine 404, not a client-side route;
		// falling through to index.html there would turn API typos into
		// confusing HTML responses.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, http.StatusNotFound, "no such endpoint")
			return
		}

		if s.serveAsset(w, r, fileServer) {
			return
		}
		// Anything else is a client-side route: serve the SPA shell.
		s.serveIndex(w, r)
	})
}

// serveAsset serves a real file if one exists, reporting whether it did.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request, fileServer http.Handler) bool {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		return false
	}
	f, err := s.ui.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()

	if info, err := f.Stat(); err != nil || info.IsDir() {
		return false
	}

	// Hashed build assets are safe to cache for a long time; everything else
	// is revalidated so a redeploy is picked up.
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	fileServer.ServeHTTP(w, r)
	return true
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	index, err := fs.ReadFile(s.ui, "index.html")
	if err != nil {
		writeError(w, http.StatusNotFound, "web UI is not available in this build")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := w.Write(index); err != nil {
		return
	}
}
