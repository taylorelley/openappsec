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

// Package web embeds the built frontend.
//
// The dist directory is produced by `npm run build` in management/frontend and
// copied here by the Docker build. A placeholder keeps the embed directive
// valid when the frontend has not been built, so the API can still be compiled
// and tested on its own.
package web

import (
	"embed"
	"errors"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// Assets returns the built frontend rooted at dist, or an error when this
// build contains only the placeholder.
func Assets() (fs.FS, error) {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, err
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, errors.New("web: no built frontend embedded (dist/index.html is missing)")
	}
	return sub, nil
}
