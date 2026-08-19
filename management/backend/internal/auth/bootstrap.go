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

package auth

import (
	"context"
	"fmt"
)

// BootstrapResult reports what Bootstrap did, so the caller can surface a
// generated password exactly once.
type BootstrapResult struct {
	Created           bool
	Username          string
	GeneratedPassword string
}

// Bootstrap creates the initial admin account if no users exist yet. When no
// password is supplied one is generated; it is returned to the caller to be
// logged once and never stored in plaintext.
func (s *Service) Bootstrap(ctx context.Context, username, password string) (BootstrapResult, error) {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return BootstrapResult{}, err
	}
	if count > 0 {
		return BootstrapResult{}, nil
	}

	if username == "" {
		username = "admin"
	}

	generated := ""
	if password == "" {
		tok, err := NewToken()
		if err != nil {
			return BootstrapResult{}, err
		}
		// Trim to a length that is still far beyond brute force but is
		// realistic to copy out of a log line.
		password = tok[:24]
		generated = password
	}

	if _, err := s.CreateUser(ctx, username, "", password, RoleAdmin); err != nil {
		return BootstrapResult{}, fmt.Errorf("create bootstrap admin: %w", err)
	}

	return BootstrapResult{
		Created:           true,
		Username:          username,
		GeneratedPassword: generated,
	}, nil
}
