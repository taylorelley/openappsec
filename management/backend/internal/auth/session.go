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
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

const SessionCookieName = "appsec_manager_session"

// Login authenticates via the configured provider and, on success, issues a
// session. The returned string is the raw token; only its hash is stored.
func (s *Service) Login(ctx context.Context, username, password, userAgent, remoteAddr string) (string, *User, error) {
	user, err := s.provider.Authenticate(ctx, username, password)
	if err != nil {
		return "", nil, err
	}

	token, err := NewToken()
	if err != nil {
		return "", nil, err
	}
	expires := time.Now().Add(s.ttl)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO sessions (token_hash, user_id, expires_at, user_agent, remote_addr)
		VALUES ($1, $2, $3, $4, $5)`,
		HashToken(token), user.ID, expires, userAgent, remoteAddr)
	if err != nil {
		return "", nil, err
	}

	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login_at = now() WHERE id = $1`, user.ID); err != nil {
		return "", nil, err
	}
	return token, user, nil
}

// Resolve looks up the user behind a session token, refreshing last_seen_at.
// Expired sessions are treated as absent.
func (s *Service) Resolve(ctx context.Context, token string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		UPDATE sessions SET last_seen_at = now()
		 WHERE token_hash = $1 AND expires_at > now()
		RETURNING (SELECT id       FROM users WHERE users.id = sessions.user_id),
		          (SELECT username FROM users WHERE users.id = sessions.user_id),
		          (SELECT email    FROM users WHERE users.id = sessions.user_id),
		          (SELECT role     FROM users WHERE users.id = sessions.user_id),
		          (SELECT disabled FROM users WHERE users.id = sessions.user_id)`,
		HashToken(token),
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Disabled)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	return &u, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, HashToken(token))
	return err
}

// PurgeExpiredSessions is run periodically by the manager's background loop.
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SetSessionCookie writes the session cookie. Secure is driven by whether the
// admin plane is actually serving TLS: setting Secure on a plain-HTTP listener
// would make the cookie silently unusable.
func (s *Service) SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(s.ttl),
	})
}

func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
