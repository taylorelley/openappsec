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

// Package auth provides local user accounts, sessions and role checks for the
// manager's admin plane.
//
// Authentication is deliberately split behind the Provider interface so that
// an OIDC provider can be added later as a second implementation rather than a
// rewrite of the login path.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleEditor, RoleViewer:
		return true
	}
	return false
}

// CanEdit reports whether the role may change policy and tuning decisions.
func (r Role) CanEdit() bool { return r == RoleAdmin || r == RoleEditor }

// CanAdmin reports whether the role may manage users and manager settings.
func (r Role) CanAdmin() bool { return r == RoleAdmin }

type User struct {
	ID          uuid.UUID  `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Role        Role       `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
}

var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrUserDisabled       = errors.New("auth: account disabled")
	ErrNotFound           = errors.New("auth: not found")
	ErrDuplicate          = errors.New("auth: username already exists")
)

// Provider authenticates a principal. LocalProvider is the only implementation
// today; an OIDCProvider would satisfy the same interface.
type Provider interface {
	Name() string
	Authenticate(ctx context.Context, username, password string) (*User, error)
}

type Service struct {
	pool     *pgxpool.Pool
	provider Provider
	ttl      time.Duration
}

func NewService(pool *pgxpool.Pool, ttl time.Duration) *Service {
	s := &Service{pool: pool, ttl: ttl}
	s.provider = &LocalProvider{pool: pool}
	return s
}

// SetProvider swaps the authentication backend. Exists so that wiring an OIDC
// provider is a call here rather than a change to the login handler.
func (s *Service) SetProvider(p Provider) { s.provider = p }

func (s *Service) ProviderName() string { return s.provider.Name() }

// LocalProvider authenticates against password hashes held in the users table.
type LocalProvider struct{ pool *pgxpool.Pool }

func (p *LocalProvider) Name() string { return "local" }

func (p *LocalProvider) Authenticate(ctx context.Context, username, password string) (*User, error) {
	var (
		u    User
		hash string
	)
	err := p.pool.QueryRow(ctx, `
		SELECT id, username, email, role, disabled, created_at, last_login_at, password_hash
		  FROM users WHERE lower(username) = lower($1)`, username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt, &hash)

	if errors.Is(err, pgx.ErrNoRows) {
		// Spend comparable time on unknown users so the response time does not
		// disclose whether the account exists.
		_, _ = VerifyPassword(password, dummyHash)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil || !ok {
		return nil, ErrInvalidCredentials
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	return &u, nil
}

// A real argon2id hash of a random value, used only to equalise timing.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHR2YWx1ZXg$" +
	"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY"

// --------------------------------------------------------------- user CRUD

func (s *Service) CreateUser(ctx context.Context, username, email, password string, role Role) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("auth: username required")
	}
	if !role.Valid() {
		return nil, fmt.Errorf("auth: invalid role %q", role)
	}
	if len(password) < 12 {
		return nil, fmt.Errorf("auth: password must be at least 12 characters")
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	u := User{ID: uuid.New(), Username: username, Email: email, Role: role}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO users (id, username, email, password_hash, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at`,
		u.ID, u.Username, u.Email, hash, string(u.Role),
	).Scan(&u.CreatedAt)

	if err != nil {
		if strings.Contains(err.Error(), "users_username_key") {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	return &u, nil
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, username, email, role, disabled, created_at, last_login_at
		  FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role,
			&u.Disabled, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, email, role, disabled, created_at, last_login_at
		  FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Service) UpdateUserRole(ctx context.Context, id uuid.UUID, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("auth: invalid role %q", role)
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET role = $2, updated_at = now() WHERE id = $1`, id, string(role))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) SetUserDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET disabled = $2, updated_at = now() WHERE id = $1`, id, disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Disabling an account must also cut its live sessions, otherwise the user
	// keeps working until the cookie expires.
	if disabled {
		if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) SetPassword(ctx context.Context, id uuid.UUID, password string) error {
	if len(password) < 12 {
		return fmt.Errorf("auth: password must be at least 12 characters")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	// One transaction, because a password change that did not revoke sessions
	// would leave the account reachable with the old credential's session.
	// Changing a password must evict every existing session, the same way
	// disabling an account does: resetting the password of a compromised
	// account is precisely how an operator locks an intruder out. A caller
	// changing its own password issues itself a fresh session afterwards.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	tag, err := tx.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// VerifyPassword checks a user's password without issuing a session.
//
// Login is the wrong tool for a re-authentication check: it inserts a session
// row before returning, so using it to confirm the current password would
// leave a live session behind on every password change.
func (s *Service) VerifyPassword(ctx context.Context, id uuid.UUID, password string) error {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, id).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}
	return nil
}

// CountAdmins is used to refuse removing or demoting the last admin.
func (s *Service) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled`).Scan(&n)
	return n, err
}
