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

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pmezard/go-difflib/difflib"
)

var ErrNotFound = errors.New("policy: revision not found")

type Revision struct {
	ID         int64      `json:"id"`
	APIVersion string     `json:"apiVersion"`
	Body       Document   `json:"body"`
	Checksum   string     `json:"checksum"`
	Message    string     `json:"message"`
	AuthorID   *uuid.UUID `json:"authorId,omitempty"`
	AuthorName string     `json:"authorName,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

type Service struct {
	pool       *pgxpool.Pool
	renderer   Renderer
	outputPath string
}

func NewService(pool *pgxpool.Pool, outputPath string) *Service {
	return &Service{pool: pool, renderer: LocalPolicyYAML{}, outputPath: outputPath}
}

// EnsureSeedRevision creates the initial revision from the shipped default
// policy, so a fresh install has something coherent to edit and deploy.
func (s *Service) EnsureSeedRevision(ctx context.Context) error {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM policy_revisions`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	doc, err := DefaultDocument()
	if err != nil {
		return err
	}
	rev, err := s.CreateRevision(ctx, doc, "Initial revision from the shipped default policy", nil)
	if err != nil {
		return err
	}
	return s.Assign(ctx, nil, rev.ID, nil)
}

// CreateRevision validates and stores a new immutable revision. Revisions are
// append-only: rollback is re-assignment of an earlier one, never an edit.
func (s *Service) CreateRevision(ctx context.Context, doc Document, message string, author *uuid.UUID) (*Revision, error) {
	result, err := Validate(doc)
	if err != nil {
		return nil, err
	}
	if !result.OK() {
		return nil, fmt.Errorf("policy is invalid: %s", result.Error())
	}

	checksum, err := doc.Checksum()
	if err != nil {
		return nil, err
	}
	body, err := doc.JSON()
	if err != nil {
		return nil, err
	}

	rev := &Revision{APIVersion: doc.APIVersion(), Body: doc, Checksum: checksum,
		Message: message, AuthorID: author}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO policy_revisions (api_version, body, checksum, message, author_id)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		rev.APIVersion, body, checksum, message, author,
	).Scan(&rev.ID, &rev.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rev, nil
}

func (s *Service) GetRevision(ctx context.Context, id int64) (*Revision, error) {
	var (
		rev  Revision
		body []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT r.id, r.api_version, r.body, r.checksum, r.message, r.author_id,
		       COALESCE(u.username, ''), r.created_at
		  FROM policy_revisions r
		  LEFT JOIN users u ON u.id = r.author_id
		 WHERE r.id = $1`, id,
	).Scan(&rev.ID, &rev.APIVersion, &body, &rev.Checksum, &rev.Message,
		&rev.AuthorID, &rev.AuthorName, &rev.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if rev.Body, err = ParseJSON(body); err != nil {
		return nil, err
	}
	return &rev, nil
}

func (s *Service) ListRevisions(ctx context.Context, limit int) ([]Revision, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.api_version, r.checksum, r.message, r.author_id,
		       COALESCE(u.username, ''), r.created_at
		  FROM policy_revisions r
		  LEFT JOIN users u ON u.id = r.author_id
		 ORDER BY r.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	revs := []Revision{}
	for rows.Next() {
		var rev Revision
		if err := rows.Scan(&rev.ID, &rev.APIVersion, &rev.Checksum, &rev.Message,
			&rev.AuthorID, &rev.AuthorName, &rev.CreatedAt); err != nil {
			return nil, err
		}
		revs = append(revs, rev)
	}
	return revs, rows.Err()
}

// Assign points an agent — or the whole fleet, when agentID is nil — at a
// revision, and immediately re-renders the shared-volume artefact.
func (s *Service) Assign(ctx context.Context, agentID *uuid.UUID, revisionID int64, by *uuid.UUID) error {
	if _, err := s.GetRevision(ctx, revisionID); err != nil {
		return err
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_assignments (agent_id, revision_id, assigned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (COALESCE(agent_id, '00000000-0000-0000-0000-000000000000'::uuid))
		DO UPDATE SET revision_id = EXCLUDED.revision_id,
		              assigned_by = EXCLUDED.assigned_by,
		              assigned_at = now()`,
		agentID, revisionID, by)
	if err != nil {
		return err
	}

	// Volume delivery is best-effort: a manager running without a shared
	// volume still serves the same policy over the companion's pull endpoint.
	if agentID == nil {
		if err := s.WriteVolumeArtifact(ctx); err != nil {
			return fmt.Errorf("assignment saved, but writing %s failed: %w", s.outputPath, err)
		}
	}
	return nil
}

// DeployedRevision returns the revision an agent should be running: its own
// assignment if it has one, otherwise the fleet default.
func (s *Service) DeployedRevision(ctx context.Context, agentID *uuid.UUID) (*Revision, error) {
	var revID int64
	err := s.pool.QueryRow(ctx, `
		SELECT revision_id FROM policy_assignments
		 WHERE agent_id IS NOT DISTINCT FROM $1`, agentID).Scan(&revID)

	if errors.Is(err, pgx.ErrNoRows) && agentID != nil {
		// Fall back to the fleet-wide default.
		err = s.pool.QueryRow(ctx, `
			SELECT revision_id FROM policy_assignments WHERE agent_id IS NULL`).Scan(&revID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetRevision(ctx, revID)
}

// Rendered returns the local_policy.yaml for an agent, plus an ETag so the
// pull companion can avoid re-applying an unchanged policy.
func (s *Service) Rendered(ctx context.Context, agentID *uuid.UUID) ([]byte, string, *Revision, error) {
	rev, err := s.DeployedRevision(ctx, agentID)
	if err != nil {
		return nil, "", nil, err
	}
	body, err := s.renderer.Render(rev.Body)
	if err != nil {
		return nil, "", nil, err
	}
	sum := sha256.Sum256(body)
	return body, `"` + hex.EncodeToString(sum[:]) + `"`, rev, nil
}

// WriteVolumeArtifact renders the fleet-default policy to the shared volume.
//
// The write is atomic: the agent polls this path (or has it symlinked over
// /etc/cp/conf/local_policy.yaml) and would otherwise be able to read a
// half-written file and fail the load.
func (s *Service) WriteVolumeArtifact(ctx context.Context) error {
	if s.outputPath == "" {
		return nil
	}
	body, _, _, err := s.Rendered(ctx, nil)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}

	dir := filepath.Dir(s.outputPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".local_policy-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.outputPath)
}

// Diff returns a unified diff of the rendered form of two revisions, which is
// what the reviewer sees before pressing Enforce.
func (s *Service) Diff(ctx context.Context, fromID, toID int64) (string, error) {
	from, err := s.GetRevision(ctx, fromID)
	if err != nil {
		return "", err
	}
	to, err := s.GetRevision(ctx, toID)
	if err != nil {
		return "", err
	}

	fromBody, err := s.renderer.Render(from.Body)
	if err != nil {
		return "", err
	}
	toBody, err := s.renderer.Render(to.Body)
	if err != nil {
		return "", err
	}

	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(fromBody)),
		B:        difflib.SplitLines(string(toBody)),
		FromFile: fmt.Sprintf("revision %d", fromID),
		ToFile:   fmt.Sprintf("revision %d", toID),
		Context:  3,
	})
}

// DiffAgainstDeployed compares a candidate document with what is currently
// deployed, without creating a revision — this drives the editor's live diff.
func (s *Service) DiffAgainstDeployed(ctx context.Context, candidate Document) (string, error) {
	rendered, err := s.renderer.Render(candidate)
	if err != nil {
		return "", err
	}

	var current []byte
	deployed, err := s.DeployedRevision(ctx, nil)
	switch {
	case err == nil:
		if current, err = s.renderer.Render(deployed.Body); err != nil {
			return "", err
		}
	case errors.Is(err, ErrNotFound):
		current = nil
	default:
		return "", err
	}

	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(current)),
		B:        difflib.SplitLines(string(rendered)),
		FromFile: "deployed",
		ToFile:   "candidate",
		Context:  3,
	})
}

// Renderer exposes the active renderer, so callers can name the artefact.
func (s *Service) Renderer() Renderer { return s.renderer }
