package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) SaveApplication(ctx context.Context, app Application) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO applications (
		id, name, digest, manifest_json, created_at
	) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(id) DO UPDATE SET name=excluded.name, digest=excluded.digest,
		manifest_json=excluded.manifest_json`,
		app.ID, app.Name, app.Digest, app.Manifest,
	)
	if err != nil {
		return fmt.Errorf("save application: %w", err)
	}
	return nil
}

func (s *Store) ListApplications(ctx context.Context) ([]Application, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, digest, manifest_json
		FROM applications ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer rows.Close()
	apps := make([]Application, 0)
	for rows.Next() {
		var app Application
		if err := rows.Scan(&app.ID, &app.Name, &app.Digest, &app.Manifest); err != nil {
			return nil, fmt.Errorf("scan application: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applications: %w", err)
	}
	return apps, nil
}

func (s *Store) GetApplication(ctx context.Context, id string) (Application, error) {
	var app Application
	err := s.db.QueryRowContext(ctx, `SELECT id, name, digest, manifest_json
		FROM applications WHERE id = ?`, id).Scan(&app.ID, &app.Name, &app.Digest, &app.Manifest)
	if errors.Is(err, sql.ErrNoRows) {
		return Application{}, fmt.Errorf("application %q not found", id)
	}
	if err != nil {
		return Application{}, fmt.Errorf("get application: %w", err)
	}
	return app, nil
}

func (s *Store) SaveReleasePlan(ctx context.Context, plan ReleasePlanSnapshot) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO release_plans (
		plan_digest, core_digest, application_id, environment, manifest_digest, plan_json, created_at
	) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		plan.Digest, plan.CoreDigest, plan.ApplicationID, plan.Environment, plan.ManifestDigest, plan.PlanJSON)
	if err != nil {
		return fmt.Errorf("save immutable release plan: %w", err)
	}
	return nil
}

func (s *Store) GetReleasePlan(ctx context.Context, digest string) (ReleasePlanSnapshot, error) {
	var plan ReleasePlanSnapshot
	err := s.db.QueryRowContext(ctx, `SELECT plan_digest, core_digest, application_id, environment,
		manifest_digest, plan_json, created_at FROM release_plans WHERE plan_digest = ?`,
		digest).Scan(&plan.Digest, &plan.CoreDigest, &plan.ApplicationID, &plan.Environment,
		&plan.ManifestDigest, &plan.PlanJSON, &plan.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ReleasePlanSnapshot{}, fmt.Errorf("release plan %q not found", digest)
	}
	if err != nil {
		return ReleasePlanSnapshot{}, fmt.Errorf("get release plan: %w", err)
	}
	return plan, nil
}

func (s *Store) PreviousReleasePlan(ctx context.Context, applicationID, environment, coreDigest string) (ReleasePlanSnapshot, error) {
	var plan ReleasePlanSnapshot
	err := s.db.QueryRowContext(ctx, `SELECT plan_digest, core_digest, application_id, environment,
		manifest_digest, plan_json, created_at FROM release_plans
		WHERE application_id = ? AND environment = ? AND core_digest != ?
		ORDER BY created_at DESC, rowid DESC LIMIT 1`,
		applicationID, environment, coreDigest).Scan(&plan.Digest, &plan.CoreDigest, &plan.ApplicationID,
		&plan.Environment, &plan.ManifestDigest, &plan.PlanJSON, &plan.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ReleasePlanSnapshot{}, ErrReleasePlanNotFound
	}
	if err != nil {
		return ReleasePlanSnapshot{}, fmt.Errorf("load latest release plan: %w", err)
	}
	return plan, nil
}
