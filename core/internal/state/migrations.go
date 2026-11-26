package state

import (
	"context"
	"database/sql"
	"fmt"
)

const schemaVersion = 6

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin state migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var currentVersion int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if currentVersion > schemaVersion {
		return fmt.Errorf("state schema version %d is newer than supported version %d", currentVersion, schemaVersion)
	}
	if currentVersion == schemaVersion {
		return tx.Commit()
	}

	statements := make([]string, 0, 25)
	if currentVersion < 1 {
		statements = append(statements,
			`CREATE TABLE journal_entries (
				id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL, plan_digest TEXT,
				resource_id TEXT NOT NULL, event_type TEXT NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'denied', 'error')),
				occurred_at TEXT NOT NULL
			)`,
			`CREATE TABLE approvals (
				approval_id TEXT PRIMARY KEY, plan_digest TEXT NOT NULL, actor TEXT NOT NULL,
				target_digest TEXT NOT NULL, scope_digest TEXT NOT NULL, expires_at TEXT NOT NULL,
				consumed_at TEXT, created_at TEXT NOT NULL
			)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (1, CURRENT_TIMESTAMP)`,
		)
	}
	if currentVersion < 2 {
		statements = append(statements,
			`CREATE TABLE hosts (
				id TEXT PRIMARY KEY, environment TEXT NOT NULL, ssh_alias TEXT NOT NULL UNIQUE,
				host TEXT NOT NULL, port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
				user TEXT NOT NULL, identity_file TEXT NOT NULL, known_hosts_file TEXT NOT NULL,
				timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
				created_at TEXT NOT NULL
			)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (2, CURRENT_TIMESTAMP)`,
		)
	}
	if currentVersion < 3 {
		statements = append(statements,
			`CREATE TABLE applications (
				id TEXT PRIMARY KEY, name TEXT NOT NULL, digest TEXT NOT NULL,
				manifest_json TEXT NOT NULL, created_at TEXT NOT NULL
			)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (3, CURRENT_TIMESTAMP)`,
		)
	}
	if currentVersion < 4 {
		statements = append(statements,
			`CREATE TABLE release_plans (
				plan_digest TEXT PRIMARY KEY, core_digest TEXT NOT NULL, application_id TEXT NOT NULL,
				environment TEXT NOT NULL, manifest_digest TEXT NOT NULL,
				plan_json TEXT NOT NULL, created_at TEXT NOT NULL
			)`,
			`CREATE INDEX release_plans_latest ON release_plans(application_id, environment, created_at)`,
			`CREATE TABLE operation_journal (
				event_id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL, plan_digest TEXT NOT NULL,
				actor TEXT NOT NULL, resource_id TEXT NOT NULL, event_type TEXT NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'denied', 'error')),
				metadata_json TEXT NOT NULL, occurred_at TEXT NOT NULL
			)`,
			`CREATE TRIGGER operation_journal_no_update BEFORE UPDATE ON operation_journal
				BEGIN SELECT RAISE(ABORT, 'operation journal is append-only'); END`,
			`CREATE TRIGGER operation_journal_no_delete BEFORE DELETE ON operation_journal
				BEGIN SELECT RAISE(ABORT, 'operation journal is append-only'); END`,
			`CREATE TABLE deployment_locks (
				scope_id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, plan_digest TEXT NOT NULL,
				expires_at TEXT NOT NULL
			)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (4, CURRENT_TIMESTAMP)`,
		)
	}
	if currentVersion < 5 {
		statements = append(statements,
			`CREATE TABLE secret_bindings (
				application_id TEXT NOT NULL, environment TEXT NOT NULL, host_alias TEXT NOT NULL,
				service_name TEXT NOT NULL, secret_name TEXT NOT NULL, reference_digest TEXT NOT NULL,
				version TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('present', 'pending', 'revoked')),
				updated_at TEXT NOT NULL,
				PRIMARY KEY (application_id, environment, host_alias, service_name, secret_name)
			)`,
			`CREATE INDEX secret_bindings_lookup ON secret_bindings(application_id, environment, status)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (5, CURRENT_TIMESTAMP)`,
		)
	}
	if currentVersion < 6 {
		statements = append(statements,
			`CREATE TABLE secret_binding_versions (
				application_id TEXT NOT NULL, environment TEXT NOT NULL, host_alias TEXT NOT NULL,
				service_name TEXT NOT NULL, secret_name TEXT NOT NULL, reference_digest TEXT NOT NULL,
				version TEXT NOT NULL,
				status TEXT NOT NULL CHECK (status IN ('present', 'pending', 'revoked', 'superseded')),
				updated_at TEXT NOT NULL,
				PRIMARY KEY (application_id, environment, host_alias, service_name, secret_name, version)
			)`,
			`INSERT INTO secret_binding_versions (
				application_id, environment, host_alias, service_name, secret_name,
				reference_digest, version, status, updated_at
			) SELECT application_id, environment, host_alias, service_name, secret_name,
				reference_digest, version, status, updated_at FROM secret_bindings`,
			`CREATE INDEX secret_binding_versions_lookup ON secret_binding_versions(application_id, environment, status)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (6, CURRENT_TIMESTAMP)`,
		)
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state migration %d: %w", schemaVersion, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state migration: %w", err)
	}
	return nil
}
