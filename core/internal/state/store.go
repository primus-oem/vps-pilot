package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const schemaVersion = 1

type Store struct {
	db *sql.DB
}

func OpenDefault(ctx context.Context) (*Store, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user config directory: %w", err)
	}
	return Open(ctx, filepath.Join(configDir, "vps-pilot", "state.db"))
}

func Open(ctx context.Context, path string) (*Store, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, fmt.Errorf("restrict state directory permissions: %w", err)
	}

	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state database must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect state database: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("create state database: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, fmt.Errorf("restrict state database permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close state database file: %w", err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to state database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

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
	err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if currentVersion > schemaVersion {
		return fmt.Errorf("state schema version %d is newer than supported version %d", currentVersion, schemaVersion)
	}
	if currentVersion == schemaVersion {
		return tx.Commit()
	}

	statements := []string{
		`CREATE TABLE journal_entries (
			id TEXT PRIMARY KEY,
			correlation_id TEXT NOT NULL,
			plan_digest TEXT,
			resource_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			status TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'denied', 'error')),
			occurred_at TEXT NOT NULL
		)`,
		`CREATE TABLE approvals (
			approval_id TEXT PRIMARY KEY,
			plan_digest TEXT NOT NULL,
			actor TEXT NOT NULL,
			target_digest TEXT NOT NULL,
			scope_digest TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			consumed_at TEXT,
			created_at TEXT NOT NULL
		)`,
		`INSERT INTO schema_migrations(version, applied_at) VALUES (1, CURRENT_TIMESTAMP)`,
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
