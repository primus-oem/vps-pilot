package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite"
)

const schemaVersion = 3

type Host struct {
	ID             string
	Environment    string
	SSHAlias       string
	Host           string
	Port           int
	User           string
	IdentityFile   string
	KnownHostsFile string
	TimeoutSeconds int
}

type Application struct {
	ID        string
	Name      string
	Digest    string
	Manifest  string
	CreatedAt string
}

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
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve state database path: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if info, err := os.Lstat(directory); err != nil {
		return nil, fmt.Errorf("inspect state directory: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state directory must not be a symlink")
	} else if !info.IsDir() {
		return nil, errors.New("state directory must be a directory")
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	directory = resolvedDirectory
	path = filepath.Join(directory, filepath.Base(path))
	if info, err := os.Stat(directory); err != nil {
		return nil, fmt.Errorf("inspect resolved state directory: %w", err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("state directory permissions %04o are too broad; restrict to 0700", info.Mode().Perm())
	}

	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state database must not be a symlink")
	} else if err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("state database must be a regular file")
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

	dsnPath := filepath.ToSlash(path)
	if runtime.GOOS == "windows" && len(dsnPath) >= 2 && dsnPath[1] == ':' {
		dsnPath = "/" + dsnPath
	}
	dsn := (&url.URL{Scheme: "file", Path: dsnPath}).String() + "?mode=rw"
	db, err := sql.Open("sqlite", dsn)
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

func (s *Store) UpsertHost(ctx context.Context, host Host) error {
	if host.ID == "" {
		host.ID = host.SSHAlias
	}
	if host.Port == 0 {
		host.Port = 22
	}
	if host.TimeoutSeconds == 0 {
		host.TimeoutSeconds = 10
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (
		id, environment, ssh_alias, host, port, user, identity_file,
		known_hosts_file, timeout_seconds, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(ssh_alias) DO UPDATE SET
		environment=excluded.environment,
		host=excluded.host,
		port=excluded.port,
		user=excluded.user,
		identity_file=excluded.identity_file,
		known_hosts_file=excluded.known_hosts_file,
		timeout_seconds=excluded.timeout_seconds`,
		host.ID, host.Environment, host.SSHAlias, host.Host, host.Port,
		host.User, host.IdentityFile, host.KnownHostsFile, host.TimeoutSeconds,
	)
	if err != nil {
		return fmt.Errorf("save SSH host: %w", err)
	}
	return nil
}

func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, environment, ssh_alias, host, port, user,
		identity_file, known_hosts_file, timeout_seconds
		FROM hosts ORDER BY ssh_alias`)
	if err != nil {
		return nil, fmt.Errorf("list SSH hosts: %w", err)
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var host Host
		err := rows.Scan(
			&host.ID, &host.Environment, &host.SSHAlias, &host.Host, &host.Port,
			&host.User, &host.IdentityFile, &host.KnownHostsFile, &host.TimeoutSeconds,
		)
		if err != nil {
			return nil, fmt.Errorf("scan SSH host: %w", err)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate SSH hosts: %w", err)
	}
	return hosts, nil
}

func (s *Store) GetHost(ctx context.Context, alias string) (Host, error) {
	var host Host
	err := s.db.QueryRowContext(ctx, `SELECT id, environment, ssh_alias, host, port, user,
		identity_file, known_hosts_file, timeout_seconds
		FROM hosts WHERE ssh_alias = ?`, alias).Scan(
		&host.ID, &host.Environment, &host.SSHAlias, &host.Host, &host.Port,
		&host.User, &host.IdentityFile, &host.KnownHostsFile, &host.TimeoutSeconds,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, fmt.Errorf("SSH host %q not found", alias)
	}
	if err != nil {
		return Host{}, fmt.Errorf("get SSH host: %w", err)
	}
	return host, nil
}

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
	var apps []Application
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

	statements := []string{}
	if currentVersion < 1 {
		statements = append(statements,
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
		)
	}
	if currentVersion < 2 {
		statements = append(statements,
			`CREATE TABLE hosts (
				id TEXT PRIMARY KEY,
				environment TEXT NOT NULL,
				ssh_alias TEXT NOT NULL UNIQUE,
				host TEXT NOT NULL,
				port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
				user TEXT NOT NULL,
				identity_file TEXT NOT NULL,
				known_hosts_file TEXT NOT NULL,
				timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
				created_at TEXT NOT NULL
			)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (2, CURRENT_TIMESTAMP)`,
		)
	}
	if currentVersion < 3 {
		statements = append(statements,
			`CREATE TABLE applications (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				digest TEXT NOT NULL,
				manifest_json TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`INSERT INTO schema_migrations(version, applied_at) VALUES (3, CURRENT_TIMESTAMP)`,
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
