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

var ErrReleasePlanNotFound = errors.New("release plan not found")

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

type ReleasePlanSnapshot struct {
	Digest         string
	CoreDigest     string
	ApplicationID  string
	Environment    string
	ManifestDigest string
	PlanJSON       string
	CreatedAt      string
}

type SecretBinding struct {
	Application string
	Environment string
	Host        string
	Service     string
	Name        string
	Reference   string
	Version     string
	Status      string
	UpdatedAt   string
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

func Open(ctx context.Context, databasePath string) (*Store, error) {
	path, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("resolve state database path: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := validateStateDirectory(directory); err != nil {
		return nil, err
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	path = filepath.Join(resolvedDirectory, filepath.Base(path))
	if err := prepareStateFile(path); err != nil {
		return nil, err
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
		_ = db.Close()
		return nil, fmt.Errorf("connect to state database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func validateStateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must not be a symlink")
	}
	if !info.IsDir() {
		return errors.New("state directory must be a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory permissions %04o are too broad; restrict to 0700", info.Mode().Perm())
	}
	return nil
}

func prepareStateFile(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("state database must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return errors.New("state database must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state database: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("create state database: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("restrict state database permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close state database file: %w", err)
	}
	return nil
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
		environment=excluded.environment, host=excluded.host, port=excluded.port,
		user=excluded.user, identity_file=excluded.identity_file,
		known_hosts_file=excluded.known_hosts_file, timeout_seconds=excluded.timeout_seconds`,
		host.ID, host.Environment, host.SSHAlias, host.Host, host.Port,
		host.User, host.IdentityFile, host.KnownHostsFile, host.TimeoutSeconds)
	if err != nil {
		return fmt.Errorf("save SSH host: %w", err)
	}
	return nil
}

func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, environment, ssh_alias, host, port, user,
		identity_file, known_hosts_file, timeout_seconds FROM hosts ORDER BY ssh_alias`)
	if err != nil {
		return nil, fmt.Errorf("list SSH hosts: %w", err)
	}
	defer rows.Close()
	hosts := make([]Host, 0)
	for rows.Next() {
		var host Host
		if err := rows.Scan(&host.ID, &host.Environment, &host.SSHAlias, &host.Host, &host.Port,
			&host.User, &host.IdentityFile, &host.KnownHostsFile, &host.TimeoutSeconds); err != nil {
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
		identity_file, known_hosts_file, timeout_seconds FROM hosts WHERE ssh_alias = ?`, alias).Scan(
		&host.ID, &host.Environment, &host.SSHAlias, &host.Host, &host.Port,
		&host.User, &host.IdentityFile, &host.KnownHostsFile, &host.TimeoutSeconds)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, fmt.Errorf("SSH host %q not found", alias)
	}
	if err != nil {
		return Host{}, fmt.Errorf("get SSH host: %w", err)
	}
	return host, nil
}
