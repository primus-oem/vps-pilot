package state

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenRejectsSymlinkDatabase(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.db")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	privateLink := filepath.Join(root, "private", "state.db")
	if err := os.Mkdir(filepath.Dir(privateLink), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, privateLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Open(context.Background(), privateLink); err == nil {
		t.Fatal("expected symlink database to be rejected")
	}
}

func TestOpenRejectsDirectoryDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.db")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("expected directory database to be rejected")
	}
}

func TestOpenRejectsSharedStateDirectoryWithoutChangingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows directory permission bits do not represent ACLs")
	}
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.db")
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("expected shared directory to be rejected")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("Open changed directory permissions to %04o", info.Mode().Perm())
	}
}

func TestHostPersistence(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host := Host{Environment: "staging", SSHAlias: "staging-1", Host: "192.0.2.10", Port: 22, User: "deploy", IdentityFile: "~/.ssh/id_ed25519", KnownHostsFile: "~/.ssh/known_hosts", TimeoutSeconds: 10}
	if err := store.UpsertHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	hosts, err := store.ListHosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].SSHAlias != "staging-1" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestApplicationPersistence(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	app := Application{ID: "sample", Name: "sample", Digest: "sha256:test", Manifest: `{"kind":"Application"}`}
	if err := store.SaveApplication(context.Background(), app); err != nil {
		t.Fatal(err)
	}
	apps, err := store.ListApplications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Name != "sample" {
		t.Fatalf("unexpected applications: %#v", apps)
	}
}

func TestSecretBindingRotationPreservesVersionHistory(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	binding := SecretBinding{
		Application: "sample", Environment: "staging", Host: "staging-1",
		Service: "api", Name: "API_TOKEN", Reference: "sha256:first", Version: "v1", Status: "present",
	}
	if err := store.UpsertSecretBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	binding.Reference = "sha256:second"
	binding.Version = "v2"
	if err := store.UpsertSecretBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetSecretBinding(ctx, "sample", "staging", "staging-1", "api", "API_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != "v2" {
		t.Fatalf("expected v2 current, got %q", current.Version)
	}
	all, err := store.ListSecretBindings(ctx, "sample", "staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Status != "superseded" || all[1].Status != "present" {
		t.Fatalf("unexpected binding history: %#v", all)
	}
	if err := store.RevokeSecretBinding(ctx, "sample", "staging", "staging-1", "api", "API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSecretBinding(ctx, "sample", "staging", "staging-1", "api", "API_TOKEN"); err == nil {
		t.Fatal("revoked binding must not be current")
	}
}

func TestMigrationFromVersionFivePreservesSecretBindings(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
		INSERT INTO schema_migrations(version, applied_at) VALUES (5, CURRENT_TIMESTAMP);
		CREATE TABLE secret_bindings (
			application_id TEXT NOT NULL, environment TEXT NOT NULL, host_alias TEXT NOT NULL,
			service_name TEXT NOT NULL, secret_name TEXT NOT NULL, reference_digest TEXT NOT NULL,
			version TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('present', 'pending', 'revoked')),
			updated_at TEXT NOT NULL,
			PRIMARY KEY (application_id, environment, host_alias, service_name, secret_name)
		);
		INSERT INTO secret_bindings VALUES (
			'sample', 'staging', 'staging-1', 'api', 'API_TOKEN',
			'sha256:legacy', 'v1', 'present', CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bindings, err := store.ListSecretBindings(ctx, "sample", "staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Version != "v1" ||
		bindings[0].Reference != "sha256:legacy" || bindings[0].Status != "present" {
		t.Fatalf("migration did not preserve the existing binding: %#v", bindings)
	}
}

func TestOpenAppliesMigrationAndRestrictsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version int
	if err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("expected schema version %d, got %d", schemaVersion, version)
	}
	var journalTable string
	if err := store.db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'journal_entries'").Scan(&journalTable); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected database mode 0600, got %04o", fileInfo.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("expected directory mode 0700, got %04o", dirInfo.Mode().Perm())
	}
	if err := store.Close(); err != nil && err != sql.ErrConnDone {
		t.Fatal(err)
	}
}
