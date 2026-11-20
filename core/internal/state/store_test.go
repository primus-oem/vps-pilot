package state

import (
	"context"
	"database/sql"
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
