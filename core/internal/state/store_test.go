package state

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

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
