// Package pgtest gives a test a PostgreSQL database of its own: a throwaway
// schema in the server named by STARTER_KIT_TEST_DATABASE_URL, with authkit's
// tables and this project's migrations applied. Tests that use it are skipped
// when the variable is not set.
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/zazhedho/authkit"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/internal/infrastructure/database"
)

// Open returns a gorm database whose search_path is a new schema with the
// migrations applied; the schema is dropped when the test ends.
func Open(t *testing.T) *gorm.DB {
	t.Helper()
	raw := os.Getenv("STARTER_KIT_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("STARTER_KIT_TEST_DATABASE_URL is not set")
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	schema := "skt_" + hex.EncodeToString(suffix)

	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("STARTER_KIT_TEST_DATABASE_URL is not a valid URL")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	db, sqlDB, err := database.Open(config.Database{
		URL: u.String(), MaxOpenConns: 4, MaxIdleConns: 2,
		ConnMaxLifetime: time.Hour, ConnMaxIdleTime: time.Minute,
	}, "UTC")
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	kit, err := authkit.New(authkit.Config{DB: db, AppName: "starter-kit-test", JWTKey: "test-jwt-key-that-is-at-least-32-characters-long"})
	if err != nil {
		t.Fatalf("authkit.New: %v", err)
	}
	if err := kit.Migrate(ctx); err != nil {
		t.Fatalf("authkit migrations: %v", err)
	}
	for _, file := range MigrationFiles(t, ".up.sql") {
		body, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(string(body)).Error; err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(file), err)
		}
	}
	return db
}

// MigrationFiles lists the project's migration files with the given suffix
// (".up.sql" or ".down.sql") in version order.
func MigrationFiles(t *testing.T, suffix string) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(here), "..", "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), suffix) {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files
}
