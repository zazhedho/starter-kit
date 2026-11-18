// Package routertest holds the helpers shared by the router tests and every
// router/<module> test: dependencies backed by sqlmock, a database that really
// executes statements, a route set and a request helper.
package routertest

import (
	"context"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/internal/infrastructure/storage"
	"starter-kit/internal/router/module"
)

func newDryRunDB(t *testing.T) (*gorm.DB, *sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DryRun:                 true,
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db, sqlDB, mock
}

// NewDepsWithMock returns complete Deps over a dry-run database (statements are
// built, not sent), with media disabled and no Redis. mutate may adjust the
// config. The mock expects the pings made through Deps.SQLDB.
func NewDepsWithMock(t *testing.T, mutate func(*config.Config)) (module.Deps, sqlmock.Sqlmock) {
	t.Helper()
	db, sqlDB, mock := newDryRunDB(t)
	cfg := config.FromEnv()
	cfg.Media.Enabled = false
	if mutate != nil {
		mutate(&cfg)
	}
	kit, err := authkit.New(authkit.Config{
		DB:      db,
		AppName: "starter-kit-test",
		JWTKey:  "test-jwt-key-that-is-at-least-32-characters-long",
	})
	if err != nil {
		t.Fatalf("authkit.New: %v", err)
	}
	return module.Deps{Config: cfg, DB: db, SQLDB: sqlDB, Kit: kit, Lifecycle: &module.Lifecycle{}}, mock
}

// NewDeps is NewDepsWithMock without the mock.
func NewDeps(t *testing.T, mutate func(*config.Config)) module.Deps {
	t.Helper()
	d, _ := NewDepsWithMock(t, mutate)
	return d
}

// NewExecDB returns a gorm database that really sends statements to sqlmock;
// queries are matched as regular expressions.
func NewExecDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db, mock
}

// RouteSet returns the engine's routes as "METHOD /path" keys.
func RouteSet(engine *gin.Engine) map[string]bool {
	set := map[string]bool{}
	for _, r := range engine.Routes() {
		set[r.Method+" "+r.Path] = true
	}
	return set
}

// SortedKeys returns the keys of set in order.
func SortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// AuthkitRoutes is what authkit mounts under /api on its own, with the same
// dependencies as the service under test (no Redis).
func AuthkitRoutes(t *testing.T, d module.Deps) map[string]bool {
	t.Helper()
	engine := gin.New()
	d.Kit.Mount(engine.Group("/api"))
	return RouteSet(engine)
}

// Mount registers one module alone on an empty engine, under /api as the router
// does, and fails the test if registration returns an error. Use Engine.Routes
// to read what the module mounts.
func Mount(t *testing.T, register func(gin.IRouter, module.Deps) error, d module.Deps) *gin.Engine {
	t.Helper()
	engine := gin.New()
	if err := register(engine.Group("/api"), d); err != nil {
		t.Fatalf("register: %v", err)
	}
	return engine
}

// Serve sends a body-less request to h and returns the status code.
func Serve(h http.Handler, method, path string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
	return rec.Code
}

// FakeStorage is a storage provider that keeps nothing.
type FakeStorage struct{}

var _ storage.Provider = FakeStorage{}

func (FakeStorage) UploadFile(_ context.Context, _ multipart.File, _ *multipart.FileHeader, folder string) (storage.StoredFile, error) {
	return storage.StoredFile{ObjectName: folder + "/object.png", URL: "https://files.example.test/" + folder + "/object.png"}, nil
}

func (FakeStorage) UploadFileFromBytes(_ context.Context, _ []byte, filename, folder, _ string) (storage.StoredFile, error) {
	return storage.StoredFile{ObjectName: folder + "/" + filename, URL: "https://files.example.test/" + folder + "/" + filename}, nil
}

func (FakeStorage) DeleteFile(context.Context, string) error { return nil }

func (FakeStorage) GetFileURL(objectName string) string {
	return "https://files.example.test/" + objectName
}

func (FakeStorage) DownloadFile(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
