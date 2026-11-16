package router

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/zazhedho/authkit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestNewRoutesRegistersHealthcheck(t *testing.T) {
	routes := NewRoutes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	routes.App.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func newRouterDryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	sqlDB, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DryRun:                 true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db
}

func newTestRoutes(t *testing.T) *Routes {
	t.Helper()
	routes := NewRoutes()
	routes.DB = newRouterDryRunDB(t)
	kit, err := authkit.New(authkit.Config{
		DB:      routes.DB,
		AppName: "starter-kit-test",
		JWTKey:  "test-jwt-key-that-is-at-least-32-characters-long",
	})
	if err != nil {
		t.Fatalf("authkit.New: %v", err)
	}
	routes.Kit = kit
	return routes
}

func serve(routes *Routes, method, path string) int {
	rec := httptest.NewRecorder()
	routes.App.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestMountAuthKitRegistersAuthRoutes(t *testing.T) {
	routes := newTestRoutes(t)
	routes.MountAuthKit()

	if got := serve(routes, http.MethodGet, "/api/users"); got != http.StatusUnauthorized {
		t.Fatalf("GET /api/users without token: expected 401, got %d", got)
	}
	if got := serve(routes, http.MethodGet, "/api/user/register/status"); got == http.StatusNotFound {
		t.Fatalf("GET /api/user/register/status: route not registered")
	}
}

func TestSessionRoutesAbsentWithoutRedis(t *testing.T) {
	routes := newTestRoutes(t)
	routes.MountAuthKit()

	// GET /api/user/sessions itself answers 401 without Redis because the
	// authenticated GET /api/user/:id route matches "sessions", so assert on the
	// registered route table instead of the status code.
	registered := map[string]bool{}
	for _, route := range routes.App.Routes() {
		registered[route.Method+" "+route.Path] = true
	}
	for _, unwanted := range []string{
		"GET /api/user/sessions",
		"DELETE /api/user/session/:session_id",
		"POST /api/user/sessions/revoke-others",
	} {
		if registered[unwanted] {
			t.Fatalf("session route %s must not be registered without Redis", unwanted)
		}
	}
	if !registered["GET /api/user/:id"] {
		t.Fatal("expected the rest of the user routes to be registered")
	}
}

func TestLocationRoutesProtection(t *testing.T) {
	routes := newTestRoutes(t)
	routes.LocationRoutes()

	switch got := serve(routes, http.MethodGet, "/api/location/province"); got {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		t.Fatalf("GET /api/location/province must be public, got %d", got)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/location/sync"},
		{http.MethodGet, "/api/location/sync/abc"},
	} {
		if got := serve(routes, c.method, c.path); got != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: expected 401, got %d", c.method, c.path, got)
		}
	}
}

// useFakeObjectStorage points the storage env at a local server that answers
// the bucket location and existence checks made when the provider starts.
func useFakeObjectStorage(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("STORAGE_PROVIDER", "minio")
	t.Setenv("STORAGE_ENDPOINT", strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("STORAGE_BASE_URL", srv.URL)
	t.Setenv("STORAGE_USE_SSL", "false")
	t.Setenv("STORAGE_BUCKET_NAME", "uploads")
}

func TestMediaRoutesProtection(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		t.Setenv("MEDIA_ENABLED", "false")
		routes := newTestRoutes(t)
		if err := routes.MediaRoutes(); err != nil {
			t.Fatalf("MediaRoutes: %v", err)
		}
		if got := serve(routes, http.MethodPost, "/api/media"); got != http.StatusNotFound {
			t.Fatalf("expected 404 when media disabled, got %d", got)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		t.Setenv("MEDIA_ENABLED", "true")
		useFakeObjectStorage(t)
		routes := newTestRoutes(t)
		if err := routes.MediaRoutes(); err != nil {
			t.Fatalf("MediaRoutes: %v", err)
		}
		if got := serve(routes, http.MethodPost, "/api/media"); got != http.StatusUnauthorized {
			t.Fatalf("POST /api/media without token: expected 401, got %d", got)
		}
		if got := serve(routes, http.MethodDelete, "/api/media/abc"); got != http.StatusUnauthorized {
			t.Fatalf("DELETE /api/media/abc without token: expected 401, got %d", got)
		}
	})
}

func TestNoMovedPackagesRemain(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{
		"utils", "middlewares", "pkg/logger", "pkg/response", "pkg/messages", "pkg/filter",
		"internal/authscope", "internal/services/user", "internal/handlers/http/user", "cmd/module-seed",
	} {
		if _, err := os.Stat(filepath.Join(root, dir)); err == nil {
			t.Errorf("moved package directory still exists: %s", dir)
		}
	}

	banned := []string{`"starter-kit/utils"`, `"starter-kit/middlewares"`, `"starter-kit/pkg/logger"`}
	repo := os.DirFS(root)
	err := fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".superpowers") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "router_test.go") {
			return nil
		}
		data, err := fs.ReadFile(repo, path)
		if err != nil {
			return err
		}
		for _, b := range banned {
			if strings.Contains(string(data), b) {
				t.Errorf("%s still imports %s", path, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
