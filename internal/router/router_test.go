package router

import (
	"bytes"
	"database/sql"
	"errors"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	domainuser "github.com/zazhedho/authkit/domain/user"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/internal/config"
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

func newTestDepsWithMock(t *testing.T, mutate func(*config.Config)) (Deps, sqlmock.Sqlmock) {
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
	return Deps{Config: cfg, DB: db, SQLDB: sqlDB, Kit: kit}, mock
}

func newTestDeps(t *testing.T, mutate func(*config.Config)) Deps {
	t.Helper()
	d, _ := newTestDepsWithMock(t, mutate)
	return d
}

func newEngine(t *testing.T, d Deps) *gin.Engine {
	t.Helper()
	engine, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

func serve(engine http.Handler, method, path string) int {
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestNewRegistersHealthcheck(t *testing.T) {
	engine := newEngine(t, newTestDeps(t, nil))
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthcheck", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareOrderAndSingleAccessLog(t *testing.T) {
	engine := newEngine(t, newTestDeps(t, nil))
	if got := len(engine.Handlers); got != 5 {
		t.Fatalf("expected 5 global handlers (CORS, recovery, context id, request logger, body limit), got %d", got)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthcheck", nil))
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID header")
	}
}

func TestGlobalBodyLimitReturns413(t *testing.T) {
	engine := newEngine(t, newTestDeps(t, func(c *config.Config) { c.HTTP.MaxBodyBytes = 1024 }))
	body := `{"email":"` + strings.Repeat("a", 4096) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/user/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	get := func(engine http.Handler) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec
	}
	compact := func(rec *httptest.ResponseRecorder) string { return strings.TrimSpace(rec.Body.String()) }

	t.Run("database ok, redis absent", func(t *testing.T) {
		d, mock := newTestDepsWithMock(t, nil)
		mock.ExpectPing()
		rec := get(newEngine(t, d))
		if rec.Code != http.StatusOK || compact(rec) != `{"status":"ok"}` {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("database ping fails", func(t *testing.T) {
		d, mock := newTestDepsWithMock(t, nil)
		mock.ExpectPing().WillReturnError(errors.New("boom-secret-detail"))
		rec := get(newEngine(t, d))
		if rec.Code != http.StatusServiceUnavailable || compact(rec) != `{"status":"unavailable"}` {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "boom") {
			t.Fatal("body must not reveal the error")
		}
	})

	t.Run("redis checked when present", func(t *testing.T) {
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		d, mock := newTestDepsWithMock(t, nil)
		d.Redis = client
		engine := newEngine(t, d)

		mock.ExpectPing()
		if rec := get(engine); rec.Code != http.StatusOK {
			t.Fatalf("expected 200 with live redis, got %d", rec.Code)
		}
		mr.Close()
		mock.ExpectPing()
		rec := get(engine)
		if rec.Code != http.StatusServiceUnavailable || compact(rec) != `{"status":"unavailable"}` {
			t.Fatalf("expected 503 after redis stops, got %d %s", rec.Code, rec.Body.String())
		}
	})
}

func TestMountAuthKitRegistersAuthRoutes(t *testing.T) {
	engine := newEngine(t, newTestDeps(t, nil))
	if got := serve(engine, http.MethodGet, "/api/users"); got != http.StatusUnauthorized {
		t.Fatalf("GET /api/users without token: expected 401, got %d", got)
	}
	if got := serve(engine, http.MethodGet, "/api/user/register/status"); got == http.StatusNotFound {
		t.Fatalf("GET /api/user/register/status: route not registered")
	}
}

func TestSessionRoutesAbsentWithoutRedis(t *testing.T) {
	engine := newEngine(t, newTestDeps(t, nil))

	// GET /api/user/sessions itself answers 401 without Redis because the
	// authenticated GET /api/user/:id route matches "sessions", so assert on the
	// registered route table instead of the status code.
	registered := map[string]bool{}
	for _, route := range engine.Routes() {
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
	engine := newEngine(t, newTestDeps(t, nil))

	switch got := serve(engine, http.MethodGet, "/api/location/province"); got {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		t.Fatalf("GET /api/location/province must be public, got %d", got)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/location/sync"},
		{http.MethodGet, "/api/location/sync/abc"},
	} {
		if got := serve(engine, c.method, c.path); got != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: expected 401, got %d", c.method, c.path, got)
		}
	}
}

// fakeObjectStorage answers the bucket location and existence checks made when
// the storage provider starts, and returns the storage settings pointing at it.
func fakeObjectStorage(t *testing.T) config.Storage {
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

	return config.Storage{
		Provider:  "minio",
		Endpoint:  strings.TrimPrefix(srv.URL, "http://"),
		BaseURL:   srv.URL,
		Bucket:    "uploads",
		AccessKey: "test-access",
		SecretKey: "test-secret",
		Region:    "auto",
	}
}

func TestMediaRoutesProtection(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		engine := newEngine(t, newTestDeps(t, func(c *config.Config) { c.Media.Enabled = false }))
		if got := serve(engine, http.MethodPost, "/api/media"); got != http.StatusNotFound {
			t.Fatalf("expected 404 when media disabled, got %d", got)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		storage := fakeObjectStorage(t)
		engine := newEngine(t, newTestDeps(t, func(c *config.Config) {
			c.Media.Enabled = true
			c.Storage = storage
		}))
		if got := serve(engine, http.MethodPost, "/api/media"); got != http.StatusUnauthorized {
			t.Fatalf("POST /api/media without token: expected 401, got %d", got)
		}
		if got := serve(engine, http.MethodDelete, "/api/media/abc"); got != http.StatusUnauthorized {
			t.Fatalf("DELETE /api/media/abc without token: expected 401, got %d", got)
		}
	})
}

func mediaDeps(t *testing.T) Deps {
	t.Helper()
	storage := fakeObjectStorage(t)
	return newTestDeps(t, func(c *config.Config) {
		c.Media.Enabled = true
		c.Media.MaxFileSizeBytes = 64 << 10
		c.HTTP.MaxBodyBytes = 1 << 20
		c.Storage = storage
	})
}

func uploadRequest(t *testing.T, d Deps, fileSize int) *http.Request {
	t.Helper()
	token, err := d.Kit.Tokens().Generate(&domainuser.Users{Id: "11111111-1111-1111-1111-111111111111", Role: "viewer"}, "test")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="file"; filename="a.png"`)
	hdr.Set("Content-Type", "image/png")
	part, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, fileSize)
	copy(data, []byte("\x89PNG\r\n\x1a\n"))
	_, _ = part.Write(data)
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/media", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestMediaUploadAtMaxSizeIsAccepted(t *testing.T) {
	d := mediaDeps(t)
	engine := newEngine(t, d)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, uploadRequest(t, d, 64<<10))
	if rec.Code == http.StatusRequestEntityTooLarge || rec.Code == http.StatusUnauthorized {
		t.Fatalf("upload at max size must pass the limits and auth, got %d: %s", rec.Code, rec.Body.String())
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
	calls    int
}

func (r *deadlineRecorder) SetReadDeadline(t time.Time) error {
	r.deadline = t
	r.calls++
	return nil
}

func TestMediaUploadExtendsReadDeadline(t *testing.T) {
	d := mediaDeps(t)
	d.Config.Media.UploadTimeout = 90 * time.Second
	engine := newEngine(t, d)
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	engine.ServeHTTP(rec, uploadRequest(t, d, 1024))
	if rec.calls == 0 {
		t.Fatal("upload handler did not extend the read deadline")
	}
	if diff := time.Until(rec.deadline) - d.Config.Media.UploadTimeout; diff > time.Second || diff < -time.Second {
		t.Fatalf("deadline is %s away from now+UploadTimeout", diff)
	}
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
