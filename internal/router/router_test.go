package router

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	domainmedia "starter-kit/internal/domain/media"
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
	return Deps{Config: cfg, DB: db, SQLDB: sqlDB, Kit: kit, Lifecycle: &Lifecycle{}}, mock
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

func accessLogLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "[Request];") {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestMiddlewareOrderAndSingleAccessLog proves the order through behavior:
// the access-log line carries the request id, so the id was set before the
// logger ran; an over-limit request still carries the CORS headers, so CORS
// runs before the body limit; and each request is logged exactly once.
func TestMiddlewareOrderAndSingleAccessLog(t *testing.T) {
	engine := newEngine(t, newTestDeps(t, func(c *config.Config) { c.HTTP.MaxBodyBytes = 1024 }))
	const requestID = "0197a4b2-6c3e-7d11-9a55-3f1c2b4d5e6f"

	mark := logs.Mark()
	ok := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodGet, "/healthcheck", nil)
	okReq.Header.Set("X-Request-ID", requestID)
	engine.ServeHTTP(ok, okReq)

	big := httptest.NewRecorder()
	bigReq := httptest.NewRequest(http.MethodPost, "/api/user/login", strings.NewReader(strings.Repeat("a", 4096)))
	engine.ServeHTTP(big, bigReq)
	lines := accessLogLines(logs.Since(mark))

	if ok.Header().Get("X-Request-ID") != requestID {
		t.Fatalf("X-Request-ID = %q", ok.Header().Get("X-Request-ID"))
	}
	if len(lines) != 2 {
		t.Fatalf("expected exactly one access-log line per request (2), got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], requestID) {
		t.Errorf("access log does not carry the request id, so the id was not set before the logger: %s", lines[0])
	}
	if big.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit status = %d", big.Code)
	}
	if big.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("over-limit response lacks CORS headers, so the body limit ran before CORS")
	}
	if !strings.Contains(lines[1], "status=413") {
		t.Errorf("the rejected request was not logged with its status: %s", lines[1])
	}
}

func TestGlobalBodyLimitCutsOffUndeclaredLengthBody(t *testing.T) {
	const limit = 1024
	engine := newEngine(t, newTestDeps(t, func(c *config.Config) { c.HTTP.MaxBodyBytes = limit }))

	var read int64
	var readErr error
	engine.POST("/probe", func(c *gin.Context) {
		read, readErr = io.Copy(io.Discard, c.Request.Body)
		if readErr != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusNoContent)
	})

	// io.MultiReader hides the size, so the request has no Content-Length.
	req := httptest.NewRequest(http.MethodPost, "/probe", io.MultiReader(strings.NewReader(strings.Repeat("a", 8*limit))))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if read > limit {
		t.Fatalf("handler read %d bytes, past the %d byte limit", read, limit)
	}
	var tooLarge *http.MaxBytesError
	if !errors.As(readErr, &tooLarge) {
		t.Fatalf("read error = %v, want *http.MaxBytesError", readErr)
	}
	if rec.Code/100 == 2 {
		t.Fatalf("status = %d, want a non-2xx response", rec.Code)
	}
}

func TestNewRejectsIncompleteDeps(t *testing.T) {
	cases := map[string]func(*Deps){
		"nil DB":        func(d *Deps) { d.DB = nil },
		"nil SQLDB":     func(d *Deps) { d.SQLDB = nil },
		"nil Kit":       func(d *Deps) { d.Kit = nil },
		"nil Lifecycle": func(d *Deps) { d.Lifecycle = nil },
		"media enabled without storage": func(d *Deps) {
			d.Config.Media.Enabled = true
			d.Storage = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := newTestDeps(t, nil)
			mutate(&d)
			engine, err := New(d)
			if err == nil || engine != nil {
				t.Fatalf("New = %v, %v; want an error and no engine", engine, err)
			}
		})
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

// fakeStorage is a storage provider that keeps nothing.
type fakeStorage struct{}

func (fakeStorage) UploadFile(_ context.Context, _ multipart.File, _ *multipart.FileHeader, folder string) (domainmedia.StoredFile, error) {
	return domainmedia.StoredFile{ObjectName: folder + "/object.png", URL: "https://files.example.test/" + folder + "/object.png"}, nil
}

func (fakeStorage) DeleteFile(context.Context, string) error { return nil }

func TestMediaRoutesProtection(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		engine := newEngine(t, newTestDeps(t, func(c *config.Config) { c.Media.Enabled = false }))
		if got := serve(engine, http.MethodPost, "/api/media"); got != http.StatusNotFound {
			t.Fatalf("expected 404 when media disabled, got %d", got)
		}
	})

	t.Run("disabled registers nothing even when a provider is passed", func(t *testing.T) {
		d := newTestDeps(t, func(c *config.Config) { c.Media.Enabled = false })
		d.Storage = fakeStorage{}
		for _, route := range newEngine(t, d).Routes() {
			if strings.HasPrefix(route.Path, "/api/media") {
				t.Fatalf("media route %s registered while media is disabled", route.Path)
			}
		}
	})

	t.Run("enabled", func(t *testing.T) {
		d := newTestDeps(t, func(c *config.Config) { c.Media.Enabled = true })
		d.Storage = fakeStorage{}
		engine := newEngine(t, d)
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
	d := newTestDeps(t, func(c *config.Config) {
		c.Media.Enabled = true
		c.Media.MaxFileSizeBytes = 64 << 10
		c.HTTP.MaxBodyBytes = 1 << 20
	})
	d.Storage = fakeStorage{}
	return d
}

func uploadRequest(t *testing.T, d Deps, fileSize int) *http.Request {
	t.Helper()
	token, err := d.Kit.IssueAccessToken("11111111-1111-1111-1111-111111111111", "", "viewer")
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
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload at max size: expected 201, got %d: %s", rec.Code, rec.Body.String())
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
