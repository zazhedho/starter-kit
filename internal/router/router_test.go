package router

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"starter-kit/internal/config"
	"starter-kit/internal/testutil/routertest"
)

func newEngine(t *testing.T, d Deps) *gin.Engine {
	t.Helper()
	engine, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

func TestNewRegistersHealthcheck(t *testing.T) {
	engine := newEngine(t, routertest.NewDeps(t, nil))
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

// TestMiddlewareOrderAndSingleAccessLog checks that the request id precedes the
// logger, CORS precedes the body limit, and each request is logged once.
func TestMiddlewareOrderAndSingleAccessLog(t *testing.T) {
	engine := newEngine(t, routertest.NewDeps(t, func(c *config.Config) { c.HTTP.MaxBodyBytes = 1024 }))
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
	engine := newEngine(t, routertest.NewDeps(t, func(c *config.Config) { c.HTTP.MaxBodyBytes = limit }))

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
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := routertest.NewDeps(t, nil)
			mutate(&d)
			engine, err := New(d)
			if err == nil || engine != nil {
				t.Fatalf("New = %v, %v; want an error and no engine", engine, err)
			}
		})
	}
}

func TestGlobalBodyLimitReturns413(t *testing.T) {
	engine := newEngine(t, routertest.NewDeps(t, func(c *config.Config) { c.HTTP.MaxBodyBytes = 1024 }))
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
		d, mock := routertest.NewDepsWithMock(t, nil)
		mock.ExpectPing()
		rec := get(newEngine(t, d))
		if rec.Code != http.StatusOK || compact(rec) != `{"status":"ok"}` {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("database ping fails", func(t *testing.T) {
		d, mock := routertest.NewDepsWithMock(t, nil)
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
		d, mock := routertest.NewDepsWithMock(t, nil)
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
	engine := newEngine(t, routertest.NewDeps(t, nil))
	if got := routertest.Serve(engine, http.MethodGet, "/api/users"); got != http.StatusUnauthorized {
		t.Fatalf("GET /api/users without token: expected 401, got %d", got)
	}
	if got := routertest.Serve(engine, http.MethodGet, "/api/user/register/status"); got == http.StatusNotFound {
		t.Fatalf("GET /api/user/register/status: route not registered")
	}
}

func TestSessionRoutesAbsentWithoutRedis(t *testing.T) {
	engine := newEngine(t, routertest.NewDeps(t, nil))

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
