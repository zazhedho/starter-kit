package location

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"

	"github.com/gin-gonic/gin"

	"starter-kit/internal/config"
	"starter-kit/internal/router/module"
	"starter-kit/internal/testutil/routertest"
)

// engineFor mounts the location module alone under /api.
func engineFor(t *testing.T, d module.Deps) *gin.Engine {
	t.Helper()
	return routertest.Mount(t, Register, d)
}

// locationRoutes is every route the module mounts, pinned on purpose: a new
// route must be added here and, if it is protected, to TestLocationRoutesProtection.
var locationRoutes = []string{
	"GET /api/location/city",
	"GET /api/location/district",
	"GET /api/location/province",
	"GET /api/location/sync/:id",
	"GET /api/location/village",
	"POST /api/location/sync",
}

func TestLocationMountsExactlyItsRoutes(t *testing.T) {
	got := routertest.SortedKeys(routertest.RouteSet(engineFor(t, routertest.NewDeps(t, nil))))
	if strings.Join(got, "\n") != strings.Join(locationRoutes, "\n") {
		t.Fatalf("routes are\n  %v\nwant\n  %v", got, locationRoutes)
	}
}

func TestLocationRoutesProtection(t *testing.T) {
	// The public read falls back to the Location Service; keep it off the network.
	engine := engineFor(t, routertest.NewDeps(t, func(c *config.Config) { c.Location.ServiceBaseURL = "http://127.0.0.1:1" }))

	switch got := routertest.Serve(engine, http.MethodGet, "/api/location/province"); got {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		t.Fatalf("GET /api/location/province must be public, got %d", got)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/location/sync"},
		{http.MethodGet, "/api/location/sync/abc"},
	} {
		if got := routertest.Serve(engine, c.method, c.path); got != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: expected 401, got %d", c.method, c.path, got)
		}
	}
}

// The public reads can cost an outbound call, so they are limited per client IP
// when Redis is there. A request without its parent code answers 400 before any
// work, which keeps the test off the database and the network.
func TestPublicReadsAreRateLimitedPerIPWithRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	d := routertest.NewDeps(t, func(c *config.Config) {
		c.Location.RateLimit = 2
		c.Location.RateWindow = time.Minute
	})
	d.Redis = client
	engine := engineFor(t, d)

	for i, want := range []int{http.StatusBadRequest, http.StatusBadRequest, http.StatusTooManyRequests} {
		if got := routertest.Serve(engine, http.MethodGet, "/api/location/city"); got != want {
			t.Fatalf("request %d = %d, want %d", i+1, got, want)
		}
	}
}

// Without Redis the limiter is not built (gokit panics on a zero limit).
func TestPublicReadsAreNotLimitedWithoutRedis(t *testing.T) {
	d := routertest.NewDeps(t, func(c *config.Config) { c.Location.RateLimit, c.Location.RateWindow = 0, 0 })
	d.Redis = nil
	engine := engineFor(t, d)
	for range 5 {
		if got := routertest.Serve(engine, http.MethodGet, "/api/location/city"); got != http.StatusBadRequest {
			t.Fatalf("got %d, want 400 every time", got)
		}
	}
}

// Only the public group is limited: the sync routes keep answering 401.
func TestTheRateLimiterDoesNotCoverTheSyncRoutes(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	d := routertest.NewDeps(t, func(c *config.Config) { c.Location.RateLimit, c.Location.RateWindow = 1, time.Minute })
	d.Redis = client
	engine := engineFor(t, d)
	for range 3 {
		if got := routertest.Serve(engine, http.MethodPost, "/api/location/sync"); got != http.StatusUnauthorized {
			t.Fatalf("POST /api/location/sync = %d, want 401", got)
		}
	}
}

// A Redis outage lets the public reads through, unless LIMITER_FAIL_CLOSED asks
// for the limiter to refuse them.
func TestPublicReadsFollowTheFailClosedSetting(t *testing.T) {
	for _, c := range []struct {
		failClosed bool
		want       int
	}{{false, http.StatusBadRequest}, {true, http.StatusServiceUnavailable}} {
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		d := routertest.NewDeps(t, func(cfg *config.Config) { cfg.Auth.FailClosedLimiters = c.failClosed })
		d.Redis = client
		engine := engineFor(t, d)
		mr.Close()
		if got := routertest.Serve(engine, http.MethodGet, "/api/location/city"); got != c.want {
			t.Fatalf("fail closed = %v: got %d, want %d", c.failClosed, got, c.want)
		}
	}
}

const (
	viewerID = "11111111-1111-1111-1111-111111111111"
	jwtKey   = "test-jwt-key-that-is-at-least-32-characters-long"
)

// signedInDeps is Deps whose database answers what Auth asks for a signed-in
// user with the given role, after the startup recovery.
func signedInDeps(t *testing.T, role string) (module.Deps, sqlmock.Sqlmock) {
	t.Helper()
	d := routertest.NewDeps(t, nil)
	db, mock := routertest.NewExecDB(t)
	kit, err := authkit.New(authkit.Config{DB: db, AppName: "starter-kit-test", JWTKey: jwtKey})
	if err != nil {
		t.Fatalf("authkit.New: %v", err)
	}
	d.DB, d.Kit = db, kit
	mock.ExpectExec(`UPDATE .location_sync_jobs. SET`).WillReturnResult(sqlmock.NewResult(0, 0)) // startup recovery
	mock.ExpectQuery(`FROM "blacklist"`).WillReturnRows(sqlmock.NewRows([]string{"?column?"}))
	mock.ExpectQuery(`FROM "users"`).WillReturnRows(sqlmock.NewRows([]string{"role", "tokens_valid_after"}).AddRow(role, nil))
	return d, mock
}

// A signed-in user without locations:sync is refused by Can, not by the handler.
func TestSyncRoutesAreForbiddenWithoutThePermission(t *testing.T) {
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/location/sync", `{"level":"province"}`},
		{http.MethodGet, "/api/location/sync/22222222-2222-2222-2222-222222222222", ""},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			d, mock := signedInDeps(t, "viewer")
			mock.ExpectQuery(`.*`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
			token, err := d.Kit.IssueAccessToken(viewerID, "", "viewer")
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			engineFor(t, d).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s = %d, want 403: %s", c.method, c.path, rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the permission lookup did not run, so Can did not decide: %v", err)
			}
		})
	}
}
