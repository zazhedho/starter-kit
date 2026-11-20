package location

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

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
	engine := engineFor(t, routertest.NewDeps(t, nil))

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
