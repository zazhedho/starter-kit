package location

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

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
