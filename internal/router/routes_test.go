package router

import (
	"sort"
	"testing"

	"github.com/gin-gonic/gin"

	"starter-kit/internal/config"
)

func routeSet(engine *gin.Engine) map[string]bool {
	set := map[string]bool{}
	for _, r := range engine.Routes() {
		set[r.Method+" "+r.Path] = true
	}
	return set
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// authkitRoutes is what authkit mounts under /api on its own, with the same
// dependencies as the service under test (no Redis).
func authkitRoutes(t *testing.T, d Deps) map[string]bool {
	t.Helper()
	engine := gin.New()
	d.Kit.Mount(engine.Group("/api"))
	return routeSet(engine)
}

// ownRoutesWithMedia and ownRoutesWithoutMedia are written by hand from the
// registrars: health.go, location.go and media.go. A new route must be added
// here on purpose; an accidental one fails the test.
var (
	ownRoutesWithoutMedia = []string{
		"GET /healthcheck",
		"GET /readyz",
		"GET /api/location/province",
		"GET /api/location/city",
		"GET /api/location/district",
		"GET /api/location/village",
		"POST /api/location/sync",
		"GET /api/location/sync/:id",
	}
	mediaRoutes = []string{
		"POST /api/media",
		"DELETE /api/media/:id",
	}
)

func sorted(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	sort.Strings(all)
	return all
}

func equalLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		media bool
		want  []string
	}{
		{"media enabled, redis absent", true, sorted(ownRoutesWithoutMedia, mediaRoutes)},
		{"media disabled, redis absent", false, sorted(ownRoutesWithoutMedia)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newTestDeps(t, func(cfg *config.Config) { cfg.Media.Enabled = c.media })
			if c.media {
				d.Storage = fakeStorage{}
			}
			all := routeSet(newEngine(t, d))
			kit := authkitRoutes(t, d)

			own := map[string]bool{}
			for route := range all {
				if !kit[route] {
					own[route] = true
				}
			}
			if got := sortedKeys(own); !equalLists(got, c.want) {
				t.Errorf("this service's routes are\n  %v\nwant\n  %v", got, c.want)
			}
			for route := range kit {
				if !all[route] {
					t.Errorf("authkit route %s is missing from the engine", route)
				}
			}
			if len(all) != len(kit)+len(c.want) {
				t.Errorf("engine has %d routes, want authkit's %d plus %d of our own", len(all), len(kit), len(c.want))
			}
		})
	}
}
