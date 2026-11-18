package router

import (
	"sort"
	"testing"

	"starter-kit/internal/config"
	"starter-kit/internal/testutil/routertest"
)

// ownRoutesWithMedia and ownRoutesWithoutMedia are written by hand from the
// registrars. A new route must be added here on purpose; an accidental one fails the test.
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
			d := routertest.NewDeps(t, func(cfg *config.Config) { cfg.Media.Enabled = c.media })
			if c.media {
				d.Storage = routertest.FakeStorage{}
			}
			all := routertest.RouteSet(newEngine(t, d))
			kit := routertest.AuthkitRoutes(t, d)

			own := map[string]bool{}
			for route := range all {
				if !kit[route] {
					own[route] = true
				}
			}
			if got := routertest.SortedKeys(own); !equalLists(got, c.want) {
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
