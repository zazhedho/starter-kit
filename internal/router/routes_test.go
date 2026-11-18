package router

import (
	"sort"
	"testing"

	"github.com/gin-gonic/gin"

	"starter-kit/internal/config"
	"starter-kit/internal/router/module"
	"starter-kit/internal/testutil/routertest"
)

// routeOwners returns every route the full engine is expected to have, mapped to
// who mounts it: authkit, the probes, or the module registered alone. Nothing is
// listed by hand; each module's own routes_test.go pins its exact routes.
func routeOwners(t *testing.T, d module.Deps) (owners map[string]string, duplicates []string) {
	t.Helper()
	owners = map[string]string{}
	add := func(owner string, routes map[string]bool) {
		for route := range routes {
			if prev, taken := owners[route]; taken {
				duplicates = append(duplicates, route+" ("+prev+" and "+owner+")")
				continue
			}
			owners[route] = owner
		}
	}

	add("authkit", routertest.AuthkitRoutes(t, d))
	probes := gin.New()
	if err := registerHealth(probes, d); err != nil {
		t.Fatalf("registerHealth: %v", err)
	}
	add("health", routertest.RouteSet(probes))
	for _, m := range modules {
		add(m.Name, routertest.RouteSet(routertest.Mount(t, m.Register, d)))
	}
	sort.Strings(duplicates)
	return owners, duplicates
}

// TestRouteTable derives the expected routes from authkit, the probes and each
// mounted module registered alone, so adding a module to modules.go needs no edit here.
func TestRouteTable(t *testing.T) {
	cases := []struct {
		name  string
		media bool
	}{
		{"media enabled, redis absent", true},
		{"media disabled, redis absent", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := routertest.NewDeps(t, func(cfg *config.Config) { cfg.Media.Enabled = c.media })
			if c.media {
				d.Storage = routertest.FakeStorage{}
			}
			all := routertest.RouteSet(newEngine(t, d))
			want, duplicates := routeOwners(t, d)

			for _, dup := range duplicates {
				t.Errorf("route mounted twice: %s", dup)
			}
			for route, owner := range want {
				if !all[route] {
					t.Errorf("%s route %s is missing from the engine", owner, route)
				}
			}
			for route := range all {
				if _, ok := want[route]; !ok {
					t.Errorf("engine route %s is not mounted by authkit, the probes or any module in modules.go", route)
				}
			}
		})
	}
}

func TestModulesAreAlphabeticalAndUnique(t *testing.T) {
	if len(modules) == 0 {
		t.Fatal("modules is empty")
	}
	for i, m := range modules {
		if m.Name == "" || m.Register == nil {
			t.Errorf("modules[%d] needs a Name and a Register", i)
		}
		if i > 0 && modules[i-1].Name >= m.Name {
			t.Errorf("modules must be alphabetical and unique: %q follows %q", m.Name, modules[i-1].Name)
		}
	}
}

func TestRouteOwnersDetectsADuplicateRoute(t *testing.T) {
	d := routertest.NewDeps(t, nil)
	saved := modules
	t.Cleanup(func() { modules = saved })
	dup := module.Entry{Name: "zzz-dup", Register: func(r gin.IRouter, _ module.Deps) error {
		r.GET("/location/province", func(*gin.Context) {})
		return nil
	}}
	modules = append(append([]module.Entry{}, saved...), dup)

	if _, duplicates := routeOwners(t, d); len(duplicates) != 1 {
		t.Fatalf("duplicates = %v, want exactly the one route mounted twice", duplicates)
	}
}
