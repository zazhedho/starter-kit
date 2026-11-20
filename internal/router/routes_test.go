package router

import (
	"os"
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
	registerHealth(probes, d)
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

// orphanProblems compares the router subdirectories with the mounted entries:
// every directory except module (the leaf) and shared must be mounted under its
// own name, and no entry may be called shared.
func orphanProblems(dirs []string, entries []module.Entry) []string {
	mounted := map[string]bool{}
	var problems []string
	for _, e := range entries {
		mounted[e.Name] = true
		if e.Name == "shared" {
			problems = append(problems, "an entry is named shared, a reserved directory name")
		}
	}
	isDir := map[string]bool{}
	for _, d := range dirs {
		isDir[d] = true
		if d == "module" || d == "shared" {
			continue
		}
		if !mounted[d] {
			problems = append(problems, "internal/router/"+d+" is not mounted in modules (add module.Entry{Name: \""+d+"\", ...} to modules.go)")
		}
	}
	for _, e := range entries {
		if e.Name != "shared" && !isDir[e.Name] {
			problems = append(problems, "entry "+e.Name+" has no internal/router/"+e.Name+" directory; Name must equal the directory name")
		}
	}
	return problems
}

func TestOrphanProblemsDetectsViolations(t *testing.T) {
	e := func(names ...string) []module.Entry {
		out := make([]module.Entry, 0, len(names))
		for _, n := range names {
			out = append(out, module.Entry{Name: n})
		}
		return out
	}
	cases := []struct {
		name    string
		dirs    []string
		entries []module.Entry
		want    int
	}{
		{"all mounted", []string{"location", "media", "module"}, e("location", "media"), 0},
		{"shared dir is exempt", []string{"location", "module", "shared"}, e("location"), 0},
		{"orphan directory", []string{"location", "module", "projects"}, e("location"), 1},
		{"entry name differs from directory", []string{"location", "module"}, e("places"), 2},
		{"entry named shared", []string{"location", "module", "shared"}, e("location", "shared"), 1},
	}
	for _, c := range cases {
		if got := orphanProblems(c.dirs, c.entries); len(got) != c.want {
			t.Errorf("%s: %v, want %d problems", c.name, got, c.want)
		}
	}
}

// TestEveryRouterDirectoryIsMounted: a router/<module> package that is not in
// modules would silently serve no routes.
func TestEveryRouterDirectoryIsMounted(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	for _, p := range orphanProblems(dirs, modules) {
		t.Error(p)
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
