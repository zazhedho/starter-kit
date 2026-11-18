// Package architecture holds repository-wide guard tests: the import rule
// between layers and a few hygiene rules. It has no non-test files.
package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "starter-kit"

func repoFiles(t *testing.T, visit func(path string, data []byte)) {
	t.Helper()
	root := filepath.Join("..", "..")
	repo := os.DirFS(root)
	err := fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".superpowers" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(repo, path)
		if err != nil {
			return err
		}
		visit(path, data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoFatalOutsideCmd(t *testing.T) {
	repoFiles(t, func(path string, data []byte) {
		if strings.HasPrefix(path, "cmd"+string(filepath.Separator)) {
			return
		}
		for _, banned := range []string{"log.Fatal", "os.Exit("} {
			if strings.Contains(string(data), banned) {
				t.Errorf("%s uses %s outside cmd/", path, banned)
			}
		}
	})
}

func TestNoPackageLevelConnections(t *testing.T) {
	banned := map[string]bool{"redis.Client": true, "gorm.DB": true, "sql.DB": true}
	repoFiles(t, func(path string, data []byte) {
		file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if vs.Type == nil {
					continue
				}
				expr := vs.Type
				if star, ok := expr.(*ast.StarExpr); ok {
					expr = star.X
				}
				sel, ok := expr.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if pkg, ok := sel.X.(*ast.Ident); ok && banned[pkg.Name+"."+sel.Sel.Name] {
					t.Errorf("%s declares a package-level %s.%s", path, pkg.Name, sel.Sel.Name)
				}
			}
		}
	})
}

// rule lists what one package tree under internal/ must not import; internal
// entries are module-relative prefixes, external entries import-path prefixes.
type rule struct {
	tree           string
	forbidInternal []string
	forbidExternal []string
	// internalAllowed, when non-nil, replaces forbidInternal: only these
	// prefixes of the module's own packages may be imported.
	internalAllowed []string
	externalAllowed []string // when non-nil, only stdlib plus these exact paths may be imported
	// exceptTrees are subtrees of tree the rule does not apply to.
	exceptTrees []string
	// testsToo applies the external bans to _test.go files as well.
	testsToo bool
}

var (
	ginPkg   = "github.com/gin-gonic/gin"
	gormPkg  = "gorm.io/gorm"
	redisPkg = "github.com/redis/go-redis"
	minioPkg = "github.com/minio/minio-go"
	gokitPkg = "github.com/zazhedho/gokit"
	// authkit is the project's auth framework: handlers translate its scope into
	// plain inputs (an Actor, a user id) so services never import it.
	authkitPkg = "github.com/zazhedho/authkit"
)

var rules = []rule{
	{
		tree:            "internal/domain",
		forbidInternal:  []string{"internal/dto", "internal/services", "internal/handlers", "internal/repositories", "internal/infrastructure", "internal/router", "internal/app", "internal/config"},
		externalAllowed: []string{gormPkg}, // gorm.DeletedAt is the single documented exception
		testsToo:        true,
	},
	{
		tree:            "internal/dto",
		internalAllowed: []string{"internal/domain"},
		externalAllowed: []string{}, // standard library only
		testsToo:        true,
	},
	{
		tree:           "internal/services",
		forbidInternal: []string{"internal/infrastructure", "internal/repositories", "internal/handlers", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{ginPkg, gormPkg, redisPkg, minioPkg, gokitPkg, authkitPkg},
		testsToo:       true,
	},
	{
		tree:           "internal/handlers",
		forbidInternal: []string{"internal/services", "internal/repositories", "internal/infrastructure", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{gormPkg, redisPkg, minioPkg},
		testsToo:       true,
	},
	{
		tree:           "internal/repositories",
		forbidInternal: []string{"internal/services", "internal/handlers", "internal/infrastructure", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{ginPkg},
	},
	{
		tree:           "internal/infrastructure",
		forbidInternal: []string{"internal/services", "internal/handlers", "internal/repositories", "internal/router", "internal/app"},
	},
	{
		// Infrastructure owns its own types. The one exception is
		// infrastructure/cache/<module>, which implements that module's port.
		tree:           "internal/infrastructure",
		forbidInternal: []string{"internal/domain"},
		exceptTrees:    []string{"internal/infrastructure/cache"},
	},
	{
		tree:           "internal/config",
		forbidInternal: []string{"internal/"},
	},
	{
		tree:           "internal/router",
		forbidInternal: []string{"internal/app"},
	},
	{
		// The leaf imports no feature module, so a module never reaches another
		// through it.
		tree:           routerLeaf,
		forbidInternal: []string{"internal/domain", "internal/dto", "internal/services", "internal/repositories", "internal/handlers", "internal/infrastructure/cache", "internal/app"},
	},
}

// knownLayers is every top-level directory of internal/. A new layer needs a
// rule in rules above and a line in the README's dependency rule before it is
// added here.
var knownLayers = []string{"app", "architecture", "config", "domain", "dto", "handlers", "infrastructure", "repositories", "router", "services", "testutil"}

// layerProblems compares the directories found under internal/ with knownLayers.
func layerProblems(found []string) []string {
	known := map[string]bool{}
	for _, l := range knownLayers {
		known[l] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range found {
		seen[d] = true
		if !known[d] {
			out = append(out, "internal/"+d+" is an unknown layer: a new layer needs a rule in rules (architecture_test.go) plus a line in the README's dependency rule, then an entry in knownLayers")
		}
	}
	for _, l := range knownLayers {
		if !seen[l] {
			out = append(out, "internal/"+l+" is in knownLayers but missing on disk; remove it from the list (and its rule and README line)")
		}
	}
	return out
}

func TestLayerProblemsDetectsViolations(t *testing.T) {
	all := append([]string{}, knownLayers...)
	cases := []struct {
		name  string
		found []string
		want  int
	}{
		{"exactly the known set", all, 0},
		{"unknown layer", append(append([]string{}, all...), "workers"), 1},
		{"known layer removed", all[1:], 1},
		{"renamed layer", append(append([]string{}, all[1:]...), "apps"), 2},
	}
	for _, c := range cases {
		if got := layerProblems(c.found); len(got) != c.want {
			t.Errorf("%s: %v, want %d problems", c.name, got, c.want)
		}
	}
}

func TestInternalLayersAreKnown(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			found = append(found, e.Name())
		}
	}
	for _, p := range layerProblems(found) {
		t.Error(p)
	}
}

func isStdlib(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}

// applies reports whether r governs the package in dir.
func applies(r rule, dir string) bool {
	if !underTree(dir, r.tree) {
		return false
	}
	for _, e := range r.exceptTrees {
		if underTree(dir, e) {
			return false
		}
	}
	return true
}

func underTree(dir, tree string) bool {
	return dir == tree || strings.HasPrefix(dir, tree+"/")
}

func matchesPrefix(importPath, prefix string) bool {
	return importPath == prefix || strings.HasPrefix(importPath, prefix+"/") || strings.HasPrefix(importPath, prefix+"-") || strings.HasPrefix(importPath, prefix+"@")
}

func collectViolations(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	root := filepath.Join("..", "..")
	err := fs.WalkDir(os.DirFS(root), "internal", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		isTest := strings.HasSuffix(p, "_test.go")
		dir := path.Dir(p)
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, p), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			for _, r := range rules {
				if !applies(r, dir) {
					continue
				}
				if bad := violates(r, ip, isTest); bad {
					found[dir+" -> "+ip] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func violates(r rule, ip string, isTest bool) bool {
	if internal, ok := strings.CutPrefix(ip, modulePath+"/"); ok {
		if isTest {
			return false
		}
		if r.internalAllowed != nil {
			for _, a := range r.internalAllowed {
				if matchesPrefix(internal, a) {
					return false
				}
			}
			return true
		}
		for _, f := range r.forbidInternal {
			if f == "internal/" {
				return true
			}
			if matchesPrefix(internal, f) {
				return true
			}
		}
		return false
	}
	if isTest && !r.testsToo {
		return false
	}
	if isStdlib(ip) {
		return false
	}
	if r.externalAllowed != nil {
		for _, a := range r.externalAllowed {
			if ip == a {
				return false
			}
		}
		return true
	}
	for _, f := range r.forbidExternal {
		if matchesPrefix(ip, f) {
			return true
		}
	}
	return false
}

func TestImportRule(t *testing.T) {
	violations := collectViolations(t)
	found := make([]string, 0, len(violations))
	for v := range violations {
		found = append(found, v)
	}
	sort.Strings(found)
	for _, v := range found {
		t.Errorf("import-rule violation: %s", v)
	}
}

// TestInfrastructureDoesNotImportDomain: infrastructure owns its own types; only
// infrastructure/cache/<module>, which implements a module's port, may name a
// domain type.
func TestInfrastructureDoesNotImportDomain(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		ip   string
		want bool
	}{
		{"storage imports a domain", "internal/infrastructure/storage", "starter-kit/internal/domain/media", true},
		{"database imports a domain", "internal/infrastructure/database", "starter-kit/internal/domain/location", true},
		{"cache of a module imports its domain", "internal/infrastructure/cache/location", "starter-kit/internal/domain/location", false},
		{"storage imports config", "internal/infrastructure/storage", "starter-kit/internal/config", false},
		{"storage imports stdlib", "internal/infrastructure/storage", "context", false},
	}
	for _, c := range cases {
		got := false
		for _, r := range rules {
			if applies(r, c.dir) && violates(r, c.ip, false) {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: violated=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedRespectsLayerRules: a shared package belongs to its tree, so the
// layer rules still apply to it and to importers of it.
func TestSharedRespectsLayerRules(t *testing.T) {
	cases := []struct {
		name, dir, ip string
		want          bool
	}{
		{"dto shared imports domain", "internal/dto/shared", "starter-kit/internal/domain/shared", false},
		{"dto shared imports gin", "internal/dto/shared", "github.com/gin-gonic/gin", true},
		{"dto shared imports a service", "internal/dto/shared", "starter-kit/internal/services/shared", true},
		{"dto module imports services shared", "internal/dto/location", "starter-kit/internal/services/shared", true},
		{"domain module imports dto shared", "internal/domain/location", "starter-kit/internal/dto/shared", true},
		{"service module imports repositories shared", "internal/services/location", "starter-kit/internal/repositories/shared", true},
		{"service module imports dto shared", "internal/services/location", "starter-kit/internal/dto/shared", false},
		{"http handler imports services shared", "internal/handlers/http/location", "starter-kit/internal/services/shared", true},
		{"http handler imports dto shared", "internal/handlers/http/location", "starter-kit/internal/dto/shared", false},
		{"repository imports handlers shared", "internal/repositories/location", "starter-kit/internal/handlers/http/shared", true},
	}
	for _, c := range cases {
		got := false
		for _, r := range rules {
			if applies(r, c.dir) && violates(r, c.ip, false) {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: violated=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestRulesDetectViolations(t *testing.T) {
	var services, domain, dto, leaf rule
	for _, r := range rules {
		switch r.tree {
		case "internal/services":
			services = r
		case "internal/domain":
			domain = r
		case "internal/dto":
			dto = r
		case routerLeaf:
			leaf = r
		}
	}
	cases := []struct {
		name   string
		r      rule
		ip     string
		isTest bool
		want   bool
	}{
		{"service imports gorm", services, "gorm.io/gorm", false, true},
		{"service imports redis", services, "github.com/redis/go-redis/v9", false, true},
		{"service imports infrastructure", services, "starter-kit/internal/infrastructure/storage", false, true},
		{"service imports domain", services, "starter-kit/internal/domain/media", false, false},
		{"service imports gokit", services, "github.com/zazhedho/gokit", false, true},
		{"service imports authkit", services, "github.com/zazhedho/authkit", false, true},
		{"service test imports authkit", services, "github.com/zazhedho/authkit", true, true},
		{"service imports uuid", services, "github.com/google/uuid", false, false},
		{"service imports stdlib", services, "context", false, false},
		{"service test imports gorm", services, "gorm.io/gorm", true, true},
		{"domain imports gorm", domain, "gorm.io/gorm", false, false},
		{"domain imports gin", domain, "github.com/gin-gonic/gin", false, true},
		{"domain imports dto", domain, "starter-kit/internal/dto", false, true},
		{"dto imports domain", dto, "starter-kit/internal/domain/location", false, false},
		{"dto imports stdlib", dto, "time", false, false},
		{"dto imports services", dto, "starter-kit/internal/services/location", false, true},
		{"dto imports another dto", dto, "starter-kit/internal/dto/media", false, true},
		{"dto imports config", dto, "starter-kit/internal/config", false, true},
		{"dto imports uuid", dto, "github.com/google/uuid", false, true},
		{"dto imports gin", dto, "github.com/gin-gonic/gin", false, true},
		{"router leaf imports a service", leaf, "starter-kit/internal/services/media", false, true},
		{"router leaf imports a domain", leaf, "starter-kit/internal/domain/media", false, true},
		{"router leaf imports a handler", leaf, "starter-kit/internal/handlers/http/media", false, true},
		{"router leaf imports the storage abstraction", leaf, "starter-kit/internal/infrastructure/storage", false, false},
		{"router leaf imports config", leaf, "starter-kit/internal/config", false, false},
		{"router leaf imports app", leaf, "starter-kit/internal/app", false, true},
	}
	for _, c := range cases {
		if got := violates(c.r, c.ip, c.isTest); got != c.want {
			t.Errorf("%s: violates=%v, want %v", c.name, got, c.want)
		}
	}
}

// Interfaces are declared by their consumer (ports.go), never in a producer-side
// package, and carry no "Interface" suffix.
func TestInterfacesLiveWithTheirConsumer(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "internal", "interfaces")); err == nil {
		t.Error("internal/interfaces must not exist: declare interfaces in the consuming package (ports.go)")
	}
	repoFiles(t, func(p string, data []byte) {
		file, err := parser.ParseFile(token.NewFileSet(), p, data, 0)
		if err != nil {
			t.Errorf("parse %s: %v", p, err)
			return
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts := spec.(*ast.TypeSpec)
				if _, isIface := ts.Type.(*ast.InterfaceType); isIface && strings.HasSuffix(ts.Name.Name, "Interface") {
					t.Errorf("%s: interface %s has an Interface suffix; name it for the role (Service, Repository, ...)", p, ts.Name.Name)
				}
			}
		}
	})
}

// moduleAliasPrefix maps each per-module tree to its import-alias prefix
// (domainlocation, routermedia). Handler trees derive theirs from the transport
// directory (internal/handlers/<transport>/<module>), so a new transport needs no edit.
var moduleAliasPrefix = map[string]string{
	"internal/domain":               "domain",
	"internal/dto":                  "dto",
	"internal/services":             "service",
	"internal/repositories":         "repository",
	"internal/infrastructure/cache": "cache",
	"internal/router":               "router",
}

const (
	handlersTree = "internal/handlers"
	// routerLeaf is the package every router/<module> imports for Deps and
	// Lifecycle. It is shared infrastructure, not a module: it has no alias prefix
	// and is skipped by the cross-module rule.
	routerLeaf = "internal/router/module"
	// sharedName is the one reserved directory name in a per-module tree
	// (<tree>/shared). It holds helpers every module of the tree may import, is
	// not a business module, and must not import one. Alias: prefix + "shared".
	sharedName = "shared"
)

// moduleTree splits a module-relative path under a per-module tree into alias
// prefix, module and the path below it ("" for the module's own package). ok is
// false outside those trees and for the router leaf; shared comes back as a module.
func moduleTree(p string) (prefix, module, rest string, ok bool) {
	if p == routerLeaf || strings.HasPrefix(p, routerLeaf+"/") {
		return "", "", "", false
	}
	if below, found := strings.CutPrefix(p, handlersTree+"/"); found {
		transport, inside, found := strings.Cut(below, "/")
		if !found || inside == "" {
			return "", "", "", false
		}
		module, rest, _ = strings.Cut(inside, "/")
		return transport, module, rest, true
	}
	for tree, prefix := range moduleAliasPrefix {
		if below, found := strings.CutPrefix(p, tree+"/"); found {
			module, rest, _ = strings.Cut(below, "/")
			return prefix, module, rest, true
		}
	}
	return "", "", "", false
}

// expectedAlias returns the alias the import convention demands for importPath,
// or "" when importPath is not a module package.
func expectedAlias(importPath string) string {
	internal, ok := strings.CutPrefix(importPath, modulePath+"/")
	if !ok {
		return ""
	}
	prefix, module, rest, ok := moduleTree(internal)
	if !ok || rest != "" {
		return ""
	}
	return prefix + module
}

// goFiles calls visit for every .go file (tests included) of the module,
// parsed with imports only.
func goFiles(t *testing.T, visit func(p string, file *ast.File)) {
	t.Helper()
	root := filepath.Join("..", "..")
	err := fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".superpowers" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, p), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		visit(p, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestImportAliasConvention(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			want := expectedAlias(ip)
			if want == "" {
				continue
			}
			got := ""
			if imp.Name != nil {
				got = imp.Name.Name
			}
			if got != want {
				t.Errorf("%s imports %s as %q; the convention is the alias %q", p, ip, got, want)
			}
		}
	})
}

func TestExpectedAlias(t *testing.T) {
	cases := map[string]string{
		"starter-kit/internal/domain/location":               "domainlocation",
		"starter-kit/internal/dto/location":                  "dtolocation",
		"starter-kit/internal/services/media":                "servicemedia",
		"starter-kit/internal/repositories/media":            "repositorymedia",
		"starter-kit/internal/handlers/http/location":        "httplocation",
		"starter-kit/internal/infrastructure/cache/location": "cachelocation",
		"starter-kit/internal/infrastructure/storage":        "",
		"starter-kit/internal/config":                        "",
		"github.com/gin-gonic/gin":                           "",
		"starter-kit/internal/handlers/http":                 "",
		"starter-kit/internal/router/location":               "routerlocation",
		"starter-kit/internal/router/media":                  "routermedia",
		"starter-kit/internal/router/module":                 "", // reserved leaf, imported as module
		"starter-kit/internal/router":                        "",
		"starter-kit/internal/handlers/grpc/location":        "grpclocation",
		"starter-kit/internal/handlers/queue/media":          "queuemedia",
		"starter-kit/internal/handlers/grpc":                 "",
		"starter-kit/internal/dto/shared":                    "dtoshared",
		"starter-kit/internal/handlers/http/shared":          "httpshared",
		"starter-kit/internal/services/shared":               "serviceshared",
		"starter-kit/internal/dto/shared/page":               "",
	}
	for ip, want := range cases {
		if got := expectedAlias(ip); got != want {
			t.Errorf("expectedAlias(%q) = %q, want %q", ip, got, want)
		}
	}
}

// TestPackageNameMatchesDirectory enforces the Go convention that a package is
// named after its directory (an external test package may add _test).
func TestPackageNameMatchesDirectory(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		if strings.HasPrefix(p, "cmd/") {
			return
		}
		want := path.Base(path.Dir(p))
		got := strings.TrimSuffix(file.Name.Name, "_test")
		if got != want {
			t.Errorf("%s declares package %s; the directory name is %s", p, file.Name.Name, want)
		}
	})
}

// moduleOf returns the business module a module-relative path belongs to, or ""
// outside the per-module trees and for a reserved shared package (see moduleTree).
func moduleOf(p string) string {
	_, module, _, _ := moduleTree(p)
	if module == sharedName {
		return ""
	}
	return module
}

// isShared reports whether the module-relative path is a reserved shared package
// (or below one) of a per-module tree.
func isShared(p string) bool {
	_, module, _, ok := moduleTree(p)
	return ok && module == sharedName
}

// crossesModules reports whether a file in directory dir (module-relative)
// imports a package of a different business module. A shared package may be
// imported by any module but may import no business module at all.
func crossesModules(dir, importPath string) bool {
	internal, ok := strings.CutPrefix(importPath, modulePath+"/")
	if !ok {
		return false
	}
	from, to := moduleOf(dir), moduleOf(internal)
	if to == "" {
		return false
	}
	return from != to && (from != "" || isShared(dir))
}

// Modules must not import each other in any layer, tests included; they meet only
// in internal/router and internal/app.
func TestModulesDoNotImportEachOther(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			if crossesModules(path.Dir(p), ip) {
				t.Errorf("%s imports %s: a module must not import another module", p, ip)
			}
		}
	})
}

func TestCrossModuleRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, dir, ip string
		want          bool
	}{
		{"media service imports location service", "internal/services/media", "starter-kit/internal/services/location", true},
		{"media handler imports location domain", "internal/handlers/http/media", "starter-kit/internal/domain/location", true},
		{"location repository imports media dto", "internal/repositories/location", "starter-kit/internal/dto/media", true},
		{"cache of location imports media", "internal/infrastructure/cache/location", "starter-kit/internal/domain/media", true},
		{"media service imports its own domain", "internal/services/media", "starter-kit/internal/domain/media", false},
		{"nested package imports its own module", "internal/services/media/upload", "starter-kit/internal/domain/media", false},
		{"media service imports infrastructure", "internal/services/media", "starter-kit/internal/infrastructure/storage", false},
		{"router imports both modules", "internal/router", "starter-kit/internal/services/location", false},
		{"router/location imports router/module", "internal/router/location", "starter-kit/internal/router/module", false},
		{"router/location imports its own service", "internal/router/location", "starter-kit/internal/services/location", false},
		{"router/location imports router/media", "internal/router/location", "starter-kit/internal/router/media", true},
		{"router/media imports location domain", "internal/router/media", "starter-kit/internal/domain/location", true},
		{"location service imports router/media", "internal/services/location", "starter-kit/internal/router/media", true},
		{"router/module imports a module", "internal/router/module", "starter-kit/internal/services/media", false},
		{"grpc handler imports another module's domain", "internal/handlers/grpc/media", "starter-kit/internal/domain/location", true},
		{"grpc handler imports http handler of the same module", "internal/handlers/grpc/media", "starter-kit/internal/handlers/http/media", false},
		{"grpc handler imports http handler of another module", "internal/handlers/grpc/media", "starter-kit/internal/handlers/http/location", true},
		{"transport root package", "internal/handlers/grpc", "starter-kit/internal/domain/location", false},
		{"media service imports a third party", "internal/services/media", "github.com/google/uuid", false},
		{"http handler imports its tree's shared", "internal/handlers/http/location", "starter-kit/internal/handlers/http/shared", false},
		{"dto imports dto shared", "internal/dto/media", "starter-kit/internal/dto/shared", false},
		{"nested module package imports shared", "internal/services/media/upload", "starter-kit/internal/services/shared", false},
		{"service imports another tree's shared", "internal/services/media", "starter-kit/internal/domain/shared", false},
		{"shared imports a module of its tree", "internal/handlers/http/shared", "starter-kit/internal/handlers/http/location", true},
		{"shared imports a module of another tree", "internal/dto/shared", "starter-kit/internal/domain/location", true},
		{"shared imports a module's own subpackage", "internal/services/shared", "starter-kit/internal/services/media/upload", true},
		{"shared imports another shared", "internal/handlers/http/shared", "starter-kit/internal/dto/shared", false},
		{"shared imports the router leaf", "internal/services/shared", "starter-kit/internal/router/module", false},
		{"shared imports a third party", "internal/handlers/http/shared", "github.com/gin-gonic/gin", false},
		{"nested package under shared imports a module", "internal/dto/shared/page", "starter-kit/internal/domain/media", true},
	}
	for _, c := range cases {
		if got := crossesModules(c.dir, c.ip); got != c.want {
			t.Errorf("%s: crossesModules=%v, want %v", c.name, got, c.want)
		}
	}
}

// constructorTrees are the layers whose exported New* must return a concrete type;
// internal/infrastructure factories may return an interface.
var constructorTrees = []string{"internal/services", "internal/repositories", "internal/handlers"}

func isConstructorName(name string) bool {
	rest, ok := strings.CutPrefix(name, "New")
	return ok && (rest == "" || rest[0] >= 'A' && rest[0] <= 'Z')
}

// constructorViolations reports New* functions that do not return a pointer to a
// struct of the package, optionally followed by an error.
func constructorViolations(files []*ast.File) []string {
	structs := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				if ts := spec.(*ast.TypeSpec); ts != nil {
					_, isStruct := ts.Type.(*ast.StructType)
					structs[ts.Name.Name] = isStruct
				}
			}
		}
	}

	var out []string
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !isConstructorName(fn.Name.Name) {
				continue
			}
			var results []ast.Expr
			if fn.Type.Results != nil {
				for _, field := range fn.Type.Results.List {
					n := max(len(field.Names), 1)
					for range n {
						results = append(results, field.Type)
					}
				}
			}
			if !returnsConcretePointer(results, structs) {
				out = append(out, fn.Name.Name)
			}
		}
	}
	return out
}

func returnsConcretePointer(results []ast.Expr, structs map[string]bool) bool {
	if len(results) == 0 || len(results) > 2 {
		return false
	}
	star, ok := results[0].(*ast.StarExpr)
	if !ok {
		return false
	}
	target, ok := star.X.(*ast.Ident)
	if !ok || !structs[target.Name] {
		return false
	}
	if len(results) == 2 {
		errIdent, ok := results[1].(*ast.Ident)
		return ok && errIdent.Name == "error"
	}
	return true
}

func parseSources(t *testing.T, sources ...string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(sources))
	for _, src := range sources {
		f, err := parser.ParseFile(fset, "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}

// TestConstructorsReturnConcreteTypes: a service, repository or handler
// constructor hands back *Struct (and optionally an error), never an interface.
func TestConstructorsReturnConcreteTypes(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, tree := range constructorTrees {
		err := fs.WalkDir(os.DirFS(root), tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			entries, err := os.ReadDir(filepath.Join(root, p))
			if err != nil {
				return err
			}
			fset := token.NewFileSet()
			var files []*ast.File
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
					continue
				}
				f, err := parser.ParseFile(fset, filepath.Join(root, p, e.Name()), nil, 0)
				if err != nil {
					return err
				}
				files = append(files, f)
			}
			for _, name := range constructorViolations(files) {
				t.Errorf("%s: %s must return a pointer to a struct (and optionally an error), not an interface", p, name)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestConstructorRuleDetectsViolations(t *testing.T) {
	const decls = "package p\ntype Service interface{ Do() }\ntype impl struct{}\ntype Options struct{}\n"
	cases := []struct {
		name string
		fn   string
		want int
	}{
		{"pointer to struct", "func NewService() *impl { return nil }", 0},
		{"pointer to struct and error", "func NewService() (*impl, error) { return nil, nil }", 0},
		{"unexported constructor is ignored", "func newService() Service { return nil }", 0},
		{"not a constructor name", "func Newest() Service { return nil }", 0},
		{"method is ignored", "func (i *impl) NewThing() Service { return nil }", 0},
		{"returns an interface", "func NewService() Service { return nil }", 1},
		{"returns an interface and an error", "func NewService() (Service, error) { return nil, nil }", 1},
		{"returns a struct value", "func NewOptions() Options { return Options{} }", 1},
		{"returns a pointer to an interface", "func NewService() *Service { return nil }", 1},
		{"returns an interface from another package", "func New() io.Reader { return nil }", 1},
		{"returns nothing", "func New() {}", 1},
		{"error comes first", "func NewService() (error, *impl) { return nil, nil }", 1},
	}
	for _, c := range cases {
		files := parseSources(t, decls+c.fn)
		if got := len(constructorViolations(files)); got != c.want {
			t.Errorf("%s: %d violations, want %d", c.name, got, c.want)
		}
	}
}
