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

// rule describes what one package tree under internal/ must not import.
// internal entries are prefixes relative to the module ("internal/services");
// external entries are import-path prefixes.
type rule struct {
	tree            string
	forbidInternal  []string
	forbidExternal  []string
	externalAllowed []string // when non-nil, only stdlib plus these exact paths may be imported
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
		tree:           "internal/dto",
		forbidInternal: []string{"internal/services", "internal/handlers", "internal/repositories", "internal/infrastructure", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{ginPkg, gormPkg, redisPkg},
		testsToo:       true,
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
		tree:           "internal/config",
		forbidInternal: []string{"internal/"},
	},
	{
		tree:           "internal/router",
		forbidInternal: []string{"internal/app"},
	},
}

func isStdlib(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
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
				if !underTree(dir, r.tree) {
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

// TestImportRule asserts the dependency rule has zero violations.
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

func TestRulesDetectViolations(t *testing.T) {
	var services, domain rule
	for _, r := range rules {
		switch r.tree {
		case "internal/services":
			services = r
		case "internal/domain":
			domain = r
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
	}
	for _, c := range cases {
		if got := violates(c.r, c.ip, c.isTest); got != c.want {
			t.Errorf("%s: violates=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestInterfacesLiveWithTheirConsumer keeps the Go convention: an interface is
// declared by the package that uses it (ports.go), never in a producer-side
// internal/interfaces package, and carries no "Interface" suffix.
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

// moduleAliasPrefix maps a package tree that holds one package per module to
// the import-alias prefix every importer must use: the alias is the prefix
// followed by the module name, for example domainlocation or httpmedia. The
// handler prefix is "http" (the transport) because handlers/<transport>/<module>
// leaves room for other transports.
var moduleAliasPrefix = map[string]string{
	"internal/domain":               "domain",
	"internal/dto":                  "dto",
	"internal/services":             "service",
	"internal/repositories":         "repository",
	"internal/handlers/http":        "http",
	"internal/infrastructure/cache": "cache",
}

// expectedAlias returns the alias the import convention demands for importPath,
// or "" when importPath is not a module package.
func expectedAlias(importPath string) string {
	internal, ok := strings.CutPrefix(importPath, modulePath+"/")
	if !ok {
		return ""
	}
	dir, module := path.Split(internal)
	prefix, ok := moduleAliasPrefix[strings.TrimSuffix(dir, "/")]
	if !ok || module == "" {
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
