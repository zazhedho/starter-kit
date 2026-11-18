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
)

var rules = []rule{
	{
		tree:            "internal/domain",
		forbidInternal:  []string{"internal/dto", "internal/interfaces", "internal/services", "internal/handlers", "internal/repositories", "internal/infrastructure", "internal/cache", "internal/router", "internal/app", "internal/config"},
		externalAllowed: []string{gormPkg}, // gorm.DeletedAt is the single documented exception
		testsToo:        true,
	},
	{
		tree:           "internal/dto",
		forbidInternal: []string{"internal/interfaces", "internal/services", "internal/handlers", "internal/repositories", "internal/infrastructure", "internal/cache", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{ginPkg, gormPkg, redisPkg},
		testsToo:       true,
	},
	{
		tree:           "internal/services",
		forbidInternal: []string{"internal/infrastructure", "internal/repositories", "internal/handlers", "internal/cache", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{ginPkg, gormPkg, redisPkg, minioPkg, gokitPkg},
		testsToo:       true,
	},
	{
		tree:           "internal/handlers",
		forbidInternal: []string{"internal/services", "internal/repositories", "internal/infrastructure", "internal/cache", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{gormPkg, redisPkg, minioPkg},
		testsToo:       true,
	},
	{
		tree:           "internal/repositories",
		forbidInternal: []string{"internal/services", "internal/handlers", "internal/infrastructure", "internal/cache", "internal/router", "internal/app", "internal/config"},
		forbidExternal: []string{ginPkg},
	},
	{
		tree:           "internal/infrastructure",
		forbidInternal: []string{"internal/services", "internal/handlers", "internal/repositories", "internal/router", "internal/app"},
	},
	{
		tree:           "internal/cache", // moves under infrastructure in a later step
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

// knownViolations is the ratchet: edges that exist today and are scheduled for
// removal, keyed "<package dir> -> <import path>". The test fails on any edge
// that is not listed and on any listed edge that no longer exists, so the map
// can only shrink. Each refactoring step deletes its entries.
var knownViolations = map[string]string{
	"internal/services/media -> starter-kit/internal/infrastructure/storage": "step 5: storage port must live in services/media",
	"internal/services/location -> github.com/redis/go-redis/v9":             "step 6: cache port",
	"internal/services/location -> starter-kit/internal/cache/location":      "step 6: cache port",
	"internal/services/location -> github.com/zazhedho/gokit":                "step 9: services stop importing gokit",
	"internal/services/media -> github.com/zazhedho/gokit":                   "step 9: services stop importing gokit",
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

func TestImportRule(t *testing.T) {
	found := collectViolations(t)
	var fresh, stale []string
	for v := range found {
		if _, ok := knownViolations[v]; !ok {
			fresh = append(fresh, v)
		}
	}
	for v := range knownViolations {
		if !found[v] {
			stale = append(stale, v)
		}
	}
	sort.Strings(fresh)
	sort.Strings(stale)
	for _, v := range fresh {
		t.Errorf("new import-rule violation: %s", v)
	}
	for _, v := range stale {
		t.Errorf("knownViolations lists an edge that no longer exists, remove it: %s", v)
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
