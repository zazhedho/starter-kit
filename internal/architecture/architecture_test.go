package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
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

func fatalCalls(t *testing.T, name string, src []byte) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	local := fatalImports(file)
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		if pkg, name, ok := packageCall(n); ok {
			switch importPath := local[pkg]; {
			case importPath == "log" && strings.HasPrefix(name, "Fatal"), importPath == "os" && name == "Exit":
				found = append(found, importPath+"."+name)
			}
		}
		return true
	})
	return found
}

func fatalImports(file *ast.File) map[string]string {
	local := map[string]string{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || (importPath != "log" && importPath != "os") {
			continue
		}
		localName := importPath
		if spec.Name != nil {
			localName = spec.Name.Name
		}
		local[localName] = importPath
	}
	return local
}

func packageCall(n ast.Node) (pkg, name string, ok bool) {
	call, isCall := n.(*ast.CallExpr)
	if !isCall {
		return "", "", false
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	id, isIdent := sel.X.(*ast.Ident)
	if !isIdent {
		return "", "", false
	}
	return id.Name, sel.Sel.Name, true
}

func panicCalls(t *testing.T, name string, src []byte) int {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	count := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" && id.Obj == nil {
				count++
			}
		}
		return true
	})
	return count
}

var panicAllowed = map[string]string{
	// Start has no error result and runs from TestMain, where a missing pipe cannot be handled.
	"internal/testutil/logcapture/logcapture.go": "test helper setup",
}

func TestNoPanicOutsideCmd(t *testing.T) {
	repoFiles(t, func(path string, data []byte) {
		if strings.HasPrefix(path, "cmd"+string(filepath.Separator)) || panicAllowed[filepath.ToSlash(path)] != "" {
			return
		}
		if n := panicCalls(t, path, data); n > 0 {
			t.Errorf("%s calls panic %d time(s) outside cmd/; return an error, or list the file in panicAllowed with the reason", path, n)
		}
	})
}

func TestPanicGuardReadsTheSyntaxTree(t *testing.T) {
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"call":      {"package p\nfunc f() { panic(\"x\") }", 1},
		"comment":   {"package p\n// panic(x) is banned\nfunc f() {}", 0},
		"string":    {"package p\nvar s = \"panic(x)\"", 0},
		"method":    {"package p\nfunc f(l T) { l.panic(1) }", 0},
		"shadowed":  {"package p\nfunc f() { panic := func(string) {}; panic(\"x\") }", 0},
		"two calls": {"package p\nfunc f() { panic(1); panic(2) }", 2},
	} {
		if got := panicCalls(t, "x.go", []byte(c.src)); got != c.want {
			t.Errorf("%s: panicCalls = %d, want %d", name, got, c.want)
		}
	}
}

func TestNoFatalOutsideCmd(t *testing.T) {
	repoFiles(t, func(path string, data []byte) {
		if strings.HasPrefix(path, "cmd"+string(filepath.Separator)) {
			return
		}
		for _, call := range fatalCalls(t, path, data) {
			t.Errorf("%s calls %s outside cmd/", path, call)
		}
	})
}

func TestFatalGuardReadsTheSyntaxTree(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"log.Fatal", "package p\nimport \"log\"\nfunc f() { log.Fatal(1) }", 1},
		{"log.Fatalf", "package p\nimport \"log\"\nfunc f() { log.Fatalf(\"x\") }", 1},
		{"os.Exit", "package p\nimport \"os\"\nfunc f() { os.Exit(1) }", 1},
		{"in a comment", "package p\n// log.Fatal and os.Exit( are banned\nfunc f() {}", 0},
		{"in a string", "package p\nvar s = \"os.Exit(1) log.Fatal(x)\"", 0},
		{"logus level", "package p\nimport \"x/logus\"\nfunc f() { logus.Log(logus.LevelFatal, 1) }", 0},
		{"other receiver", "package p\nfunc f(l T) { l.Fatal(1) }", 0},
		{"aliased log", "package p\nimport stdlog \"log\"\nfunc f() { stdlog.Fatalln(1) }", 1},
		{"aliased os", "package p\nimport quit \"os\"\nfunc f() { quit.Exit(1) }", 1},
		{"a local named log", "package p\nimport \"fmt\"\nfunc f(log T) { log.Fatal(fmt.Sprint(1)) }", 0},
		{"another package aliased to os", "package p\nimport os \"example.com/other\"\nfunc f() { os.Exit(1) }", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fatalCalls(t, "x.go", []byte(c.src)); len(got) != c.want {
				t.Fatalf("fatalCalls = %v, want %d", got, c.want)
			}
		})
	}
}

const maxCommentLines = 2

func longComments(t *testing.T, name string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var found []string
	for _, group := range file.Comments {
		lines := 0
		for _, c := range group.List {
			for _, line := range strings.Split(c.Text, "\n") {
				if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//go:") || strings.HasPrefix(trimmed, "//nolint") {
					continue
				}
				lines++
			}
		}
		if lines > maxCommentLines {
			found = append(found, fmt.Sprintf("%s:%d has %d lines", name, fset.Position(group.Pos()).Line, lines))
		}
	}
	return found
}

func TestCommentsAreShort(t *testing.T) {
	repoFiles(t, func(path string, data []byte) {
		for _, problem := range longComments(t, path, data) {
			t.Errorf("comment longer than %d lines: %s", maxCommentLines, problem)
		}
	})
}

func TestCommentGuardCountsBlocks(t *testing.T) {
	three := "package p\n// a\n// b\n// c\nfunc f() {}"
	two := "package p\n// a\n// b\nfunc f() {}"
	split := "package p\n// a\n// b\n\n// c\n// d\nfunc f() {}"
	block := "package p\n/* a\nb\nc */\nfunc f() {}"
	mixed := "package p\n/* a\nb */\n// c\n// d\nfunc f() {}"
	directive := "package p\n// a\n// b\n//nolint:x\nfunc f() {}"
	for name, c := range map[string]struct {
		src  string
		want int
	}{"three lines": {three, 1}, "two lines": {two, 0}, "two blocks": {split, 0}, "block comment": {block, 1}, "block then lines": {mixed, 1}, "directives do not count": {directive, 0}} {
		if got := longComments(t, "x.go", []byte(c.src)); len(got) != c.want {
			t.Errorf("%s: %v, want %d", name, got, c.want)
		}
	}
}

func TestCmdImportsOnlyApp(t *testing.T) {
	root := filepath.Join("..", "..", "cmd")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			if internal, ok := strings.CutPrefix(ip, modulePath+"/"); ok && internal != "internal/app" {
				t.Errorf("%s imports %s; cmd may import only internal/app", p, ip)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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
				if name, bad := bannedConnectionType(spec.(*ast.ValueSpec), banned); bad {
					t.Errorf("%s declares a package-level %s", path, name)
				}
			}
		}
	})
}

func bannedConnectionType(vs *ast.ValueSpec, banned map[string]bool) (string, bool) {
	expr := vs.Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	name := pkg.Name + "." + sel.Sel.Name
	return name, banned[name]
}

type rule struct {
	tree            string
	forbidInternal  []string
	forbidExternal  []string
	internalAllowed []string
	externalAllowed []string
	exceptTrees     []string
	testsToo        bool
}

var (
	ginPkg     = "github.com/gin-gonic/gin"
	gormPkg    = "gorm.io/gorm"
	redisPkg   = "github.com/redis/go-redis"
	minioPkg   = "github.com/minio/minio-go"
	gokitPkg   = "github.com/zazhedho/gokit"
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
		externalAllowed: []string{},
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
		// The one exception is infrastructure/cache/<module>, which implements that module's port.
		tree:           "internal/infrastructure",
		forbidInternal: []string{"internal/domain"},
		exceptTrees:    []string{"internal/infrastructure/cache"},
	},
	{
		tree:           "internal/config",
		forbidInternal: []string{"internal/dto", "internal/services", "internal/handlers", "internal/repositories", "internal/infrastructure", "internal/router", "internal/app"},
	},
	{
		tree:           "internal/router",
		forbidInternal: []string{"internal/app"},
	},
	{
		tree:           "internal/app",
		forbidInternal: []string{"internal/domain", "internal/dto", "internal/services", "internal/repositories", "internal/handlers"},
	},
	{
		tree:           routerLeaf,
		forbidInternal: []string{"internal/domain", "internal/dto", "internal/services", "internal/repositories", "internal/handlers", "internal/infrastructure/cache", "internal/app"},
	},
}

var knownLayers = []string{"app", "architecture", "config", "domain", "dto", "handlers", "infrastructure", "repositories", "router", "services", "testutil"}

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
		keys, err := fileViolations(filepath.Join(root, p), p)
		for _, key := range keys {
			found[key] = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func fileViolations(fsPath, p string) ([]string, error) {
	isTest := strings.HasSuffix(p, "_test.go")
	dir := path.Dir(p)
	file, err := parser.ParseFile(token.NewFileSet(), fsPath, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, imp := range file.Imports {
		ip, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return keys, err
		}
		for _, r := range rules {
			if applies(r, dir) && violates(r, ip, isTest) {
				keys = append(keys, dir+" -> "+ip)
			}
		}
	}
	return keys, nil
}

func violates(r rule, ip string, isTest bool) bool {
	if internal, ok := strings.CutPrefix(ip, modulePath+"/"); ok {
		return !isTest && violatesInternal(r, internal)
	}
	if isStdlib(ip) || (isTest && !r.testsToo) {
		return false
	}
	if r.externalAllowed != nil {
		return !slices.Contains(r.externalAllowed, ip)
	}
	return matchesAny(ip, r.forbidExternal)
}

func violatesInternal(r rule, internal string) bool {
	if r.internalAllowed != nil {
		return !matchesAny(internal, r.internalAllowed)
	}
	return slices.Contains(r.forbidInternal, "internal/") || matchesAny(internal, r.forbidInternal)
}

func matchesAny(s string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(prefix string) bool { return matchesPrefix(s, prefix) })
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
	var services, domain, dto, leaf, app rule
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
		case "internal/app":
			app = r
		}
	}
	cases := []struct {
		name   string
		r      rule
		ip     string
		isTest bool
		want   bool
	}{
		{"app imports a service", app, "starter-kit/internal/services/location", false, true},
		{"app imports a handler", app, "starter-kit/internal/handlers/http/media", false, true},
		{"app imports a repository", app, "starter-kit/internal/repositories/media", false, true},
		{"app imports the router", app, "starter-kit/internal/router", false, false},
		{"app imports config", app, "starter-kit/internal/config", false, false},
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
			for _, name := range interfacesWithSuffix(decl) {
				t.Errorf("%s: interface %s has an Interface suffix; name it for the role (Service, Repository, ...)", p, name)
			}
		}
	})
}

func interfacesWithSuffix(decl ast.Decl) []string {
	gen, ok := decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.TYPE {
		return nil
	}
	var names []string
	for _, spec := range gen.Specs {
		ts := spec.(*ast.TypeSpec)
		if _, isIface := ts.Type.(*ast.InterfaceType); isIface && strings.HasSuffix(ts.Name.Name, "Interface") {
			names = append(names, ts.Name.Name)
		}
	}
	return names
}

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
	routerLeaf   = "internal/router/module"
	sharedName   = "shared"
)

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

func moduleOf(p string) string {
	_, module, _, _ := moduleTree(p)
	if module == sharedName {
		return ""
	}
	return module
}

func isShared(p string) bool {
	_, module, _, ok := moduleTree(p)
	return ok && module == sharedName
}

var sharedEntityTrees = []string{"internal/domain", "internal/dto"}

func underAny(p string, trees []string) bool {
	for _, tree := range trees {
		if underTree(p, tree) {
			return true
		}
	}
	return false
}

func crossesModules(dir, importPath string) bool {
	internal, ok := strings.CutPrefix(importPath, modulePath+"/")
	if !ok {
		return false
	}
	from, to := moduleOf(dir), moduleOf(internal)
	if to == "" || from == to || (from == "" && !isShared(dir)) {
		return false
	}
	higherLayer := from != "" && !underAny(dir, sharedEntityTrees)
	return !higherLayer || !underAny(internal, sharedEntityTrees)
}

func TestModulesDoNotImportEachOther(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			if crossesModules(path.Dir(p), ip) {
				t.Errorf("%s imports %s: a module may only import another module's domain or dto, from a higher layer", p, ip)
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
		{"media handler imports location domain", "internal/handlers/http/media", "starter-kit/internal/domain/location", false},
		{"location repository imports media dto", "internal/repositories/location", "starter-kit/internal/dto/media", false},
		{"cache of location imports media domain", "internal/infrastructure/cache/location", "starter-kit/internal/domain/media", false},
		{"media service imports location domain", "internal/services/media", "starter-kit/internal/domain/location", false},
		{"media service imports location dto", "internal/services/media", "starter-kit/internal/dto/location", false},
		{"media domain imports location domain", "internal/domain/media", "starter-kit/internal/domain/location", true},
		{"media dto imports location dto", "internal/dto/media", "starter-kit/internal/dto/location", true},
		{"media domain imports location dto", "internal/domain/media", "starter-kit/internal/dto/location", true},
		{"media dto imports location domain", "internal/dto/media", "starter-kit/internal/domain/location", true},
		{"media handler imports location handler", "internal/handlers/http/media", "starter-kit/internal/handlers/http/location", true},
		{"media repository imports location repository", "internal/repositories/media", "starter-kit/internal/repositories/location", true},
		{"media handler imports location service", "internal/handlers/http/media", "starter-kit/internal/services/location", true},
		{"media service imports location cache", "internal/services/media", "starter-kit/internal/infrastructure/cache/location", true},
		{"media service imports a location domain subpackage", "internal/services/media", "starter-kit/internal/domain/location/sub", false},
		{"services shared imports a module domain", "internal/services/shared", "starter-kit/internal/domain/location", true},
		{"media service imports its own domain", "internal/services/media", "starter-kit/internal/domain/media", false},
		{"nested package imports its own module", "internal/services/media/upload", "starter-kit/internal/domain/media", false},
		{"media service imports infrastructure", "internal/services/media", "starter-kit/internal/infrastructure/storage", false},
		{"router imports both modules", "internal/router", "starter-kit/internal/services/location", false},
		{"router/location imports router/module", "internal/router/location", "starter-kit/internal/router/module", false},
		{"router/location imports its own service", "internal/router/location", "starter-kit/internal/services/location", false},
		{"router/location imports router/media", "internal/router/location", "starter-kit/internal/router/media", true},
		{"router/media imports location domain", "internal/router/media", "starter-kit/internal/domain/location", false},
		{"router/media imports location service", "internal/router/media", "starter-kit/internal/services/location", true},
		{"location service imports router/media", "internal/services/location", "starter-kit/internal/router/media", true},
		{"router/module imports a module", "internal/router/module", "starter-kit/internal/services/media", false},
		{"grpc handler imports another module's domain", "internal/handlers/grpc/media", "starter-kit/internal/domain/location", false},
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

var constructorTrees = []string{"internal/services", "internal/repositories", "internal/handlers"}

func isConstructorName(name string) bool {
	rest, ok := strings.CutPrefix(name, "New")
	return ok && (rest == "" || rest[0] >= 'A' && rest[0] <= 'Z')
}

func structNames(files []*ast.File) map[string]bool {
	structs := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts := spec.(*ast.TypeSpec)
				_, isStruct := ts.Type.(*ast.StructType)
				structs[ts.Name.Name] = isStruct
			}
		}
	}
	return structs
}

func resultTypes(fn *ast.FuncDecl) []ast.Expr {
	var results []ast.Expr
	if fn.Type.Results == nil {
		return results
	}
	for _, field := range fn.Type.Results.List {
		for range max(len(field.Names), 1) {
			results = append(results, field.Type)
		}
	}
	return results
}

func exportedConstructor(decl ast.Decl) (*ast.FuncDecl, bool) {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Recv != nil || !fn.Name.IsExported() || !isConstructorName(fn.Name.Name) {
		return nil, false
	}
	return fn, true
}

func constructorViolations(files []*ast.File) []string {
	structs := structNames(files)
	var out []string
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := exportedConstructor(decl); ok && !returnsConcretePointer(resultTypes(fn), structs) {
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

func parseNonTestFiles(dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func TestConstructorsReturnConcreteTypes(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, tree := range constructorTrees {
		err := fs.WalkDir(os.DirFS(root), tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			files, err := parseNonTestFiles(filepath.Join(root, p))
			if err != nil {
				return err
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

var restatingStopwords = map[string]bool{
	"returns": true, "return": true, "is": true, "a": true, "an": true, "the": true, "of": true, "for": true,
	"to": true, "over": true, "with": true, "from": true, "and": true, "wraps": true, "creates": true,
	"builds": true, "in": true, "on": true, "by": true, "as": true, "it": true, "that": true, "holds": true,
	"new": true, "makes": true, "gets": true, "get": true, "sets": true, "set": true,
}

func words(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

func restatingComments(t *testing.T, name string, src []byte) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var found []string
	check := func(declName string, doc *ast.CommentGroup, known map[string]bool) {
		if text, ok := restatingDoc(declName, doc, known); ok {
			found = append(found, fmt.Sprintf("%s: %s", declName, text))
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			check(d.Name.Name, d.Doc, funcWords(d))
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					check(ts.Name.Name, typeDoc(d, ts), addWords(map[string]bool{}, ts.Name.Name))
				}
			}
		}
	}
	return found
}

func restatingDoc(declName string, doc *ast.CommentGroup, known map[string]bool) (string, bool) {
	if doc == nil || len(doc.List) != 1 || strings.HasPrefix(doc.List[0].Text, "/*") {
		return "", false
	}
	text := strings.TrimSpace(strings.TrimPrefix(doc.List[0].Text, "//"))
	if !strings.HasPrefix(text, declName+" ") {
		return "", false
	}
	for _, w := range words(text) {
		if !known[w] && !restatingStopwords[w] {
			return "", false
		}
	}
	return text, true
}

func addWords(known map[string]bool, texts ...string) map[string]bool {
	for _, text := range texts {
		for _, w := range words(text) {
			known[w] = true
		}
	}
	return known
}

func funcWords(d *ast.FuncDecl) map[string]bool {
	known := addWords(map[string]bool{}, d.Name.Name)
	for _, list := range []*ast.FieldList{d.Recv, d.Type.Params, d.Type.Results} {
		if list == nil {
			continue
		}
		for _, f := range list.List {
			addWords(known, types.ExprString(f.Type))
			for _, n := range f.Names {
				addWords(known, n.Name)
			}
		}
	}
	return known
}

func typeDoc(d *ast.GenDecl, ts *ast.TypeSpec) *ast.CommentGroup {
	if ts.Doc == nil && len(d.Specs) == 1 {
		return d.Doc
	}
	return ts.Doc
}

func TestCommentsDoNotRestateTheDeclaration(t *testing.T) {
	repoFiles(t, func(path string, data []byte) {
		for _, problem := range restatingComments(t, path, data) {
			t.Errorf("%s restates its declaration: %s", path, problem)
		}
	})
}

func TestRestatingCommentGuard(t *testing.T) {
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"restates a constructor": {"package p\n// NewRepository returns a Repository over db.\nfunc NewRepository(db *gorm.DB) *Repository { return nil }", 1},
		"restates a wrapper":     {"package p\n// New wraps client.\nfunc New(client *redis.Client) *Cache { return nil }", 1},
		"restates a type":        {"package p\n// Handler is the handler.\ntype Handler struct{}", 1},
		"says why":               {"package p\n// NewRepository returns a Repository over db; it never opens a connection.\nfunc NewRepository(db *gorm.DB) *Repository { return nil }", 0},
		"several lines":          {"package p\n// Handler is the handler.\n// It also logs.\ntype Handler struct{}", 0},
		"another subject":        {"package p\n// Close stops the job.\nfunc Close() {}", 0},
	} {
		if got := restatingComments(t, "x.go", []byte(c.src)); len(got) != c.want {
			t.Errorf("%s: %v, want %d", name, got, c.want)
		}
	}
}
