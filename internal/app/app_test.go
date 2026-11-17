package app

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/pkg/storage"
)

const testJWTKey = "test-jwt-key-that-is-at-least-32-characters-long"

func testConfig() config.Config {
	return config.Config{
		App: config.App{Name: "starter-kit-test", Port: "8080", Timezone: "UTC"},
		HTTP: config.HTTP{
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			ShutdownTimeout:   5 * time.Second,
			MaxBodyBytes:      10 << 20,
		},
		Auth: authkit.Config{AppName: "starter-kit-test", JWTKey: testJWTKey},
	}
}

// mockDB returns a sqlmock-backed gorm database and an opener that hands it
// out and counts how often it was asked for it.
func mockDB(t *testing.T) (sqlmock.Sqlmock, *atomic.Int32, func(config.Database, string) (*gorm.DB, *sql.DB, error)) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DryRun:                 true,
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	var calls atomic.Int32
	open := func(config.Database, string) (*gorm.DB, *sql.DB, error) {
		calls.Add(1)
		return db, sqlDB, nil
	}
	return mock, &calls, open
}

// newTestApp builds an App over a mock database and a listener on a random
// port. The mock expects exactly one Close.
func newTestApp(t *testing.T, cfg config.Config, routes func(*gin.Engine)) (*App, net.Listener) {
	t.Helper()
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	a, err := newApp(context.Background(), cfg, deps{openDB: open, listener: ln, routes: routes})
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, ln
}

type serveResult struct{ err error }

func serveAsync(ctx context.Context, a *App) <-chan serveResult {
	done := make(chan serveResult, 1)
	go func() { done <- serveResult{a.Serve(ctx)} }()
	return done
}

func waitServe(t *testing.T, done <-chan serveResult, within time.Duration) error {
	t.Helper()
	select {
	case r := <-done:
		return r.err
	case <-time.After(within):
		t.Fatal("Serve did not return in time")
		return nil
	}
}

var noKeepAlive = &http.Client{
	Timeout:   5 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noKeepAlive.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestServeStopsCleanlyOnContextCancel(t *testing.T) {
	a, ln := newTestApp(t, testConfig(), nil)
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := serveAsync(ctx, a)

	if status, _ := get(t, "http://"+addr+"/healthcheck"); status != http.StatusOK {
		t.Fatalf("healthcheck status = %d", status)
	}
	cancel()
	if err := waitServe(t, done, 2*time.Second); err != nil {
		t.Fatalf("Serve = %v, want nil", err)
	}
	if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("port is still open after Serve returned")
	}
}

func TestServeFinishesInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	a, ln := newTestApp(t, testConfig(), func(e *gin.Engine) {
		e.GET("/slow", func(c *gin.Context) {
			close(started)
			time.Sleep(300 * time.Millisecond)
			c.String(http.StatusOK, "finished")
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := serveAsync(ctx, a)

	type reply struct {
		status int
		body   string
	}
	got := make(chan reply, 1)
	go func() {
		status, body := get(t, "http://"+ln.Addr().String()+"/slow")
		got <- reply{status, body}
	}()
	<-started
	cancel()

	r := <-got
	if r.status != http.StatusOK || r.body != "finished" {
		t.Fatalf("in-flight reply = %d %q, want 200 \"finished\"", r.status, r.body)
	}
	if err := waitServe(t, done, 2*time.Second); err != nil {
		t.Fatalf("Serve = %v, want nil", err)
	}
}

func TestServeReturnsErrShutdownTimeout(t *testing.T) {
	cfg := testConfig()
	cfg.HTTP.ShutdownTimeout = 50 * time.Millisecond
	started := make(chan struct{})
	a, ln := newTestApp(t, cfg, func(e *gin.Engine) {
		e.GET("/stuck", func(c *gin.Context) {
			close(started)
			select {
			case <-time.After(time.Second):
			case <-c.Request.Context().Done():
			}
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := serveAsync(ctx, a)

	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/stuck", nil)
		if err != nil {
			return
		}
		if resp, err := noKeepAlive.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started
	cancel()

	err := waitServe(t, done, 2*time.Second)
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Serve = %v, want ErrShutdownTimeout", err)
	}
}

func TestServeReturnsListenError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	_, port, _ := net.SplitHostPort(busy.Addr().String())

	cfg := testConfig()
	cfg.App.Port = port
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	a, err := newApp(context.Background(), cfg, deps{openDB: open})
	if err != nil {
		t.Fatal(err)
	}
	// Bind to the exact busy address: ":port" may coexist with a loopback
	// listener on some platforms.
	a.server.Addr = busy.Addr().String()

	if err := a.Serve(context.Background()); err == nil {
		t.Fatal("Serve on a busy port returned nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was not closed after listen failure: %v", err)
	}
}

func TestServerTimeoutsComeFromConfig(t *testing.T) {
	cfg := testConfig()
	cfg.App.Port = "9191"
	cfg.HTTP = config.HTTP{
		ReadHeaderTimeout: 1 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       4 * time.Second,
		ShutdownTimeout:   6 * time.Second,
		MaxBodyBytes:      1 << 20,
	}
	a, _ := newTestApp(t, cfg, nil)
	s := a.server
	if s.Addr != ":9191" {
		t.Errorf("Addr = %q", s.Addr)
	}
	if s.ReadHeaderTimeout != time.Second || s.ReadTimeout != 2*time.Second ||
		s.WriteTimeout != 3*time.Second || s.IdleTimeout != 4*time.Second {
		t.Errorf("timeouts = %v %v %v %v", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout)
	}
	if s.Handler == nil || a.Handler() != s.Handler {
		t.Error("Handler() is not the server handler")
	}
}

// TestCloseIsIdempotent holds a Redis client, because closing a go-redis
// client twice returns an error: without the guard in Close the second call
// would report "redis: client is closed".
func TestCloseIsIdempotent(t *testing.T) {
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	a, err := newApp(context.Background(), testConfig(), deps{openDB: open})
	if err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	a.redis = redis.NewClient(&redis.Options{Addr: mr.Addr()})

	for i := 0; i < 2; i++ {
		if err := a.Close(); err != nil {
			t.Fatalf("Close #%d = %v", i+1, err)
		}
	}
	if err := a.redis.Close(); err == nil {
		t.Fatal("the Redis client was not closed by App.Close")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	return port
}

func TestNewClosesDatabaseWhenRedisUnreachable(t *testing.T) {
	cfg := testConfig()
	cfg.Redis = config.Redis{Host: "127.0.0.1", Port: closedPort(t)}
	mock, calls, open := mockDB(t)
	mock.ExpectClose()

	a, err := newApp(context.Background(), cfg, deps{openDB: open})
	if err == nil {
		_ = a.Close()
		t.Fatal("newApp succeeded although Redis is unreachable")
	}
	if calls.Load() != 1 {
		t.Fatalf("database opened %d times", calls.Load())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was left open: %v", err)
	}
}

func TestNewWithoutRedisDoesNotDial(t *testing.T) {
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	start := time.Now()
	a, err := newApp(context.Background(), testConfig(), deps{openDB: open})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("New took %v", d)
	}
	if a.redis != nil {
		t.Fatal("a Redis client exists although Redis is not configured")
	}
	for _, r := range a.engine.Routes() {
		if strings.Contains(r.Path, "/sessions") {
			t.Fatalf("session route %s mounted without Redis", r.Path)
		}
	}
}

func TestNewFailsOnInvalidAuthConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Auth.JWTKey = "short"
	mock, _, open := mockDB(t)
	mock.ExpectClose()

	a, err := newApp(context.Background(), cfg, deps{openDB: open})
	if err == nil {
		_ = a.Close()
		t.Fatal("newApp accepted a short JWT key")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was left open: %v", err)
	}
}

type nopStorage struct{ storage.StorageProvider }

func TestNewBuildsStorageOnlyWhenMediaIsEnabled(t *testing.T) {
	mediaRoutes := func(a *App) int {
		n := 0
		for _, r := range a.engine.Routes() {
			if strings.HasPrefix(r.Path, "/api/media") {
				n++
			}
		}
		return n
	}

	t.Run("disabled", func(t *testing.T) {
		mock, _, open := mockDB(t)
		mock.ExpectClose()
		a, err := newApp(context.Background(), testConfig(), deps{
			openDB: open,
			initStorage: func(config.Storage) (storage.StorageProvider, error) {
				t.Error("storage was initialized although media is disabled")
				return nil, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		if mediaRoutes(a) != 0 {
			t.Fatal("media routes registered while media is disabled")
		}
	})

	t.Run("enabled", func(t *testing.T) {
		cfg := testConfig()
		cfg.Media.Enabled = true
		cfg.Media.MaxFileSizeBytes = 1 << 20
		mock, _, open := mockDB(t)
		mock.ExpectClose()
		a, err := newApp(context.Background(), cfg, deps{
			openDB:      open,
			initStorage: func(config.Storage) (storage.StorageProvider, error) { return nopStorage{}, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		if mediaRoutes(a) == 0 {
			t.Fatal("media routes missing although media is enabled")
		}
	})
}

func TestNewClosesDatabaseWhenStorageFails(t *testing.T) {
	cfg := testConfig()
	cfg.Media.Enabled = true
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	boom := errors.New("boom")

	a, err := newApp(context.Background(), cfg, deps{
		openDB:      open,
		initStorage: func(config.Storage) (storage.StorageProvider, error) { return nil, boom },
	})
	if !errors.Is(err, boom) {
		if a != nil {
			_ = a.Close()
		}
		t.Fatalf("newApp = %v, want the storage error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was left open: %v", err)
	}
}

func TestNewReportsDatabaseOpenError(t *testing.T) {
	boom := errors.New("boom")
	_, err := newApp(context.Background(), testConfig(), deps{
		openDB: func(config.Database, string) (*gorm.DB, *sql.DB, error) { return nil, nil, boom },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("newApp = %v, want it to wrap the open error", err)
	}
}

func TestNewRejectsUnknownTimezone(t *testing.T) {
	cfg := testConfig()
	cfg.App.Timezone = "Nowhere/Land"
	_, calls, open := mockDB(t)
	if _, err := newApp(context.Background(), cfg, deps{openDB: open}); err == nil {
		t.Fatal("newApp accepted an unknown time zone")
	}
	if calls.Load() != 0 {
		t.Fatal("database was opened before the time zone was checked")
	}
}

// countingListener records Accept calls.
type countingListener struct {
	net.Listener
	accepts atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	return l.Listener.Accept()
}

func TestRunMigrateOnlyDoesNotListen(t *testing.T) {
	cfg := testConfig()
	cfg.Migrate = config.Migrate{Run: true, Only: true}
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &countingListener{Listener: inner}
	defer func() { _ = ln.Close() }()

	var migrations int
	err = execute(context.Background(), cfg, deps{
		openDB:   open,
		listener: ln,
		migrate:  func(context.Context) error { migrations++; return nil },
	})
	if err != nil {
		t.Fatalf("execute = %v", err)
	}
	if migrations != 1 {
		t.Fatalf("migrate hook called %d times", migrations)
	}
	if ln.accepts.Load() != 0 {
		t.Fatal("a listener was used in migrate-only mode")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was not closed: %v", err)
	}
}

func TestExecuteClosesWhenMigrationFails(t *testing.T) {
	cfg := testConfig()
	cfg.Migrate.Run = true
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	boom := errors.New("boom")

	err := execute(context.Background(), cfg, deps{
		openDB:  open,
		migrate: func(context.Context) error { return boom },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("execute = %v, want migration error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was not closed: %v", err)
	}
}

func TestRunReturnsValidationError(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("PORT", "")
	_, calls, open := mockDB(t)

	err := run(context.Background(), nil, deps{openDB: open})
	if err == nil || !strings.Contains(err.Error(), "PORT") {
		t.Fatalf("run = %v, want an error naming PORT", err)
	}
	if calls.Load() != 0 {
		t.Fatal("a database connection was opened before validation passed")
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	_, calls, open := mockDB(t)
	if err := run(context.Background(), []string{"-nope"}, deps{openDB: open}); err == nil {
		t.Fatal("run accepted an unknown flag")
	}
	if calls.Load() != 0 {
		t.Fatal("a database connection was opened")
	}
}

func TestRunHelpReturnsNil(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	_, calls, open := mockDB(t)
	if err := run(context.Background(), []string{"-h"}, deps{openDB: open}); err != nil {
		t.Fatalf("run -h = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("a database connection was opened")
	}
}

func TestMigrateProjectBadSourceDoesNotLeak(t *testing.T) {
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	_, sqlDB, err := open(config.Database{}, "")
	if err != nil {
		t.Fatal(err)
	}
	err = migrateProject(context.Background(), sqlDB, "file://"+filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("migrateProject accepted a missing source directory")
	}
	// The application's pool is still usable, and the caller closes it.
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("pool close: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetServerIPEnv(t *testing.T) {
	t.Setenv("ServerIP", "")
	if err := setServerIPEnv(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ServerIP") == "" {
		t.Fatal("ServerIP was not set")
	}
}

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

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}
