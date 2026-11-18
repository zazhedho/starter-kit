package app

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	"starter-kit/internal/infrastructure/storage"
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
	if err := a.buildRoutes(); err != nil {
		t.Fatalf("buildRoutes: %v", err)
	}
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
	if err := a.buildRoutes(); err != nil {
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

// TestCloseStopsBackgroundWorkBeforeReleasingConnections pins the shutdown
// order: hooks registered by modules (the location sync job) run while the
// database is still open. sqlmock expects the ping before the close.
func TestCloseStopsBackgroundWorkBeforeReleasingConnections(t *testing.T) {
	mock, _, open := mockDB(t)
	mock.ExpectPing()
	mock.ExpectClose()
	a, err := newApp(context.Background(), testConfig(), deps{openDB: open})
	if err != nil {
		t.Fatal(err)
	}
	hookRan := false
	a.lifecycle.OnClose("test job", func(ctx context.Context) error {
		hookRan = true
		return a.sqlDB.PingContext(ctx) // fails if the database were closed already
	})

	if err := a.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if !hookRan {
		t.Fatal("Close did not run the lifecycle hooks")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// TestCloseWaitsForBackgroundWorkOnlyUntilTheShutdownTimeout: a hook that
// never finishes must not block Close forever; the error is reported and the
// connections are still released.
func TestCloseWaitsForBackgroundWorkOnlyUntilTheShutdownTimeout(t *testing.T) {
	cfg := testConfig()
	cfg.HTTP.ShutdownTimeout = 20 * time.Millisecond
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	a, err := newApp(context.Background(), cfg, deps{openDB: open})
	if err != nil {
		t.Fatal(err)
	}
	a.lifecycle.OnClose("stuck job", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	if err := a.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close = %v, want it to report the timed-out hook", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the database was not closed: %v", err)
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
	if err := a.buildRoutes(); err != nil {
		t.Fatal(err)
	}
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

// TestBrevoConfigMapsEverySMTPField checks that brevoConfig copies each SMTP
// setting into the matching field of authkit's public BrevoConfig, unchanged.
func TestBrevoConfigMapsEverySMTPField(t *testing.T) {
	tests := []struct {
		name string
		smtp config.SMTP
		want authkit.BrevoConfig
	}{
		{
			name: "all fields set",
			smtp: config.SMTP{
				Host: "smtp.example.test", Port: 2525, User: "mailer", Password: "pw", From: "a@example.test",
				OTPSubject: "Code", ResetSubject: "Reset", AppName: "Starter",
			},
			want: authkit.BrevoConfig{
				Host: "smtp.example.test", Port: 2525, User: "mailer", Pass: "pw", From: "a@example.test",
				OTPSubject: "Code", ResetSubject: "Reset", AppName: "Starter",
			},
		},
		{
			name: "optional fields empty",
			smtp: config.SMTP{Host: "smtp.example.test", Password: "pw", From: "a@example.test"},
			want: authkit.BrevoConfig{Host: "smtp.example.test", Pass: "pw", From: "a@example.test"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brevoConfig(tt.smtp); got != tt.want {
				t.Fatalf("brevoConfig(%v)\n got  %+v\n want %+v", tt.smtp, got, tt.want)
			}
		})
	}
}

func TestAuthConfigPassesAMailerOnlyWithRedisAndCompleteSMTP(t *testing.T) {
	full := config.SMTP{
		Host: "smtp.example.test", Port: 2525, User: "mailer", Password: "pw", From: "a@example.test",
		OTPSubject: "Code", ResetSubject: "Reset", AppName: "Starter",
	}
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })

	build := func(smtp config.SMTP, client *redis.Client) authkit.Config {
		cfg := testConfig()
		cfg.SMTP = smtp
		return authConfig(cfg, nil, client)
	}

	t.Run("without redis there is no mailer", func(t *testing.T) {
		got := build(full, nil)
		if got.Mailer != nil || got.Redis != nil {
			t.Fatalf("Mailer = %v, Redis = %v; want neither", got.Mailer, got.Redis)
		}
	})
	t.Run("without smtp there is no mailer", func(t *testing.T) {
		got := build(config.SMTP{}, rdb)
		if got.Mailer != nil || got.Redis != rdb {
			t.Fatalf("Mailer = %v, Redis ok = %t", got.Mailer, got.Redis == rdb)
		}
	})
	t.Run("incomplete smtp has no mailer", func(t *testing.T) {
		partial := full
		partial.Password = ""
		if got := build(partial, rdb); got.Mailer != nil {
			t.Fatalf("Mailer = %v, want nil", got.Mailer)
		}
	})
	t.Run("redis and complete smtp pass a mailer", func(t *testing.T) {
		if got := build(full, rdb); got.Mailer == nil {
			t.Fatal("Mailer = nil, want the Brevo sender")
		}
	})
	t.Run("minimal complete smtp passes a mailer", func(t *testing.T) {
		minimal := config.SMTP{Host: "smtp.example.test", Password: "pw", From: "a@example.test"}
		if got := build(minimal, rdb); got.Mailer == nil {
			t.Fatal("Mailer = nil, want the Brevo sender")
		}
	})
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

type nopStorage struct{ storage.Provider }

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
			initStorage: func(config.Storage) (storage.Provider, error) {
				t.Error("storage was initialized although media is disabled")
				return nil, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		if err := a.buildRoutes(); err != nil {
			t.Fatal(err)
		}
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
			initStorage: func(config.Storage) (storage.Provider, error) { return nopStorage{}, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		if err := a.buildRoutes(); err != nil {
			t.Fatal(err)
		}
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
		initStorage: func(config.Storage) (storage.Provider, error) { return nil, boom },
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
	routesBuilt := false
	err = execute(context.Background(), cfg, deps{
		openDB:   open,
		listener: ln,
		migrate:  func(context.Context) error { migrations++; return nil },
		routes:   func(*gin.Engine) { routesBuilt = true },
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
	if routesBuilt {
		t.Fatal("routes were built in migrate-only mode")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("database was not closed: %v", err)
	}
}

// TestStartupOrder: dependencies are opened, then the schema is migrated, then
// the routes are built (some of them query tables the migration creates), then
// the server runs.
func TestStartupOrder(t *testing.T) {
	cfg := testConfig()
	cfg.Migrate.Run = true
	mock, _, openMock := mockDB(t)
	mock.ExpectClose()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()

	var mu sync.Mutex
	var steps []string
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, step)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = execute(ctx, cfg, deps{
		openDB: func(c config.Database, tz string) (*gorm.DB, *sql.DB, error) {
			record("open")
			return openMock(c, tz)
		},
		listener: inner,
		migrate:  func(context.Context) error { record("migrate"); return nil },
		routes: func(e *gin.Engine) {
			record("routes")
			e.GET("/stop", func(c *gin.Context) { record("serve"); cancel(); c.Status(http.StatusNoContent) })
			go func() {
				for i := 0; i < 100; i++ {
					time.Sleep(20 * time.Millisecond)
					if resp, err := noKeepAlive.Get("http://" + inner.Addr().String() + "/stop"); err == nil {
						_ = resp.Body.Close()
						return
					}
				}
			}()
		},
	})
	if err != nil {
		t.Fatalf("execute = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got, want := strings.Join(steps, ","), "open,migrate,routes,serve"; got != want {
		t.Fatalf("startup order = %s, want %s", got, want)
	}
}

func TestMigrationFailureBuildsNoRoutes(t *testing.T) {
	cfg := testConfig()
	cfg.Migrate.Run = true
	mock, _, open := mockDB(t)
	mock.ExpectClose()
	built := false
	err := execute(context.Background(), cfg, deps{
		openDB:  open,
		migrate: func(context.Context) error { return errors.New("boom") },
		routes:  func(*gin.Engine) { built = true },
	})
	if err == nil {
		t.Fatal("execute succeeded although the migration failed")
	}
	if built {
		t.Fatal("routes were built although the migration failed")
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

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func TestCloseWithoutLifecycleDoesNotPanic(t *testing.T) {
	a := &App{cfg: testConfig()}
	if err := a.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
}

// TestShutdownSharesOneDeadline: the drain and the lifecycle hooks spend the
// same HTTP_SHUTDOWN_TIMEOUT, counted from the moment shutdown starts.
func TestShutdownSharesOneDeadline(t *testing.T) {
	cfg := testConfig()
	cfg.HTTP.ShutdownTimeout = 300 * time.Millisecond
	started := make(chan struct{})
	a, ln := newTestApp(t, cfg, func(e *gin.Engine) {
		e.GET("/stuck", func(c *gin.Context) {
			close(started)
			select {
			case <-time.After(5 * time.Second):
			case <-c.Request.Context().Done():
			}
		})
	})
	deadlines := make(chan time.Time, 1)
	a.lifecycle.OnClose("slow job", func(ctx context.Context) error {
		dl, _ := ctx.Deadline()
		deadlines <- dl
		<-ctx.Done()
		return ctx.Err()
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
	begin := time.Now()
	cancel()

	err := waitServe(t, done, 3*time.Second)
	elapsed := time.Since(begin)
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Serve = %v, want ErrShutdownTimeout", err)
	}
	dl := <-deadlines
	if limit := begin.Add(cfg.HTTP.ShutdownTimeout + cfg.HTTP.ShutdownTimeout/2); dl.After(limit) {
		t.Fatalf("hooks got a deadline %s after shutdown began, want about one timeout (%s)", dl.Sub(begin), cfg.HTTP.ShutdownTimeout)
	}
	if elapsed > cfg.HTTP.ShutdownTimeout+cfg.HTTP.ShutdownTimeout/2 {
		t.Fatalf("shutdown took %s, want about one timeout (%s)", elapsed, cfg.HTTP.ShutdownTimeout)
	}
}
