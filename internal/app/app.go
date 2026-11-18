// Package app owns the service lifecycle: New, Migrate, Serve, Close.
// Failures are returned as errors; only cmd/api exits the process.
package app

// To add a config field, a dependency or a module, see the README sections
// "Runtime Configuration" and "Adding a module".

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/logus"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/internal/infrastructure/database"
	"starter-kit/internal/infrastructure/storage"
	"starter-kit/internal/router"
	"starter-kit/internal/router/module"
)

// App holds the open connections and the HTTP server of one running service.
type App struct {
	cfg    config.Config
	db     *gorm.DB
	sqlDB  *sql.DB
	redis  *redis.Client
	kit    *authkit.Kit
	engine *gin.Engine  // nil until buildRoutes has run
	server *http.Server // nil until buildRoutes has run

	storage storage.Provider // nil unless media is enabled

	// lifecycle holds the shutdown hooks of background work the modules start
	// (the location sync job). Close runs it before releasing Redis and the
	// database, so that work can still use them while it finishes.
	lifecycle *module.Lifecycle
	routes    func(*gin.Engine) // extra routes added by tests

	listener net.Listener                    // nil: Serve listens on server.Addr
	migrate  func(ctx context.Context) error // replaces the real migrations in tests

	closeMu sync.Mutex
	closed  bool
}

// deps lets tests replace the pieces that need a real database or a fixed
// port. The zero value is production behavior.
type deps struct {
	openDB      func(config.Database, string) (*gorm.DB, *sql.DB, error)
	listener    net.Listener
	initStorage func(config.Storage) (storage.Provider, error)
	routes      func(*gin.Engine)
	migrate     func(ctx context.Context) error
}

// Run loads configuration, builds the App, migrates when asked, and serves until
// ctx is canceled. args exclude the program name.
func Run(ctx context.Context, args []string) error {
	return run(ctx, args, deps{})
}

func run(ctx context.Context, args []string, d deps) error {
	if err := setServerIPEnv(); err != nil {
		return err
	}

	cfg, err := loadConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil // usage has been printed
	}
	if err != nil {
		return err
	}
	logus.WriteLog(logus.LogLevelInfo, "APP: "+cfg.App.Name+"; PORT: "+cfg.App.Port)

	return execute(ctx, cfg, d)
}

// loadConfig applies .env (never overriding the environment), Consul or file,
// environment, flags, then validation, in that order.
func loadConfig(args []string) (config.Config, error) {
	if err := config.LoadDotEnv(".env"); err != nil {
		return config.Config{}, fmt.Errorf("load environment: %w", err)
	}
	config.LoadRemote()

	cfg := config.FromEnv()
	if err := applyFlags(&cfg, args); err != nil {
		return config.Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// applyFlags parses args on a private FlagSet, so Run can be called more than
// once and from tests. Flag defaults are the values already in cfg.
func applyFlags(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	fs.StringVar(&cfg.App.Port, "port", cfg.App.Port, "port of the service")
	fs.StringVar(&cfg.App.Name, "appname", cfg.App.Name, "service name")
	fs.BoolVar(&cfg.Migrate.Run, "migrate", cfg.Migrate.Run, "run database migration before starting server")
	fs.BoolVar(&cfg.Migrate.Only, "migrate-only", false, "run database migration, then exit without serving")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// execute builds the App from a validated config and runs the requested mode.
// The App is closed on every path.
func execute(ctx context.Context, cfg config.Config, d deps) (err error) {
	a, err := newApp(ctx, cfg, d)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if cfg.Migrate.Run || cfg.Migrate.Only {
		if err := a.Migrate(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if cfg.Migrate.Only {
		logus.WriteLog(logus.LogLevelInfo, "Migration finished; not serving (migrate-only)")
		return nil
	}
	// Routes come after the migration: some modules query their tables when
	// they are registered.
	if err := a.buildRoutes(); err != nil {
		return err
	}
	return a.Serve(ctx)
}

// New opens the connections and builds authkit, but no routes (Serve does),
// so callers can Migrate first. On failure everything opened is closed.
func New(ctx context.Context, cfg config.Config) (*App, error) {
	return newApp(ctx, cfg, deps{})
}

func newApp(ctx context.Context, cfg config.Config, d deps) (*App, error) {
	loc, err := time.LoadLocation(cfg.App.Timezone)
	if err != nil {
		return nil, fmt.Errorf("load time zone: %w", err)
	}
	// A process-wide setting: write it only when it changes, so a second App
	// in the same process (tests) does not race with readers of time.Local.
	if loc.String() != time.Local.String() {
		time.Local = loc
	}

	openDB := d.openDB
	if openDB == nil {
		openDB = database.Open
	}

	a := &App{cfg: cfg, listener: d.listener, migrate: d.migrate, routes: d.routes, lifecycle: &module.Lifecycle{}}
	if a.db, a.sqlDB, err = openDB(cfg.Database, cfg.App.Timezone); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// From here on, a failure must release what is open.
	fail := func(err error) (*App, error) {
		if closeErr := a.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}

	// Redis is optional: not configured means no connection attempt, and
	// configured but unreachable is a startup failure.
	if cfg.Redis.Configured() {
		if a.redis, err = database.OpenRedis(ctx, cfg.Redis); err != nil {
			return fail(fmt.Errorf("open redis: %w", err))
		}
		logus.WriteLog(logus.LogLevelInfo, "Redis initialized, session management enabled")
	}

	// The storage provider exists only when media is enabled; a failure to
	// start it is a startup failure, not a missing route.
	if cfg.Media.Enabled {
		initStorage := d.initStorage
		if initStorage == nil {
			initStorage = storage.InitStorage
		}
		if a.storage, err = initStorage(cfg.Storage); err != nil {
			return fail(fmt.Errorf("initialize storage: %w", err))
		}
	}

	if a.kit, err = authkit.New(authConfig(cfg, a.db, a.redis)); err != nil {
		return fail(fmt.Errorf("initialize authkit: %w", err))
	}
	return a, nil
}

// authConfig adds the open connections to authkit's config. The mailer is
// set only with Redis and full SMTP settings; otherwise the service runs without it.
func authConfig(cfg config.Config, db *gorm.DB, rdb *redis.Client) authkit.Config {
	authCfg := cfg.Auth
	authCfg.DB = db
	if rdb == nil {
		return authCfg
	}
	authCfg.Redis = rdb
	if !cfg.SMTP.Configured() {
		return authCfg
	}
	sender, err := authkit.NewBrevoMailer(brevoConfig(cfg.SMTP))
	if err != nil {
		logus.WriteLog(logus.LogLevelWarn, "Email sender not configured: ", err)
		return authCfg
	}
	authCfg.Mailer = sender
	return authCfg
}

// brevoConfig maps this service's SMTP settings onto authkit's public Brevo
// configuration. Empty values are passed through; authkit applies its defaults.
func brevoConfig(s config.SMTP) authkit.BrevoConfig {
	return authkit.BrevoConfig{
		Host: s.Host, Port: s.Port, User: s.User, Pass: s.Password, From: s.From,
		OTPSubject: s.OTPSubject, ResetSubject: s.ResetSubject, AppName: s.AppName,
	}
}

// ModuleDeps returns what the modules are wired from: the open connections, the
// config and the shutdown Lifecycle. The routes use it, and so can a second
// binary or transport that builds the App with New.
func (a *App) ModuleDeps() module.Deps {
	return module.Deps{Config: a.cfg, DB: a.db, SQLDB: a.sqlDB, Redis: a.redis, Kit: a.kit, Storage: a.storage, Lifecycle: a.lifecycle}
}

// buildRoutes creates the router and server once; it runs after the migrations
// because some routes query the database.
func (a *App) buildRoutes() error {
	if a.engine != nil {
		return nil
	}
	engine, err := router.New(a.ModuleDeps())
	if err != nil {
		return fmt.Errorf("initialize routes: %w", err)
	}
	if a.routes != nil {
		a.routes(engine)
	}
	logus.WriteLog(logus.LogLevelInfo, "All routes registered successfully")

	a.engine = engine
	a.server = &http.Server{
		Addr:              ":" + a.cfg.App.Port,
		Handler:           engine,
		ReadHeaderTimeout: a.cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       a.cfg.HTTP.ReadTimeout,
		WriteTimeout:      a.cfg.HTTP.WriteTimeout,
		IdleTimeout:       a.cfg.HTTP.IdleTimeout,
	}
	return nil
}

// Handler returns the HTTP handler with every route mounted, or nil before
// the routes are built (Serve builds them).
func (a *App) Handler() http.Handler {
	if a.engine == nil {
		return nil
	}
	return a.engine
}

// Close stops background work (waiting at most HTTP_SHUTDOWN_TIMEOUT), then closes
// Redis and the database. Only the first call acts.
func (a *App) Close() error {
	return a.closeBy(time.Now().Add(a.cfg.HTTP.ShutdownTimeout))
}

// closeBy is Close with an explicit deadline so Serve's drain, hooks and final
// writes share one.
func (a *App) closeBy(deadline time.Time) error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true

	var errs []error
	if a.lifecycle != nil {
		stopCtx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		if err := a.lifecycle.Close(stopCtx); err != nil {
			errs = append(errs, fmt.Errorf("stop background work: %w", err))
		}
	}
	if a.redis != nil {
		if err := a.redis.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close redis: %w", err))
		}
	}
	if a.sqlDB != nil {
		if err := a.sqlDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close database: %w", err))
		}
	}
	return errors.Join(errs...)
}

// setServerIPEnv publishes the first non-loopback IPv4 address as ServerIP for the
// logger; the only environment write outside internal/config.
func setServerIPEnv() error {
	addr := "unknown"
	addrs, _ := net.InterfaceAddrs()
	for _, address := range addrs {
		if ipNet, ok := address.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			addr = ipNet.IP.String()
			break
		}
	}
	addr = fmt.Sprintf("%-15s", addr)
	if err := os.Setenv("ServerIP", addr); err != nil {
		return fmt.Errorf("set server IP: %w", err)
	}
	logus.WriteLog(logus.LogLevelInfo, "Server IP: "+addr)
	return nil
}
