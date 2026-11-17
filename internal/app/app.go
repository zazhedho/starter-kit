// Package app owns the service lifecycle. Run loads and validates the
// configuration, then New opens the connections, Migrate updates the schema,
// Serve handles requests until the context ends, and Close releases
// everything. Every failure is returned as an error; only cmd/api decides to
// exit the process.
package app

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
	"github.com/zazhedho/authkit/mailer"
	"github.com/zazhedho/logus"
	"gorm.io/gorm"

	"starter-kit/infrastructure/database"
	"starter-kit/infrastructure/media"
	"starter-kit/internal/config"
	"starter-kit/internal/router"
	appconfig "starter-kit/pkg/config"
	"starter-kit/pkg/storage"
)

// App holds the open connections and the HTTP server of one running service.
type App struct {
	cfg    config.Config
	db     *gorm.DB
	sqlDB  *sql.DB
	redis  *redis.Client
	kit    *authkit.Kit
	engine *gin.Engine
	server *http.Server

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
	initStorage func(config.Storage) (storage.StorageProvider, error)
	routes      func(*gin.Engine)
	migrate     func(ctx context.Context) error
}

// Run is the whole program: it loads configuration, builds the App, migrates
// when asked, and serves until ctx is canceled. args are the command-line
// arguments without the program name.
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

// loadConfig applies the sources in their fixed order: .env (never overriding
// the environment), Consul or the config file, the environment, command-line
// flags, then validation.
func loadConfig(args []string) (config.Config, error) {
	if err := config.LoadDotEnv(".env"); err != nil {
		return config.Config{}, fmt.Errorf("load environment: %w", err)
	}
	confID := appconfig.GetAppConf("CONFIG_ID", "", nil)
	logus.WriteLog(logus.LogLevelDebug, fmt.Sprintf("ConfigID: %v", confID))

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
	return a.Serve(ctx)
}

// New opens the database, and Redis when configured, builds authkit and the
// routes, and prepares the HTTP server. If any step fails, everything already
// opened is closed and the error is returned.
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

	a := &App{cfg: cfg, listener: d.listener, migrate: d.migrate}
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
	var storageProvider storage.StorageProvider
	if cfg.Media.Enabled {
		initStorage := d.initStorage
		if initStorage == nil {
			initStorage = media.InitStorage
		}
		if storageProvider, err = initStorage(cfg.Storage); err != nil {
			return fail(fmt.Errorf("initialize storage: %w", err))
		}
	}

	authCfg := cfg.Auth
	authCfg.DB = a.db
	if a.redis != nil {
		authCfg.Redis = a.redis
		// The mailer is only useful with Redis (OTP and password reset need it).
		if cfg.SMTPConfigured {
			if sender, mailErr := mailer.NewBrevoSenderFromEnv(); mailErr != nil {
				logus.WriteLog(logus.LogLevelWarn, "Email sender not configured: ", mailErr)
			} else {
				authCfg.Mailer = sender
			}
		}
	}
	if a.kit, err = authkit.New(authCfg); err != nil {
		return fail(fmt.Errorf("initialize authkit: %w", err))
	}

	if a.engine, err = router.New(router.Deps{Config: cfg, DB: a.db, SQLDB: a.sqlDB, Redis: a.redis, Kit: a.kit, Storage: storageProvider}); err != nil {
		return fail(fmt.Errorf("initialize routes: %w", err))
	}
	if d.routes != nil {
		d.routes(a.engine)
	}
	logus.WriteLog(logus.LogLevelInfo, "All routes registered successfully")

	a.server = &http.Server{
		Addr:              ":" + cfg.App.Port,
		Handler:           a.engine,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}
	return a, nil
}

// Handler returns the HTTP handler with every route mounted.
func (a *App) Handler() http.Handler { return a.engine }

// Close closes Redis, then the database. It is safe to call more than once;
// only the first call does anything and reports errors.
func (a *App) Close() error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true

	var errs []error
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

// setServerIPEnv publishes the host's first non-loopback IPv4 address as
// ServerIP, which the logger adds to every line. It is the only place outside
// internal/config that writes the environment.
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
