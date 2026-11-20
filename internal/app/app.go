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
	"github.com/zazhedho/logus"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/internal/infrastructure/database"
	"starter-kit/internal/infrastructure/storage"
	"starter-kit/internal/router"
	"starter-kit/internal/router/module"
)

type App struct {
	cfg    config.Config
	db     *gorm.DB
	sqlDB  *sql.DB
	redis  *redis.Client
	kit    *authkit.Kit
	engine *gin.Engine
	server *http.Server

	storage storage.Provider

	// Close runs the hooks before releasing Redis and the database, so the work they stop can still use them.
	lifecycle *module.Lifecycle
	routes    func(*gin.Engine)

	listener net.Listener
	migrate  func(ctx context.Context) error

	closeMu sync.Mutex
	closed  bool
}

type deps struct {
	openDB      func(config.Database, string) (*gorm.DB, *sql.DB, error)
	listener    net.Listener
	initStorage func(config.Storage) (storage.Provider, error)
	routes      func(*gin.Engine)
	migrate     func(ctx context.Context) error
}

func Run(ctx context.Context, args []string) error {
	return run(ctx, args, deps{})
}

func run(ctx context.Context, args []string, d deps) error {
	if err := setServerIPEnv(); err != nil {
		return err
	}

	cfg, err := loadConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	logus.Logf(logus.LevelInfo, "APP: %s; PORT: %s", cfg.App.Name, cfg.App.Port)
	for _, warning := range cfg.Warnings() {
		logus.Log(logus.LevelWarn, warning)
	}

	return execute(ctx, cfg, d)
}

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
		logus.Log(logus.LevelInfo, "Migration finished; not serving (migrate-only)")
		return nil
	}
	// Routes come after the migration: some modules query their tables when they are registered.
	if err := a.buildRoutes(); err != nil {
		return err
	}
	return a.Serve(ctx)
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	return newApp(ctx, cfg, deps{})
}

func newApp(ctx context.Context, cfg config.Config, d deps) (*App, error) {
	loc, err := time.LoadLocation(cfg.App.Timezone)
	if err != nil {
		return nil, fmt.Errorf("load time zone: %w", err)
	}
	// Process-wide setting: write it only when it changes, or a second App (tests) races with
	// readers of time.Local.
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

	fail := func(err error) (*App, error) {
		if closeErr := a.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}

	if cfg.Redis.Configured() {
		if a.redis, err = database.OpenRedis(ctx, cfg.Redis); err != nil {
			return fail(fmt.Errorf("open redis: %w", err))
		}
		logus.Log(logus.LevelInfo, "Redis initialized, session management enabled")
	}

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
	// authkit drains its in-flight mail after the HTTP server stops and before Redis and the database close;
	// hooks run in reverse order, so later module hooks run before it.
	a.lifecycle.OnClose("authkit", a.kit.Close)
	return a, nil
}

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
		logus.Log(logus.LevelWarn, "Email sender not configured:", err)
		return authCfg
	}
	authCfg.Mailer = sender
	return authCfg
}

func brevoConfig(s config.SMTP) authkit.BrevoConfig {
	return authkit.BrevoConfig{
		Host: s.Host, Port: s.Port, User: s.User, Pass: s.Password, From: s.From,
		OTPSubject: s.OTPSubject, ResetSubject: s.ResetSubject, AppName: s.AppName,
	}
}

func (a *App) ModuleDeps() module.Deps {
	return module.Deps{Config: a.cfg, DB: a.db, SQLDB: a.sqlDB, Redis: a.redis, Kit: a.kit, Storage: a.storage, Lifecycle: a.lifecycle}
}

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
	logus.Log(logus.LevelInfo, "All routes registered successfully")

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

func (a *App) Handler() http.Handler {
	if a.engine == nil {
		return nil
	}
	return a.engine
}

func (a *App) Close() error {
	return a.closeBy(time.Now().Add(a.cfg.HTTP.ShutdownTimeout))
}

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
	if err := os.Setenv("SERVER_IP", addr); err != nil {
		return fmt.Errorf("set server IP: %w", err)
	}
	logus.Log(logus.LevelInfo, "Server IP:", addr)
	return nil
}
