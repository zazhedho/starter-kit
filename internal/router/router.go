// Package router builds the HTTP engine: global middleware, health checks and
// every module's routes, from explicit configuration and connections. It
// opens nothing; the caller passes in every connection and provider.
package router

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	authmiddlewares "github.com/zazhedho/authkit/middlewares"
	"github.com/zazhedho/gokit/middlewares"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/pkg/storage"
)

// Deps is everything the routes need. Redis is nil when Redis is not used;
// Storage is nil when media is disabled.
type Deps struct {
	Config  config.Config
	DB      *gorm.DB
	SQLDB   *sql.DB
	Redis   *redis.Client
	Kit     *authkit.Kit
	Storage storage.StorageProvider
}

// registrar mounts one module's routes. Module registrars take the /api group
// and use paths relative to it.
type registrar struct {
	name     string
	register func(r gin.IRouter, d Deps) error
}

// rootRegistrars are mounted on the engine itself (probes live outside /api).
var rootRegistrars = []registrar{
	{"health", registerHealth},
}

// apiRegistrars are mounted under /api, after authkit's own routes.
var apiRegistrars = []registrar{
	{"location", registerLocation},
	{"media", registerMedia},
}

func (d Deps) validate() error {
	var missing []string
	if d.DB == nil {
		missing = append(missing, "DB")
	}
	if d.SQLDB == nil {
		missing = append(missing, "SQLDB")
	}
	if d.Kit == nil {
		missing = append(missing, "Kit")
	}
	if d.Config.Media.Enabled && d.Storage == nil {
		missing = append(missing, "Storage (media is enabled)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("router deps incomplete: %v", missing)
	}
	return nil
}

// New builds the engine with its global middleware and all routes.
func New(d Deps) (*gin.Engine, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}

	engine := gin.New()

	engine.Use(middlewares.CORS())
	engine.Use(gin.CustomRecovery(middlewares.ErrorHandler))
	engine.Use(middlewares.SetContextId())
	engine.Use(authmiddlewares.RequestLogger())
	engine.Use(bodyLimit(d.Config.HTTP.MaxBodyBytes))

	if err := mount(engine, rootRegistrars, d); err != nil {
		return nil, err
	}

	api := engine.Group("/api")
	d.Kit.Mount(api)
	if err := mount(api, apiRegistrars, d); err != nil {
		return nil, err
	}

	return engine, nil
}

// mount runs the registrars in order and stops at the first error.
func mount(r gin.IRouter, registrars []registrar, d Deps) error {
	for _, reg := range registrars {
		if err := reg.register(r, d); err != nil {
			return fmt.Errorf("register %s routes: %w", reg.name, err)
		}
	}
	return nil
}
