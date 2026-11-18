// Package router builds the HTTP engine: middleware, health checks and module
// routes. It opens nothing; callers pass in every connection.
package router

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	servicemedia "starter-kit/internal/services/media"
)

// Deps is everything the routes need. Redis is nil when unused, Storage when media
// is disabled; the caller closes Lifecycle.
type Deps struct {
	Config  config.Config
	DB      *gorm.DB
	SQLDB   *sql.DB
	Redis   *redis.Client
	Kit     *authkit.Kit
	Storage servicemedia.Storage

	Lifecycle *Lifecycle
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

// apiRegistrars mount under /api after authkit's routes; a new module must also be
// added to the router tests' expected route list.
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
	if d.Lifecycle == nil {
		missing = append(missing, "Lifecycle")
	}
	if d.Config.Media.Enabled && d.Storage == nil {
		missing = append(missing, "Storage (media is enabled)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("router deps incomplete: %v", missing)
	}
	return nil
}

// New returns the engine, or an error when Deps is incomplete or a registrar
// fails.
func New(d Deps) (*gin.Engine, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}

	engine := gin.New()

	engine.Use(gokit.CORS())
	engine.Use(gin.CustomRecovery(gokit.ErrorHandler))
	engine.Use(gokit.SetContextId())
	engine.Use(authkit.RequestLogger())
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
