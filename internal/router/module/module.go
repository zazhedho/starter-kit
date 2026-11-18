package module

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"gorm.io/gorm"

	"starter-kit/internal/config"
	"starter-kit/internal/infrastructure/storage"
)

// Deps is everything a module is wired from. Redis is nil when unused, Storage
// when media is disabled; the caller closes Lifecycle.
type Deps struct {
	Config  config.Config
	DB      *gorm.DB
	SQLDB   *sql.DB
	Redis   *redis.Client
	Kit     *authkit.Kit
	Storage storage.Provider

	Lifecycle *Lifecycle
}

// Entry mounts one module's routes. Register takes the /api group and uses
// paths relative to it; it checks the Deps it needs and returns an error rather
// than panicking or exiting.
type Entry struct {
	Name     string
	Register func(r gin.IRouter, d Deps) error
}
