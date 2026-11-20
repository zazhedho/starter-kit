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

type Deps struct {
	Config  config.Config
	DB      *gorm.DB
	SQLDB   *sql.DB
	Redis   *redis.Client
	Kit     *authkit.Kit
	Storage storage.Provider

	Lifecycle *Lifecycle
}

type Entry struct {
	Name     string
	Register func(r gin.IRouter, d Deps) error
}
