// Package router builds the HTTP engine: global middleware, health checks and
// every module's routes, from explicit configuration and connections.
package router

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	authmiddlewares "github.com/zazhedho/authkit/middlewares"
	"github.com/zazhedho/gokit/messages"
	"github.com/zazhedho/gokit/middlewares"
	"github.com/zazhedho/gokit/response"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"gorm.io/gorm"

	mediaInfrastructure "starter-kit/infrastructure/media"
	"starter-kit/internal/config"
	locationHandler "starter-kit/internal/handlers/http/location"
	mediaHandler "starter-kit/internal/handlers/http/media"
	locationRepo "starter-kit/internal/repositories/location"
	mediaRepo "starter-kit/internal/repositories/media"
	locationSvc "starter-kit/internal/services/location"
	mediaSvc "starter-kit/internal/services/media"
)

const readyTimeout = 2 * time.Second

// Deps is everything the routes need. Redis is nil when Redis is not used.
type Deps struct {
	Config config.Config
	DB     *gorm.DB
	SQLDB  *sql.DB
	Redis  *redis.Client
	Kit    *authkit.Kit
}

// New builds the engine with its global middleware and all routes.
func New(d Deps) (*gin.Engine, error) {
	engine := gin.New()

	engine.Use(middlewares.CORS())
	engine.Use(gin.CustomRecovery(middlewares.ErrorHandler))
	engine.Use(middlewares.SetContextId())
	engine.Use(authmiddlewares.RequestLogger())
	engine.Use(bodyLimit(d.Config.HTTP.MaxBodyBytes))

	registerHealth(engine, d)
	d.Kit.Mount(engine.Group("/api"))
	registerLocation(engine, d)
	if err := registerMedia(engine, d); err != nil {
		return nil, fmt.Errorf("register media routes: %w", err)
	}

	return engine, nil
}

// bodyLimit caps request bodies. A declared Content-Length over the limit is
// answered with 413 up front; a body without a declared length is wrapped in
// http.MaxBytesReader, so reading past the limit fails and the handler answers
// (most JSON handlers with 400, the media handler with 413).
func bodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			logID := utils.GenerateLogId(c)
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
				response.ErrorResponse(http.StatusRequestEntityTooLarge, messages.InvalidRequest, logID, "request body too large"))
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

func registerHealth(r gin.IRouter, d Deps) {
	r.GET("/healthcheck", func(ctx *gin.Context) {
		logus.WriteLogWithContext(ctx, logus.LogLevelDebug, "ClientIP: "+ctx.ClientIP())
		ctx.JSON(http.StatusOK, gin.H{
			"message": "OK!!",
		})
	})

	r.GET("/readyz", func(ctx *gin.Context) {
		pingCtx, cancel := context.WithTimeout(ctx.Request.Context(), readyTimeout)
		defer cancel()

		if err := ping(pingCtx, d); err != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, "readyz; "+err.Error())
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

func ping(ctx context.Context, d Deps) error {
	if d.SQLDB == nil {
		return errors.New("database is not configured")
	}
	if err := d.SQLDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	if d.Redis != nil {
		if err := d.Redis.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis ping failed: %w", err)
		}
	}
	return nil
}

func registerLocation(r gin.IRouter, d Deps) {
	loc := d.Config.Location
	repo := locationRepo.NewLocationRepo(d.DB)
	svc := locationSvc.NewLocationService(repo, locationSvc.Options{
		Redis:      d.Redis,
		BaseURL:    loc.ServiceBaseURL,
		SourceYear: loc.SourceYear,
		Timeout:    loc.ServiceTimeout,
		CacheTTL:   loc.CacheTTL,
	})
	h := locationHandler.NewLocationHandler(svc)

	location := r.Group("/api/location")
	{
		location.GET("/province", h.GetProvince)
		location.GET("/city", h.GetCity)
		location.GET("/district", h.GetDistrict)
		location.GET("/village", h.GetVillage)
	}

	locationPriv := r.Group("/api/location").Use(d.Kit.Auth())
	{
		locationPriv.POST("/sync", d.Kit.Can("locations", "sync"), h.Sync)
		locationPriv.GET("/sync/:id", d.Kit.Can("locations", "sync"), h.GetSyncJob)
	}
}

func registerMedia(r gin.IRouter, d Deps) error {
	m := d.Config.Media
	if !m.Enabled {
		logus.WriteLog(logus.LogLevelDebug, "Media routes disabled")
		return nil
	}

	storageProvider, err := mediaInfrastructure.InitStorage(d.Config.Storage)
	if err != nil {
		return err
	}

	repo := mediaRepo.NewMediaRepo(d.DB)
	svc := mediaSvc.NewMediaService(repo, storageProvider, m.MaxFileSizeBytes, m.AllowedContentTypes)
	h := mediaHandler.NewMediaHandler(svc, d.Kit.Audit(), m.UploadTimeout)

	media := r.Group("/api/media").Use(d.Kit.Auth())
	{
		uploadLimiter := middlewares.IPRateLimitMiddleware(d.Redis, "media_upload", m.UploadRateLimit, m.UploadRateWindow)
		media.POST("", uploadLimiter, h.Upload)
		media.DELETE("/:id", h.Delete)
	}

	logus.WriteLog(logus.LogLevelInfo, "Media routes registered")
	return nil
}
