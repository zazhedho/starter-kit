package router

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	authmiddlewares "github.com/zazhedho/authkit/middlewares"
	"github.com/zazhedho/gokit/middlewares"
	"github.com/zazhedho/gokit/utils"
	"github.com/zazhedho/logus"
	"gorm.io/gorm"

	"starter-kit/infrastructure/database"
	mediaInfrastructure "starter-kit/infrastructure/media"
	locationHandler "starter-kit/internal/handlers/http/location"
	mediaHandler "starter-kit/internal/handlers/http/media"
	locationRepo "starter-kit/internal/repositories/location"
	mediaRepo "starter-kit/internal/repositories/media"
	locationSvc "starter-kit/internal/services/location"
	mediaSvc "starter-kit/internal/services/media"
)

type Routes struct {
	App *gin.Engine
	DB  *gorm.DB
	Kit *authkit.Kit
}

func NewRoutes() *Routes {
	app := gin.Default()

	app.Use(middlewares.CORS())
	app.Use(gin.CustomRecovery(middlewares.ErrorHandler))
	app.Use(middlewares.SetContextId())
	app.Use(authmiddlewares.RequestLogger())

	app.GET("/healthcheck", func(ctx *gin.Context) {
		logus.WriteLogWithContext(ctx, logus.LogLevelDebug, "ClientIP: "+ctx.ClientIP())
		ctx.JSON(http.StatusOK, gin.H{
			"message": "OK!!",
		})
	})

	return &Routes{
		App: app,
	}
}

// MountAuthKit registers the users, auth, RBAC, menu, config and audit routes
// provided by authkit under /api. Kit must be set first.
func (r *Routes) MountAuthKit() {
	r.Kit.Mount(r.App.Group("/api"))
}

func (r *Routes) LocationRoutes() {
	repo := locationRepo.NewLocationRepo(r.DB)
	svc := locationSvc.NewLocationService(repo, database.GetRedisClient())
	h := locationHandler.NewLocationHandler(svc)

	location := r.App.Group("/api/location")
	{
		location.GET("/province", h.GetProvince)
		location.GET("/city", h.GetCity)
		location.GET("/district", h.GetDistrict)
		location.GET("/village", h.GetVillage)
	}

	locationPriv := r.App.Group("/api/location").Use(r.Kit.Auth())
	{
		locationPriv.POST("/sync", r.Kit.Can("locations", "sync"), h.Sync)
		locationPriv.GET("/sync/:id", r.Kit.Can("locations", "sync"), h.GetSyncJob)
	}
}

func (r *Routes) MediaRoutes() error {
	if !utils.GetEnv("MEDIA_ENABLED", false) {
		logus.WriteLog(logus.LogLevelDebug, "Media routes disabled")
		return nil
	}

	storageProvider, err := mediaInfrastructure.InitStorage()
	if err != nil {
		return err
	}

	maxFileSize := int64(utils.GetEnv("MEDIA_MAX_FILE_SIZE_MB", 5)) << 20
	allowedContentTypes := strings.Split(utils.GetEnv("MEDIA_ALLOWED_CONTENT_TYPES", "image/jpeg,image/png,image/webp,image/gif,application/pdf"), ",")
	repo := mediaRepo.NewMediaRepo(r.DB)
	svc := mediaSvc.NewMediaService(repo, storageProvider, maxFileSize, allowedContentTypes)
	h := mediaHandler.NewMediaHandler(svc, r.Kit.Audit())

	media := r.App.Group("/api/media").Use(r.Kit.Auth())
	{
		uploadLimiter := middlewares.IPRateLimitMiddleware(
			database.GetRedisClient(),
			"media_upload",
			utils.GetEnv("MEDIA_UPLOAD_RATE_LIMIT", 20),
			time.Duration(utils.GetEnv("MEDIA_UPLOAD_RATE_WINDOW_SECONDS", 60))*time.Second,
		)
		media.POST("", uploadLimiter, h.Upload)
		media.DELETE("/:id", h.Delete)
	}

	logus.WriteLog(logus.LogLevelInfo, "Media routes registered")
	return nil
}
