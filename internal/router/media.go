package router

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	httpmedia "starter-kit/internal/handlers/http/media"
	repositorymedia "starter-kit/internal/repositories/media"
	servicemedia "starter-kit/internal/services/media"
)

// registerMedia mounts the media routes, or nothing when media is disabled.
// The storage provider arrives in Deps; New has already checked it is there.
func registerMedia(r gin.IRouter, d Deps) error {
	m := d.Config.Media
	if !m.Enabled {
		logus.WriteLog(logus.LogLevelDebug, "Media routes disabled")
		return nil
	}

	repo := repositorymedia.NewRepository(d.DB)
	svc := servicemedia.NewService(repo, d.Storage, servicemedia.Options{
		MaxFileSize:         m.MaxFileSizeBytes,
		AllowedContentTypes: m.AllowedContentTypes,
		NewID:               gokit.CreateUUID,
	})
	h := httpmedia.New(svc, d.Kit.Audit(), m.UploadTimeout)

	media := r.Group("/media").Use(d.Kit.Auth())
	{
		uploadLimiter := gokit.IPRateLimitMiddleware(d.Redis, "media_upload", m.UploadRateLimit, m.UploadRateWindow)
		media.POST("", uploadLimiter, h.Upload)
		media.DELETE("/:id", h.Delete)
	}

	logus.WriteLog(logus.LogLevelInfo, "Media routes registered")
	return nil
}
