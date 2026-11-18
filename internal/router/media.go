package router

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	mediaHandler "starter-kit/internal/handlers/http/media"
	mediaRepo "starter-kit/internal/repositories/media"
	mediaSvc "starter-kit/internal/services/media"
)

// registerMedia mounts the media routes, or nothing when media is disabled.
// The storage provider arrives in Deps; New has already checked it is there.
func registerMedia(r gin.IRouter, d Deps) error {
	m := d.Config.Media
	if !m.Enabled {
		logus.WriteLog(logus.LogLevelDebug, "Media routes disabled")
		return nil
	}

	repo := mediaRepo.NewRepository(d.DB)
	svc := mediaSvc.NewMediaService(repo, d.Storage, m.MaxFileSizeBytes, m.AllowedContentTypes)
	h := mediaHandler.NewMediaHandler(svc, d.Kit.Audit(), m.UploadTimeout)

	media := r.Group("/media").Use(d.Kit.Auth())
	{
		uploadLimiter := gokit.IPRateLimitMiddleware(d.Redis, "media_upload", m.UploadRateLimit, m.UploadRateWindow)
		media.POST("", uploadLimiter, h.Upload)
		media.DELETE("/:id", h.Delete)
	}

	logus.WriteLog(logus.LogLevelInfo, "Media routes registered")
	return nil
}
