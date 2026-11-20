package media

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	"starter-kit/internal/router/module"
)

func Register(r gin.IRouter, d module.Deps) error {
	m := d.Config.Media
	if !m.Enabled {
		logus.Log(logus.LevelDebug, "Media routes disabled")
		return nil
	}

	w, err := wire(d)
	if err != nil {
		return err
	}
	h := w.handler

	media := r.Group("/media").Use(d.Kit.Auth())
	{
		// Limits and windows are validated in config: gokit panics on a value <= 0.
		// The per-user limit comes after Auth, which sets the user its key reads.
		var uploadHandlers []gin.HandlerFunc
		if d.Redis != nil {
			uploadHandlers = append(uploadHandlers,
				gokit.IPRateLimit(gokit.RateLimitOptions{
					Redis:      d.Redis,
					Prefix:     "media_upload",
					Limit:      m.UploadRateLimit,
					Window:     m.UploadRateWindow,
					FailClosed: d.Config.Auth.FailClosedLimiters,
				}),
				gokit.IPRateLimit(gokit.RateLimitOptions{
					Redis:      d.Redis,
					Prefix:     "media_upload_user",
					Limit:      m.UserUploadLimit,
					Window:     m.UserUploadWindow,
					FailClosed: d.Config.Auth.FailClosedLimiters,
					KeyFunc:    func(c *gin.Context) string { return authkit.ScopeFrom(c.Request.Context()).UserID },
				}))
		}
		uploadHandlers = append(uploadHandlers, h.Upload)
		loadPermissions := d.Kit.LoadPermissions()
		media.GET("", loadPermissions, h.List)
		media.POST("", uploadHandlers...)
		media.DELETE("/:id", loadPermissions, h.Delete)
	}

	logus.Log(logus.LevelInfo, "Media routes registered")
	return nil
}
