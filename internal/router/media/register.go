// Package media mounts the media module: wire.go builds it from module.Deps,
// register.go mounts its routes. Alias routermedia.
package media

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	"starter-kit/internal/router/module"
)

// Register mounts nothing when media is disabled; otherwise it wires the module
// and mounts its routes under r.
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
		// The limiters need Redis; without it the route is unthrottled.
		// Limits and windows are validated in config: gokit panics on a value <= 0.
		// The per-user limit comes after Auth, which sets the user the key reads.
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
		// Permission-aware routes load the caller's permissions after Auth; the
		// handler reads them through the scope and never rejects on its own.
		loadPermissions := d.Kit.LoadPermissions()
		media.GET("", loadPermissions, h.List)
		media.POST("", uploadHandlers...)
		media.DELETE("/:id", loadPermissions, h.Delete)
	}

	logus.Log(logus.LevelInfo, "Media routes registered")
	return nil
}
