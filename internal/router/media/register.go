// Package media mounts the media module: wire.go builds it from module.Deps,
// register.go mounts its routes. Alias routermedia.
package media

import (
	"github.com/gin-gonic/gin"
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
		// The limiter needs Redis. Without it the route is unthrottled, as before.
		// Limit and Window are validated in config: gokit panics on a value <= 0.
		var uploadHandlers []gin.HandlerFunc
		if d.Redis != nil {
			uploadHandlers = append(uploadHandlers, gokit.IPRateLimit(gokit.RateLimitOptions{
				Redis:  d.Redis,
				Prefix: "media_upload",
				Limit:  m.UploadRateLimit,
				Window: m.UploadRateWindow,
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
