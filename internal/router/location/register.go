package location

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"

	"starter-kit/internal/router/module"
)

func Register(r gin.IRouter, d module.Deps) error {
	w, err := wire(d)
	if err != nil {
		return err
	}
	h := w.handler

	// Limit and Window are validated in config: gokit panics on a value <= 0.
	location := r.Group("/location")
	if d.Redis != nil {
		location.Use(gokit.IPRateLimit(gokit.RateLimitOptions{
			Redis:      d.Redis,
			Prefix:     "location_read",
			Limit:      d.Config.Location.RateLimit,
			Window:     d.Config.Location.RateWindow,
			FailClosed: d.Config.Auth.FailClosedLimiters,
		}))
	}
	{
		location.GET("/province", h.GetProvince)
		location.GET("/city", h.GetCity)
		location.GET("/district", h.GetDistrict)
		location.GET("/village", h.GetVillage)
	}

	locationPriv := r.Group("/location").Use(d.Kit.Auth())
	{
		locationPriv.POST("/sync", d.Kit.Can("locations", "sync"), h.Sync)
		locationPriv.GET("/sync/:id", d.Kit.Can("locations", "sync"), h.GetSyncJob)
	}
	return nil
}
