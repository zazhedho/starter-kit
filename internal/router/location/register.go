// Package location mounts the location module: wire.go builds it from
// module.Deps, register.go mounts its routes. Alias routerlocation.
package location

import (
	"github.com/gin-gonic/gin"

	"starter-kit/internal/router/module"
)

// Register wires the module and mounts its routes under r.
func Register(r gin.IRouter, d module.Deps) error {
	w, err := wire(d)
	if err != nil {
		return err
	}
	h := w.handler

	location := r.Group("/location")
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
