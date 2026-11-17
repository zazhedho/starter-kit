package router

import (
	"github.com/gin-gonic/gin"

	locationHandler "starter-kit/internal/handlers/http/location"
	locationRepo "starter-kit/internal/repositories/location"
	locationSvc "starter-kit/internal/services/location"
)

func registerLocation(r gin.IRouter, d Deps) error {
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
