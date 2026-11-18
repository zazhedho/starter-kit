package router

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"

	httplocation "starter-kit/internal/handlers/http/location"
	cachelocation "starter-kit/internal/infrastructure/cache/location"
	repositorylocation "starter-kit/internal/repositories/location"
	servicelocation "starter-kit/internal/services/location"
)

func registerLocation(r gin.IRouter, d Deps) error {
	loc := d.Config.Location
	repo := repositorylocation.NewRepository(d.DB)
	svc := servicelocation.NewService(repo, servicelocation.Options{
		Cache:      cachelocation.New(d.Redis),
		NewID:      gokit.CreateUUID,
		BaseURL:    loc.ServiceBaseURL,
		SourceYear: loc.SourceYear,
		Timeout:    loc.ServiceTimeout,
		CacheTTL:   loc.CacheTTL,
	})
	// A sync job left queued or running by a previous process will never
	// finish: fail it now, then let the application stop this process's job at
	// shutdown.
	if err := svc.RecoverInterruptedJobs(context.Background()); err != nil {
		return fmt.Errorf("recover location sync jobs: %w", err)
	}
	d.Lifecycle.OnClose("location sync", svc.Close)
	h := httplocation.New(svc)

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
