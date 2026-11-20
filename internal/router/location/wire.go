package location

import (
	"context"
	"fmt"
	"time"

	"github.com/zazhedho/gokit"

	httplocation "starter-kit/internal/handlers/http/location"
	cachelocation "starter-kit/internal/infrastructure/cache/location"
	repositorylocation "starter-kit/internal/repositories/location"
	"starter-kit/internal/router/module"
	servicelocation "starter-kit/internal/services/location"
)

var recoveryTimeout = 10 * time.Second

type wired struct {
	handler *httplocation.Handler
}

func wire(d module.Deps) (*wired, error) {
	loc := d.Config.Location
	repo := repositorylocation.NewRepository(d.DB)
	svc := servicelocation.NewService(repo, servicelocation.Options{
		Cache:    cachelocation.New(d.Redis),
		NewID:    gokit.CreateUUID,
		BaseURL:  loc.ServiceBaseURL,
		Timeout:  loc.ServiceTimeout,
		CacheTTL: loc.CacheTTL,

		MaxResponseBytes: loc.MaxResponseBytes,
	})
	recoverCtx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	if err := svc.RecoverInterruptedJobs(recoverCtx); err != nil {
		return nil, fmt.Errorf("recover location sync jobs: %w", err)
	}
	d.Lifecycle.OnDrain(svc.Interrupt)
	d.Lifecycle.OnClose("location sync", svc.Close)
	return &wired{handler: httplocation.New(svc)}, nil
}
