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

// recoveryTimeout bounds the startup recovery of interrupted sync jobs. A
// variable so tests can shorten it.
var recoveryTimeout = 10 * time.Second

// wired is what the location routes need once the module is built.
type wired struct {
	handler *httplocation.Handler
	service *servicelocation.Service
}

// wire builds repository, cache, service and handler, fails sync jobs a previous
// process left behind, and registers the service's shutdown hook.
func wire(d module.Deps) (*wired, error) {
	loc := d.Config.Location
	repo := repositorylocation.NewRepository(d.DB)
	svc := servicelocation.NewService(repo, servicelocation.Options{
		Cache:    cachelocation.New(d.Redis),
		NewID:    gokit.CreateUUID,
		BaseURL:  loc.ServiceBaseURL,
		Timeout:  loc.ServiceTimeout,
		CacheTTL: loc.CacheTTL,
	})
	// A sync job left queued or running by a previous process will never
	// finish: fail it now, then let the application stop this process's job at
	// shutdown.
	recoverCtx, cancel := context.WithTimeout(context.Background(), recoveryTimeout)
	defer cancel()
	if err := svc.RecoverInterruptedJobs(recoverCtx); err != nil {
		return nil, fmt.Errorf("recover location sync jobs: %w", err)
	}
	d.Lifecycle.OnDrain(svc.Interrupt) // the job records its end while requests drain
	d.Lifecycle.OnClose("location sync", svc.Close)
	return &wired{handler: httplocation.New(svc), service: svc}, nil
}
