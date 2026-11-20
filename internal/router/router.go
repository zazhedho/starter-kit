// Package router builds the HTTP engine: middleware, health checks and module
// routes. It opens nothing; callers pass in every connection.
package router

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"

	"starter-kit/internal/router/module"
)

func validate(d module.Deps) error {
	var missing []string
	if d.DB == nil {
		missing = append(missing, "DB")
	}
	if d.SQLDB == nil {
		missing = append(missing, "SQLDB")
	}
	if d.Kit == nil {
		missing = append(missing, "Kit")
	}
	if d.Lifecycle == nil {
		missing = append(missing, "Lifecycle")
	}
	if len(missing) > 0 {
		return fmt.Errorf("router deps incomplete: %v", missing)
	}
	return nil
}

// New returns the engine, or an error when Deps is incomplete or a module
// fails to register. Probes live on the engine; modules (modules.go) mount under /api.
func New(d module.Deps) (*gin.Engine, error) {
	if err := validate(d); err != nil {
		return nil, err
	}

	engine := gin.New()

	// The request id comes first: recovery, the limiters and every handler then
	// log and answer with one log_id per request.
	engine.Use(gokit.RequestIDMiddleware())
	engine.Use(gokit.Recovery())
	engine.Use(gokit.CORS(gokit.CORSOptions{})) // open by default: any origin, no credentials
	engine.Use(authkit.RequestLogger())
	engine.Use(bodyLimit(d.Config.HTTP.MaxBodyBytes))

	if err := registerHealth(engine, d); err != nil {
		return nil, fmt.Errorf("register health routes: %w", err)
	}

	api := engine.Group("/api")
	if err := d.Kit.Mount(api); err != nil {
		return nil, fmt.Errorf("mount authkit routes: %w", err)
	}
	for _, m := range modules {
		if err := m.Register(api, d); err != nil {
			return nil, fmt.Errorf("register %s routes: %w", m.Name, err)
		}
	}

	return engine, nil
}
