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

func New(d module.Deps) (*gin.Engine, error) {
	if err := validate(d); err != nil {
		return nil, err
	}

	engine := gin.New()
	// Nil trusts no proxy, so X-Forwarded-For cannot pick the client IP the limiters key on.
	if err := engine.SetTrustedProxies(d.Config.HTTP.TrustedProxies); err != nil {
		return nil, fmt.Errorf("set trusted proxies: %w", err)
	}

	// The request id comes first so recovery, the limiters and handlers share one log_id per request.
	engine.Use(gokit.RequestIDMiddleware())
	engine.Use(gokit.Recovery())
	engine.Use(gokit.CORS(gokit.CORSOptions{})) // open by default: any origin, no credentials
	engine.Use(authkit.RequestLogger())
	engine.Use(bodyLimit(d.Config.HTTP.MaxBodyBytes))

	registerHealth(engine, d)

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
