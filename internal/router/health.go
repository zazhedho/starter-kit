package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/logus"

	"starter-kit/internal/router/module"
)

const readyTimeout = 2 * time.Second

func registerHealth(r gin.IRouter, d module.Deps) {
	r.GET("/healthcheck", func(ctx *gin.Context) {
		logus.LogContext(ctx, logus.LevelDebug, "ClientIP:", ctx.ClientIP())
		ctx.JSON(http.StatusOK, gin.H{
			"message": "OK!!",
		})
	})

	r.GET("/readyz", func(ctx *gin.Context) {
		// Once shutdown has started the service is still up but must receive no
		// new traffic, so the load balancer is told before the server drains.
		if d.Lifecycle.Draining() {
			logus.LogContext(ctx, logus.LevelDebug, "readyz; shutting down")
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		pingCtx, cancel := context.WithTimeout(ctx.Request.Context(), readyTimeout)
		defer cancel()

		if err := ping(pingCtx, d); err != nil {
			logus.LogContext(ctx, logus.LevelWarn, "readyz; "+err.Error())
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

func ping(ctx context.Context, d module.Deps) error {
	if d.SQLDB == nil {
		return errors.New("database is not configured")
	}
	if err := d.SQLDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	if d.Redis != nil {
		if err := d.Redis.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis ping failed: %w", err)
		}
	}
	return nil
}
