package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/logus"
)

const readyTimeout = 2 * time.Second

func registerHealth(r gin.IRouter, d Deps) error {
	r.GET("/healthcheck", func(ctx *gin.Context) {
		logus.WriteLogWithContext(ctx, logus.LogLevelDebug, "ClientIP: "+ctx.ClientIP())
		ctx.JSON(http.StatusOK, gin.H{
			"message": "OK!!",
		})
	})

	r.GET("/readyz", func(ctx *gin.Context) {
		pingCtx, cancel := context.WithTimeout(ctx.Request.Context(), readyTimeout)
		defer cancel()

		if err := ping(pingCtx, d); err != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, "readyz; "+err.Error())
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return nil
}

func ping(ctx context.Context, d Deps) error {
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
