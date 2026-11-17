package database

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/logus"

	"starter-kit/internal/config"
)

// OpenRedis connects to Redis and checks it with PING (5 second limit). On
// failure nothing is left open. The caller owns, and must close, the client.
func OpenRedis(ctx context.Context, cfg config.Redis) (*redis.Client, error) {
	var opt *redis.Options
	if cfg.URL != "" {
		parsed, err := redis.ParseURL(cfg.URL)
		if err != nil {
			// The parse error quotes the URL, which may carry a password.
			return nil, errors.New("REDIS_URL is invalid")
		}
		opt = parsed
	} else {
		opt = &redis.Options{
			Addr:         net.JoinHostPort(cfg.Host, cfg.Port),
			Password:     cfg.Password,
			DB:           cfg.DB,
			DialTimeout:  10 * time.Second,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			PoolSize:     10,
			PoolTimeout:  30 * time.Second,
		}
	}
	client := redis.NewClient(opt)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, failed("ping redis: "+classifyRedis(err), "OpenRedis; ")
	}

	logus.WriteLog(logus.LogLevelInfo, "OpenRedis; connected to Redis at "+client.Options().Addr)
	return client, nil
}

// classifyRedis names the kind of failure without using the client's text,
// which can quote addresses and credentials.
func classifyRedis(err error) string {
	var netErr net.Error
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "WRONGPASS") || strings.HasPrefix(msg, "NOAUTH") || strings.Contains(msg, "AUTH"):
		return "authentication failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return "timed out"
	default:
		return "unavailable"
	}
}
