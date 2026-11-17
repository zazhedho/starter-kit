package database

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"starter-kit/internal/config"
)

func TestOpenRedisPingFailureReturnsError(t *testing.T) {
	client, err := OpenRedis(context.Background(), config.Redis{URL: "redis://127.0.0.1:1/0"})
	if err == nil {
		if client != nil {
			_ = client.Close()
		}
		t.Fatal("expected redis connection error")
	}
	if client != nil {
		t.Fatalf("expected nil client on error, got %#v", client)
	}

	client, err = OpenRedis(context.Background(), config.Redis{Host: "127.0.0.1", Port: "1"})
	if err == nil || client != nil {
		t.Fatalf("expected host/port ping failure with nil client, got %v %v", client, err)
	}
}

func TestOpenRedisErrorDoesNotLeakPasswordOrURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	client, err := OpenRedis(ctx, config.Redis{URL: "redis://:url-SECRET@127.0.0.1:1/0"})
	if err == nil || client != nil {
		t.Fatalf("expected failure with nil client, got %v %v", client, err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "redis://") {
		t.Fatalf("error leaks the URL or password: %q", err)
	}

	mr := miniredis.RunT(t)
	mr.RequireAuth("right-password")
	host, port, _ := net.SplitHostPort(mr.Addr())
	_, err = OpenRedis(ctx, config.Redis{Host: host, Port: port, Password: "wrong-SECRET"})
	if err == nil {
		t.Fatal("expected an authentication failure")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error leaks the password: %q", err)
	}
}
