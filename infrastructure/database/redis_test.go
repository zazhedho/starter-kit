package database

import (
	"context"
	"testing"

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
