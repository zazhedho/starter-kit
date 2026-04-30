package database

import "testing"

func TestGetAndCloseRedisWhenUnset(t *testing.T) {
	RedisClient = nil
	if got := GetRedisClient(); got != nil {
		t.Fatalf("expected nil redis client, got %#v", got)
	}
	if err := CloseRedis(); err != nil {
		t.Fatalf("expected nil close error, got %v", err)
	}
}
