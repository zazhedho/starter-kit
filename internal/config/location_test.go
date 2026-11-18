package config

import (
	"testing"
	"time"
)

func TestFromEnvAcceptsSecondsForms(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("LOCATION_SERVICE_TIMEOUT_SECONDS", "0")
	t.Setenv("LOCATION_CACHE_TTL", "3600")
	cfg := FromEnv()
	if cfg.Location.ServiceTimeout != 20*time.Second {
		t.Fatalf("non-positive timeout must fall back to 20s, got %v", cfg.Location.ServiceTimeout)
	}
	if cfg.Location.CacheTTL != time.Hour {
		t.Fatalf("plain seconds LOCATION_CACHE_TTL must be accepted, got %v", cfg.Location.CacheTTL)
	}
}
