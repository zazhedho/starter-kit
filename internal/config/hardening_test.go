package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestSizeSettingsAreValidatedBeforeShifting(t *testing.T) {
	for _, key := range []string{"MEDIA_MAX_FILE_SIZE_MB", "HTTP_MAX_BODY_MB"} {
		for _, bad := range []string{"0", "1025", "17592186044417", "-3"} {
			t.Run(key+"="+bad, func(t *testing.T) {
				clearEnv(t)
				setRequiredEnv(t)
				t.Setenv(key, bad)
				wantInError(t, validateFromEnv(t), key+" must be between 1 and 1024")
			})
		}
		for _, good := range []string{"1", "1024"} {
			t.Run(key+"="+good+" accepted", func(t *testing.T) {
				clearEnv(t)
				setRequiredEnv(t)
				t.Setenv(key, good)
				if err := validateFromEnv(t); err != nil {
					t.Fatalf("expected %s=%s to be accepted, got %v", key, good, err)
				}
			})
		}
	}
}

func TestRedactionHoldsForGoSyntaxPrinting(t *testing.T) {
	clearEnv(t)
	t.Setenv("JWT_KEY", "jwt-SECRET-0123456789-0123456789-0123")
	cfg := FromEnv()
	//nolint:gosec // G101: fixture values, not real credentials
	cfg.Database = Database{URL: "postgres://u:db-URL-SECRET@h/db", Password: "db-PASS-SECRET"}
	//nolint:gosec // G101: fixture values, not real credentials
	cfg.Redis = Redis{URL: "redis://:redis-URL-SECRET@h", Password: "redis-PASS-SECRET"}
	//nolint:gosec // G101: fixture values, not real credentials
	cfg.Storage = Storage{AccessKey: "storage-ACCESS-SECRET", SecretKey: "storage-KEY-SECRET", BaseURL: "http://bu:base-URL-SECRET@files.example.com/x"}

	outputs := map[string]string{
		"config":   fmt.Sprintf("%#v", cfg),
		"database": fmt.Sprintf("%#v", cfg.Database),
		"redis":    fmt.Sprintf("%#v", cfg.Redis),
		"storage":  fmt.Sprintf("%#v", cfg.Storage),
		"v":        fmt.Sprintf("%v %+v", cfg, cfg.Storage),
	}
	secrets := []string{"db-URL-SECRET", "db-PASS-SECRET", "redis-URL-SECRET", "redis-PASS-SECRET",
		"storage-ACCESS-SECRET", "storage-KEY-SECRET", "jwt-SECRET", "base-URL-SECRET"}
	for name, out := range outputs {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s output leaks %q: %s", name, secret, out)
			}
		}
	}
	if !strings.Contains(outputs["storage"], "files.example.com") {
		t.Errorf("expected the base URL host to stay visible: %s", outputs["storage"])
	}
}

func TestHostAndPortValuesAreTrimmed(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("PORT", " 8080")
	t.Setenv("DB_HOST", " db.internal ")
	t.Setenv("DB_PORT", "5432 ")
	t.Setenv("REDIS_HOST", " cache ")
	cfg := FromEnv()
	if cfg.App.Port != "8080" || cfg.Database.Host != "db.internal" || cfg.Database.Port != "5432" || cfg.Redis.Host != "cache" {
		t.Fatalf("values not trimmed: %q %q %q %q", cfg.App.Port, cfg.Database.Host, cfg.Database.Port, cfg.Redis.Host)
	}
}
