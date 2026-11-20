package config

import (
	"strings"
	"testing"
)

func warningsText(t *testing.T) string {
	t.Helper()
	return strings.Join(FromEnv().Warnings(), "\n")
}

func TestWarnings(t *testing.T) {
	t.Run("without redis, media and the public location reads are not limited", warnsWithoutRedis)
	t.Run("placeholder secrets in development name the variable only", warnsPlaceholderSecretsByName)
	t.Run("minio without ssl outside development", warnsMinioWithoutSSL)
	t.Run("public read has no effect with r2", warnsPublicReadOnR2)
	t.Run("a clean config has none", isQuietWhenClean)
}

func warnsWithoutRedis(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	enableMediaEnv(t)
	got := warningsText(t)
	for _, want := range []string{"MEDIA_ENABLED", "LOCATION_RATE_LIMIT"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warnings = %q, want %s", got, want)
		}
	}
	t.Setenv("REDIS_HOST", "cache")
	t.Setenv("STORAGE_USE_SSL", "true")
	if got := FromEnv().Warnings(); len(got) != 0 {
		t.Fatalf("warnings = %v, want none with Redis", got)
	}
}

func warnsPlaceholderSecretsByName(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("REDIS_HOST", "cache")
	t.Setenv("APP_ENV", "development")
	enableMediaEnv(t)
	t.Setenv("DB_PASS", "CHANGE_ME_DB_PASSWORD")
	t.Setenv("STORAGE_SECRET_KEY", "minioadmin")
	t.Setenv("JWT_KEY", "a-real-looking-key-that-is-long-enough-1234")
	got := warningsText(t)
	for _, want := range []string{"DB_PASS", "STORAGE_SECRET_KEY"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warnings = %q, want %s", got, want)
		}
	}
	if strings.Contains(got, "JWT_KEY") || strings.Contains(got, "CHANGE_ME") || strings.Contains(got, "minioadmin") {
		t.Fatalf("warnings = %q: only placeholder variables, never values", got)
	}
}

func warnsMinioWithoutSSL(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("REDIS_HOST", "cache")
	enableMediaEnv(t)
	t.Setenv("STORAGE_USE_SSL", "false")
	t.Setenv("APP_ENV", "production")
	if got := warningsText(t); !strings.Contains(got, "STORAGE_USE_SSL") {
		t.Fatalf("warnings = %q, want STORAGE_USE_SSL", got)
	}
	t.Setenv("APP_ENV", "development")
	if got := warningsText(t); strings.Contains(got, "STORAGE_USE_SSL") {
		t.Fatalf("warnings = %q: development may use plain http", got)
	}
}

func warnsPublicReadOnR2(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("REDIS_HOST", "cache")
	enableMediaEnv(t)
	t.Setenv("STORAGE_PROVIDER", "r2")
	t.Setenv("STORAGE_USE_SSL", "true")
	t.Setenv("STORAGE_PUBLIC_READ", "true")
	if got := warningsText(t); !strings.Contains(got, "STORAGE_PUBLIC_READ") {
		t.Fatalf("warnings = %q, want STORAGE_PUBLIC_READ", got)
	}
}

func isQuietWhenClean(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("REDIS_HOST", "cache")
	if got := FromEnv().Warnings(); len(got) != 0 {
		t.Fatalf("warnings = %v", got)
	}
}

func TestPlaceholderSecretsAreErrorsOutsideDevelopment(t *testing.T) {
	for _, env := range []string{"production", "staging", ""} {
		t.Run("env="+env, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			enableMediaEnv(t)
			t.Setenv("APP_ENV", env)
			t.Setenv("DB_PASS", "CHANGE_ME_DB_PASSWORD")
			t.Setenv("JWT_KEY", "CHANGE_ME_JWT_KEY")
			t.Setenv("STORAGE_ACCESS_KEY", "CHANGE_ME_STORAGE_ACCESS_KEY")
			t.Setenv("STORAGE_SECRET_KEY", "minioadmin")
			err := validateFromEnv(t)
			wantInError(t, err, "DB_PASS", "JWT_KEY", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY")
			if strings.Contains(err.Error(), "CHANGE_ME") || strings.Contains(err.Error(), "minioadmin") {
				t.Fatalf("the error leaks a value: %v", err)
			}
		})
	}
}

func TestPlaceholderSecretsAreOnlyWarningsInDevelopment(t *testing.T) {
	for _, env := range []string{"development", "dev", "local", "test"} {
		t.Run(env, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			t.Setenv("APP_ENV", env)
			t.Setenv("DB_PASS", "CHANGE_ME_DB_PASSWORD")
			if err := validateFromEnv(t); err != nil {
				t.Fatalf("Validate = %v, want a warning only", err)
			}
		})
	}
}

func TestStorageKeysAreNotCheckedWhileMediaIsOff(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	enableMediaEnv(t)
	t.Setenv("MEDIA_ENABLED", "false")
	t.Setenv("APP_ENV", "production")
	t.Setenv("STORAGE_SECRET_KEY", "CHANGE_ME_STORAGE_SECRET_KEY")
	if err := validateFromEnv(t); err != nil {
		t.Fatalf("Validate = %v: unused storage keys are not a risk", err)
	}
}

func TestConfigStringRedactsTheLocationURLUserinfo(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	t.Setenv("LOCATION_SERVICE_BASE_URL", "https://user:hunter2@locations.example.invalid")
	got := FromEnv().String()
	if strings.Contains(got, "hunter2") || strings.Contains(got, "user:") {
		t.Fatalf("Config.String leaks the location URL userinfo: %s", got)
	}
	if !strings.Contains(got, "locations.example.invalid") {
		t.Fatalf("Config.String lost the host: %s", got)
	}
}
