package config

import (
	"testing"
	"time"
)

func TestGetAppConfReturnsDefaultWhenConfigMissing(t *testing.T) {
	t.Setenv("CONSUL", "")
	t.Setenv("APP_CONFIG", t.TempDir())
	t.Setenv("APP_ENV", "test")

	if got := GetAppConf("MISSING_VALUE", "fallback", nil); got != "fallback" {
		t.Fatalf("expected fallback value, got %v", got)
	}
}

func TestLoadOTPConfigPrefersDurationStrings(t *testing.T) {
	t.Setenv("OTP_TTL_SECONDS", "300")
	t.Setenv("OTP_TTL", "7m")
	t.Setenv("OTP_COOLDOWN", "90s")
	t.Setenv("OTP_RATE_WINDOW", "10m")
	t.Setenv("OTP_MAX_ATTEMPTS", "3")
	t.Setenv("OTP_RATE_LIMIT", "9")
	t.Setenv("OTP_SECRET", " otp-secret ")

	got := LoadOTPConfig()
	if got.TTL != 7*time.Minute || got.Cooldown != 90*time.Second || got.RateWindow != 10*time.Minute {
		t.Fatalf("unexpected durations: %+v", got)
	}
	if got.MaxAttempts != 3 || got.RateLimit != 9 || got.Secret != "otp-secret" {
		t.Fatalf("unexpected scalar config: %+v", got)
	}
}

func TestLoadPasswordResetConfigUsesFallbackURL(t *testing.T) {
	t.Setenv("RESET_TTL", "20m")
	t.Setenv("RESET_COOLDOWN", "2m")
	t.Setenv("RESET_RATE_WINDOW", "30m")
	t.Setenv("RESET_RATE_LIMIT", "7")
	t.Setenv("RESET_SECRET", " reset-secret ")
	t.Setenv("RESET_URL_TEMPLATE", "")
	t.Setenv("RESET_URL", "https://example.com/reset?token={token}")

	got := LoadPasswordResetConfig()
	if got.TTL != 20*time.Minute || got.Cooldown != 2*time.Minute || got.RateWindow != 30*time.Minute {
		t.Fatalf("unexpected durations: %+v", got)
	}
	if got.RateLimit != 7 || got.Secret != "reset-secret" || got.URLTemplate != "https://example.com/reset?token={token}" {
		t.Fatalf("unexpected reset config: %+v", got)
	}
}
