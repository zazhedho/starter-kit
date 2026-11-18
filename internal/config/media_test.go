package config

import "testing"

func TestValidateMedia(t *testing.T) {
	t.Run("requires storage when media enabled", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("MEDIA_ENABLED", "true")
		t.Setenv("MEDIA_MAX_FILE_SIZE_MB", "0")
		t.Setenv("STORAGE_PROVIDER", "r2")
		wantInError(t, validateFromEnv(t),
			"STORAGE_ENDPOINT is required when storage is configured",
			"STORAGE_ACCESS_KEY is required when storage is configured",
			"STORAGE_BASE_URL is required when media is enabled",
			"MEDIA_MAX_FILE_SIZE_MB must be between 1 and 1024",
		)
	})

	t.Run("rejects invalid storage base url", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("STORAGE_ENDPOINT", "localhost:9000")
		t.Setenv("STORAGE_ACCESS_KEY", "k")
		t.Setenv("STORAGE_SECRET_KEY", "s")
		t.Setenv("STORAGE_BUCKET_NAME", "b")
		t.Setenv("STORAGE_BASE_URL", "not a url")
		wantInError(t, validateFromEnv(t), "STORAGE_BASE_URL must be a valid URL")
	})

	t.Run("max body must exceed media max file size", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("MEDIA_ENABLED", "true")
		t.Setenv("STORAGE_ENDPOINT", "localhost:9000")
		t.Setenv("STORAGE_ACCESS_KEY", "k")
		t.Setenv("STORAGE_SECRET_KEY", "s")
		t.Setenv("STORAGE_BUCKET_NAME", "b")
		t.Setenv("STORAGE_BASE_URL", "http://localhost:9000")
		t.Setenv("MEDIA_MAX_FILE_SIZE_MB", "10")
		t.Setenv("HTTP_MAX_BODY_MB", "10")
		wantInError(t, validateFromEnv(t), "HTTP_MAX_BODY_MB", "MEDIA_MAX_FILE_SIZE_MB")

		t.Setenv("HTTP_MAX_BODY_MB", "11")
		if err := validateFromEnv(t); err != nil {
			t.Fatalf("body larger than max file size must pass, got %v", err)
		}
	})

	t.Run("unknown timezone", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("APP_TIMEZONE", "Mars/Olympus")
		wantInError(t, validateFromEnv(t), "APP_TIMEZONE")
	})

	t.Run("collects several problems in one error", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("PORT", "0")
		t.Setenv("APP_TIMEZONE", "Mars/Olympus")
		err := validateFromEnv(t)
		wantInError(t, err, "PORT must be a number between 1 and 65535", "APP_TIMEZONE", "; ")
	})
}

func TestMediaUploadRateIsValidatedWhenMediaEnabled(t *testing.T) {
	for _, bad := range []string{"-5", "0"} {
		t.Run("limit="+bad, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			enableMediaEnv(t)
			t.Setenv("MEDIA_UPLOAD_RATE_LIMIT", bad)
			wantInError(t, validateFromEnv(t), "MEDIA_UPLOAD_RATE_LIMIT")
		})
		t.Run("window="+bad, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			enableMediaEnv(t)
			t.Setenv("MEDIA_UPLOAD_RATE_WINDOW_SECONDS", bad)
			wantInError(t, validateFromEnv(t), "MEDIA_UPLOAD_RATE_WINDOW_SECONDS")
		})
	}
	t.Run("ignored when media disabled", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		t.Setenv("MEDIA_UPLOAD_RATE_LIMIT", "0")
		if err := validateFromEnv(t); err != nil {
			t.Fatalf("expected success with media disabled, got %v", err)
		}
	})
}

func enableMediaEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MEDIA_ENABLED", "true")
	t.Setenv("STORAGE_ENDPOINT", "files.example.com")
	t.Setenv("STORAGE_ACCESS_KEY", "access")
	t.Setenv("STORAGE_SECRET_KEY", "secret")
	t.Setenv("STORAGE_BUCKET_NAME", "bucket")
	t.Setenv("STORAGE_BASE_URL", "https://files.example.com")
}
