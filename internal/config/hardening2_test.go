package config

import (
	"strings"
	"testing"
	"time"
)

func TestLocationDefaults(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	l := FromEnv().Location
	if l.MaxResponseBytes != 4<<20 || l.RateLimit != 60 || l.RateWindow != time.Minute {
		t.Fatalf("Location = %+v", l)
	}
}

func TestValidateLocationBaseURL(t *testing.T) {
	cases := []struct {
		name, env, url string
		want           string
	}{
		{"https in production", "production", "https://locations.example.invalid", ""},
		{"https with a path", "", "https://locations.example.invalid/base", ""},
		{"http in development", "development", "http://localhost:9000", ""},
		{"http outside development", "production", "http://locations.example.invalid", "LOCATION_SERVICE_BASE_URL must use https"},
		{"http with APP_ENV unset", "", "http://locations.example.invalid", "LOCATION_SERVICE_BASE_URL must use https"},
		{"no scheme", "development", "locations.example.invalid", "LOCATION_SERVICE_BASE_URL must be an http or https URL"},
		{"other scheme", "development", "ftp://locations.example.invalid", "LOCATION_SERVICE_BASE_URL must be an http or https URL"},
		{"no host", "development", "https://", "LOCATION_SERVICE_BASE_URL must be an http or https URL"},
		{"not parsable", "development", "http://[::1", "LOCATION_SERVICE_BASE_URL must be an http or https URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			t.Setenv("APP_ENV", c.env)
			t.Setenv("LOCATION_SERVICE_BASE_URL", c.url)
			err := validateFromEnv(t)
			if c.want == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			wantInError(t, err, c.want)
			if strings.Contains(err.Error(), "invalid") && strings.Contains(err.Error(), c.url) {
				t.Fatalf("the error must not print the value: %v", err)
			}
		})
	}
}

func TestValidateLocationLimits(t *testing.T) {
	for _, c := range []struct{ key, value string }{
		{"LOCATION_SERVICE_MAX_RESPONSE_MB", "0"},
		{"LOCATION_SERVICE_MAX_RESPONSE_MB", "65"},
		{"LOCATION_RATE_LIMIT", "0"},
		{"LOCATION_RATE_WINDOW_SECONDS", "-1"},
	} {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			t.Setenv(c.key, c.value)
			wantInError(t, validateFromEnv(t), c.key)
		})
	}
}

func TestValidateStorageRequiresSSLForR2(t *testing.T) {
	for _, provider := range []string{"r2", "cloudflare", "cloudflare-r2"} {
		t.Run(provider, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			enableMediaEnv(t)
			t.Setenv("STORAGE_PROVIDER", provider)
			t.Setenv("STORAGE_USE_SSL", "false")
			wantInError(t, validateFromEnv(t), "STORAGE_USE_SSL must be true")

			t.Setenv("STORAGE_USE_SSL", "true")
			if err := validateFromEnv(t); err != nil {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
	t.Run("minio may use plain http", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		enableMediaEnv(t)
		t.Setenv("STORAGE_USE_SSL", "false")
		if err := validateFromEnv(t); err != nil {
			t.Fatalf("Validate = %v", err)
		}
	})
}

func TestStorageRegionDefaultsByProvider(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	if got := FromEnv().Storage.Region; got != "" {
		t.Fatalf("minio region = %q, want empty so the server's region is used", got)
	}
	t.Setenv("STORAGE_PROVIDER", "r2")
	if got := FromEnv().Storage.Region; got != "auto" {
		t.Fatalf("r2 region = %q, want auto", got)
	}
	t.Setenv("STORAGE_REGION", "eu-west-1")
	if got := FromEnv().Storage.Region; got != "eu-west-1" {
		t.Fatalf("explicit region = %q", got)
	}
}

func TestStoragePublicReadIsOptIn(t *testing.T) {
	clearEnv(t)
	setRequiredEnv(t)
	if FromEnv().Storage.PublicRead {
		t.Fatal("STORAGE_PUBLIC_READ must default to false")
	}
	t.Setenv("STORAGE_PUBLIC_READ", "true")
	if !FromEnv().Storage.PublicRead {
		t.Fatal("STORAGE_PUBLIC_READ=true must be read")
	}
}

func TestValidateAllowedContentTypes(t *testing.T) {
	bad := []string{"text/html", "image/svg+xml", "TEXT/HTML; charset=utf-8", "application/x-unknown", "image/*"}
	for _, ct := range bad {
		t.Run(ct, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			enableMediaEnv(t)
			t.Setenv("MEDIA_ALLOWED_CONTENT_TYPES", "image/png,"+ct)
			err := validateFromEnv(t)
			wantInError(t, err, "MEDIA_ALLOWED_CONTENT_TYPES")
			if strings.Contains(err.Error(), "x-unknown") {
				t.Fatalf("the error must not echo the value: %v", err)
			}
		})
	}
	t.Run("every supported type, in any case", func(t *testing.T) {
		clearEnv(t)
		setRequiredEnv(t)
		enableMediaEnv(t)
		t.Setenv("MEDIA_ALLOWED_CONTENT_TYPES", " IMAGE/PNG ,image/jpeg; q=1,application/pdf,image/gif,image/webp")
		if err := validateFromEnv(t); err != nil {
			t.Fatalf("Validate = %v", err)
		}
	})
}

func TestValidateUserUploadRate(t *testing.T) {
	for _, c := range []struct{ key, value string }{
		{"MEDIA_UPLOAD_USER_RATE_LIMIT", "0"},
		{"MEDIA_UPLOAD_USER_RATE_WINDOW_SECONDS", "0"},
	} {
		t.Run(c.key, func(t *testing.T) {
			clearEnv(t)
			setRequiredEnv(t)
			enableMediaEnv(t)
			t.Setenv(c.key, c.value)
			wantInError(t, validateFromEnv(t), c.key)
		})
	}
	clearEnv(t)
	setRequiredEnv(t)
	if m := FromEnv().Media; m.UserUploadLimit != 10 || m.UserUploadWindow != time.Minute {
		t.Fatalf("defaults = %d per %v", m.UserUploadLimit, m.UserUploadWindow)
	}
}
