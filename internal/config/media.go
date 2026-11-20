package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zazhedho/gokit"
)

const defaultAllowedContentTypes = "image/jpeg,image/png,image/webp,image/gif,application/pdf"

// Media is the media module's setting.
type Media struct {
	Enabled             bool
	MaxFileSizeBytes    int64
	AllowedContentTypes []string
	UploadRateLimit     int
	UploadRateWindow    time.Duration
	UploadTimeout       time.Duration
}

// Storage is the object-storage setting the media module needs.
type Storage struct {
	Provider, Endpoint, AccessKey, SecretKey, Bucket, BaseURL, Region, R2AccountID string
	UseSSL                                                                         bool
}

// String redacts both keys.
func (s Storage) String() string {
	return fmt.Sprintf("Storage{Provider:%q Endpoint:%q AccessKey:%s SecretKey:%s Bucket:%q BaseURL:%q Region:%q R2AccountID:%q UseSSL:%t}",
		s.Provider, s.Endpoint, redact(s.AccessKey), redact(s.SecretKey), s.Bucket, withoutUserinfo(s.BaseURL), s.Region, s.R2AccountID, s.UseSSL)
}

// GoString keeps %#v from printing the raw fields.
func (s Storage) GoString() string { return s.String() }

func mediaFromEnv() (Media, Storage) {
	media := Media{
		Enabled:             gokit.GetEnv("MEDIA_ENABLED", false),
		MaxFileSizeBytes:    megabytes("MEDIA_MAX_FILE_SIZE_MB", 5),
		AllowedContentTypes: splitList(gokit.GetEnv("MEDIA_ALLOWED_CONTENT_TYPES", defaultAllowedContentTypes)),
		UploadRateLimit:     gokit.GetEnv("MEDIA_UPLOAD_RATE_LIMIT", 20),
		UploadRateWindow:    time.Duration(gokit.GetEnv("MEDIA_UPLOAD_RATE_WINDOW_SECONDS", 60)) * time.Second,
		UploadTimeout:       gokit.GetEnv("MEDIA_UPLOAD_TIMEOUT", 2*time.Minute),
	}
	storage := Storage{
		Provider:    normalizeKey(gokit.GetEnv("STORAGE_PROVIDER", "minio")),
		Endpoint:    gokit.GetEnv("STORAGE_ENDPOINT", ""),
		AccessKey:   gokit.GetEnv("STORAGE_ACCESS_KEY", ""),
		SecretKey:   gokit.GetEnv("STORAGE_SECRET_KEY", ""),
		Bucket:      gokit.GetEnv("STORAGE_BUCKET_NAME", ""),
		BaseURL:     gokit.GetEnv("STORAGE_BASE_URL", ""),
		Region:      gokit.GetEnv("STORAGE_REGION", "auto"),
		R2AccountID: gokit.GetEnv("R2_ACCOUNT_ID", ""),
		UseSSL:      gokit.GetEnv("STORAGE_USE_SSL", false),
	}
	return media, storage
}

// validateMedia covers the media module's own settings, its storage and the
// request-body limit it depends on.
func (c Config) validateMedia() []string {
	var problems []string
	if c.Media.Enabled && c.HTTP.MaxBodyBytes <= c.Media.MaxFileSizeBytes {
		problems = append(problems, "HTTP_MAX_BODY_MB must be greater than MEDIA_MAX_FILE_SIZE_MB when media is enabled")
	}
	if c.Media.UploadTimeout <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_TIMEOUT must be greater than zero")
	}
	if c.Media.MaxFileSizeBytes <= 0 {
		problems = append(problems, "MEDIA_MAX_FILE_SIZE_MB must be between 1 and 1024")
	}
	problems = append(problems, c.validateStorage()...)
	problems = append(problems, c.validateMediaRate()...)
	return problems
}

func (c Config) validateStorage() []string {
	s := c.Storage
	configured := c.Media.Enabled || s.Endpoint != "" || s.AccessKey != "" || s.SecretKey != "" ||
		s.Bucket != "" || s.BaseURL != "" || s.R2AccountID != ""
	if !configured {
		return nil
	}

	var problems []string
	provider := s.Provider
	if provider == "" {
		provider = "minio"
	}
	switch provider {
	case "minio", "r2", "cloudflare", "cloudflare-r2":
	default:
		problems = append(problems, "STORAGE_PROVIDER must be one of: minio, r2, cloudflare, cloudflare-r2")
	}

	for _, f := range []struct{ key, value string }{
		{"STORAGE_ENDPOINT", s.Endpoint}, {"STORAGE_ACCESS_KEY", s.AccessKey},
		{"STORAGE_SECRET_KEY", s.SecretKey}, {"STORAGE_BUCKET_NAME", s.Bucket},
	} {
		if f.value == "" {
			problems = append(problems, f.key+" is required when storage is configured")
		}
	}
	if c.Media.Enabled && s.BaseURL == "" {
		problems = append(problems, "STORAGE_BASE_URL is required when media is enabled")
	}
	if s.BaseURL != "" {
		if _, err := url.ParseRequestURI(s.BaseURL); err != nil {
			problems = append(problems, "STORAGE_BASE_URL must be a valid URL")
		}
	}
	return problems
}

func (c Config) validateMediaRate() []string {
	if !c.Media.Enabled {
		return nil
	}
	var problems []string
	if c.Media.UploadRateLimit <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_RATE_LIMIT must be greater than zero")
	}
	if c.Media.UploadRateWindow <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_RATE_WINDOW_SECONDS must be greater than zero")
	}
	return problems
}

// withoutUserinfo drops any user:password part of a URL so it can be printed.
func withoutUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid"
	}
	u.User = nil
	return u.String()
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
