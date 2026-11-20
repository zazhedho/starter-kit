package config

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zazhedho/gokit"

	domainmedia "starter-kit/internal/domain/media"
)

type Media struct {
	Enabled                    bool
	MaxFileSizeBytes           int64
	AllowedContentTypes        []string
	UploadRateLimit            int
	UploadRateWindow           time.Duration
	UserUploadLimit            int
	UserUploadWindow           time.Duration
	UploadTimeout              time.Duration
	UploadMaxConcurrent        int
	UploadMaxConcurrentPerUser int
}

type Storage struct {
	Provider, Endpoint, AccessKey, SecretKey, Bucket, BaseURL, Region, R2AccountID string
	UseSSL                                                                         bool
	PublicRead                                                                     bool
}

func (s Storage) String() string {
	return fmt.Sprintf("Storage{Provider:%q Endpoint:%q AccessKey:%s SecretKey:%s Bucket:%q BaseURL:%q Region:%q R2AccountID:%q UseSSL:%t PublicRead:%t}",
		s.Provider, s.Endpoint, redact(s.AccessKey), redact(s.SecretKey), s.Bucket, withoutUserinfo(s.BaseURL), s.Region, s.R2AccountID, s.UseSSL, s.PublicRead)
}

func (s Storage) GoString() string { return s.String() }

func mediaFromEnv() (Media, Storage) {
	media := Media{
		Enabled:                    gokit.GetEnv("MEDIA_ENABLED", false),
		MaxFileSizeBytes:           megabytes("MEDIA_MAX_FILE_SIZE_MB", 5),
		AllowedContentTypes:        splitList(gokit.GetEnv("MEDIA_ALLOWED_CONTENT_TYPES", strings.Join(domainmedia.SupportedContentTypes(), ","))),
		UploadRateLimit:            gokit.GetEnv("MEDIA_UPLOAD_RATE_LIMIT", 20),
		UploadRateWindow:           time.Duration(gokit.GetEnv("MEDIA_UPLOAD_RATE_WINDOW_SECONDS", 60)) * time.Second,
		UserUploadLimit:            gokit.GetEnv("MEDIA_UPLOAD_USER_RATE_LIMIT", 10),
		UserUploadWindow:           time.Duration(gokit.GetEnv("MEDIA_UPLOAD_USER_RATE_WINDOW_SECONDS", 60)) * time.Second,
		UploadTimeout:              gokit.GetEnv("MEDIA_UPLOAD_TIMEOUT", time.Minute),
		UploadMaxConcurrent:        gokit.GetEnv("MEDIA_UPLOAD_MAX_CONCURRENT", 8),
		UploadMaxConcurrentPerUser: gokit.GetEnv("MEDIA_UPLOAD_MAX_CONCURRENT_PER_USER", 2),
	}
	provider := normalizeKey(gokit.GetEnv("STORAGE_PROVIDER", "minio"))
	storage := Storage{
		Provider:    provider,
		Endpoint:    gokit.GetEnv("STORAGE_ENDPOINT", ""),
		AccessKey:   gokit.GetEnv("STORAGE_ACCESS_KEY", ""),
		SecretKey:   gokit.GetEnv("STORAGE_SECRET_KEY", ""),
		Bucket:      gokit.GetEnv("STORAGE_BUCKET_NAME", ""),
		BaseURL:     gokit.GetEnv("STORAGE_BASE_URL", ""),
		Region:      gokit.GetEnv("STORAGE_REGION", defaultRegion(provider)),
		R2AccountID: gokit.GetEnv("R2_ACCOUNT_ID", ""),
		UseSSL:      gokit.GetEnv("STORAGE_USE_SSL", false),
		PublicRead:  gokit.GetEnv("STORAGE_PUBLIC_READ", false),
	}
	return media, storage
}

// R2 requires "auto"; MinIO picks its own region when empty.
func defaultRegion(provider string) string {
	if isR2(provider) {
		return "auto"
	}
	return ""
}

func isR2(provider string) bool {
	switch provider {
	case "r2", "cloudflare", "cloudflare-r2":
		return true
	}
	return false
}

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
	problems = append(problems, c.validateContentTypes()...)
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
	switch {
	case provider == "minio":
	case isR2(provider):
		if !s.UseSSL {
			problems = append(problems, "STORAGE_USE_SSL must be true for the r2, cloudflare and cloudflare-r2 providers")
		}
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

func (c Config) validateContentTypes() []string {
	supported := domainmedia.SupportedContentTypes()
	for _, configured := range c.Media.AllowedContentTypes {
		if !slices.Contains(supported, domainmedia.NormalizeContentType(configured)) {
			return []string{"MEDIA_ALLOWED_CONTENT_TYPES may list only: " + strings.Join(supported, ", ") + " (text/html and SVG are never allowed)"}
		}
	}
	return nil
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
	if c.Media.UploadMaxConcurrent <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_MAX_CONCURRENT must be greater than zero")
	}
	if c.Media.UploadMaxConcurrentPerUser <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_MAX_CONCURRENT_PER_USER must be greater than zero")
	}
	if c.Media.UserUploadLimit <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_USER_RATE_LIMIT must be greater than zero")
	}
	if c.Media.UserUploadWindow <= 0 {
		problems = append(problems, "MEDIA_UPLOAD_USER_RATE_WINDOW_SECONDS must be greater than zero")
	}
	return problems
}

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
