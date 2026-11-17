package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit/utils"
)

const (
	defaultLocationServiceBaseURL = "https://location-service-y7si.onrender.com"
	defaultLocationTimeoutSeconds = 20
	defaultLocationCacheTTL       = 180 * 24 * time.Hour
	maxSizeMB                     = 1024
	defaultAllowedContentTypes    = "image/jpeg,image/png,image/webp,image/gif,application/pdf"
)

// FromEnv reads the process environment as it is. It does not load .env or
// Consul; the caller does that first. Values it cannot parse fall back to
// their defaults and are reported later by Validate.
func FromEnv() Config {
	var l loader

	cfg := Config{
		App: App{
			Name:     utils.GetEnv("APP_NAME", ""),
			Env:      utils.GetEnv("APP_ENV", ""),
			Port:     utils.GetEnv("PORT", ""),
			Timezone: l.str("APP_TIMEZONE", "Asia/Jakarta"),
		},
		HTTP: HTTP{
			ReadHeaderTimeout: l.duration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
			ReadTimeout:       l.duration("HTTP_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:      l.duration("HTTP_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:       l.duration("HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout:   l.duration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
			MaxBodyBytes:      l.megabytes("HTTP_MAX_BODY_MB", 10),
		},
		Database: Database{
			URL:             utils.GetEnv("DATABASE_URL", ""),
			Host:            utils.GetEnv("DB_HOST", ""),
			Port:            utils.GetEnv("DB_PORT", ""),
			Username:        utils.GetEnv("DB_USERNAME", ""),
			Password:        utils.GetEnv("DB_PASS", ""),
			Name:            utils.GetEnv("DB_NAME", ""),
			SSLMode:         l.str("DB_SSLMODE", "disable"),
			MaxOpenConns:    l.integer("DB_MAX_OPEN_CONNS", 100),
			MaxIdleConns:    l.integer("DB_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: l.duration("DB_CONN_MAX_LIFETIME", time.Hour),
			ConnMaxIdleTime: l.duration("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
		},
		Migrate: Migrate{
			Run:  utils.GetEnv("RUN_MIGRATION", true),
			Path: l.str("PATH_MIGRATE", "file://migrations"),
		},
		Location: Location{
			ServiceBaseURL: strings.TrimRight(l.str("LOCATION_SERVICE_BASE_URL", defaultLocationServiceBaseURL), "/"),
			SourceYear:     utils.GetEnv("LOCATION_SOURCE_YEAR", ""),
			ServiceTimeout: locationTimeout(),
			CacheTTL:       locationCacheTTL(),
		},
		Media: Media{
			Enabled:             utils.GetEnv("MEDIA_ENABLED", false),
			MaxFileSizeBytes:    l.megabytes("MEDIA_MAX_FILE_SIZE_MB", 5),
			AllowedContentTypes: splitList(l.str("MEDIA_ALLOWED_CONTENT_TYPES", defaultAllowedContentTypes)),
			UploadRateLimit:     utils.GetEnv("MEDIA_UPLOAD_RATE_LIMIT", 20),
			UploadRateWindow:    time.Duration(utils.GetEnv("MEDIA_UPLOAD_RATE_WINDOW_SECONDS", 60)) * time.Second,
			UploadTimeout:       l.duration("MEDIA_UPLOAD_TIMEOUT", 2*time.Minute),
		},
		Storage: Storage{
			Provider:    utils.NormalizeKey(l.str("STORAGE_PROVIDER", "minio")),
			Endpoint:    utils.GetEnv("STORAGE_ENDPOINT", ""),
			AccessKey:   utils.GetEnv("STORAGE_ACCESS_KEY", ""),
			SecretKey:   utils.GetEnv("STORAGE_SECRET_KEY", ""),
			Bucket:      utils.GetEnv("STORAGE_BUCKET_NAME", ""),
			BaseURL:     utils.GetEnv("STORAGE_BASE_URL", ""),
			Region:      l.str("STORAGE_REGION", "auto"),
			R2AccountID: utils.GetEnv("R2_ACCOUNT_ID", ""),
			UseSSL:      utils.GetEnv("STORAGE_USE_SSL", false),
		},
		Auth: authkit.ConfigFromEnv(),
	}

	cfg.Redis = Redis{
		URL:      utils.GetEnv("REDIS_URL", ""),
		Host:     utils.GetEnv("REDIS_HOST", ""),
		Port:     l.str("REDIS_PORT", "6379"),
		Password: utils.GetEnv("REDIS_PASSWORD", ""),
	}
	cfg.Redis.DB, cfg.Redis.dbInvalid = redisDB()

	cfg.smtp = smtpSettings{
		hostSet: utils.GetEnv("SMTP_HOST", "") != "",
		passSet: utils.GetEnv("SMTP_PASS", "") != "",
		port:    utils.GetEnv("SMTP_PORT", ""),
		from:    utils.GetEnv("SMTP_FROM", ""),
	}
	cfg.SMTPConfigured = cfg.smtp.hostSet && cfg.smtp.passSet && cfg.smtp.from != ""
	cfg.problems = l.problems

	return cfg
}

// loader reads the variables introduced with this config. Unlike the legacy
// seconds forms, they take Go durations, and anything unparsable is recorded
// for Validate instead of being dropped silently.
type loader struct{ problems []string }

func (l *loader) str(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func (l *loader) duration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		l.problems = append(l.problems, key+" must be a duration such as 30s or 2m")
		return def
	}
	return d
}

// megabytes reads a size in whole megabytes and returns it in bytes. The raw
// number is checked before it is shifted so a huge value cannot wrap around
// to a small one; an out-of-range value is recorded for Validate and the
// default is used.
func (l *loader) megabytes(key string, def int) int64 {
	n := l.integer(key, def)
	if n < 1 || n > maxSizeMB {
		l.problems = append(l.problems, key+" must be between 1 and 1024")
		n = def
	}
	return int64(n) << 20
}

func (l *loader) integer(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		l.problems = append(l.problems, key+" must be an integer")
		return def
	}
	return n
}

// locationTimeout keeps the seconds form LOCATION_SERVICE_TIMEOUT_SECONDS has
// always accepted; a non-positive value means the default.
func locationTimeout() time.Duration {
	sec := utils.GetEnv("LOCATION_SERVICE_TIMEOUT_SECONDS", defaultLocationTimeoutSeconds)
	if sec <= 0 {
		sec = defaultLocationTimeoutSeconds
	}
	return time.Duration(sec) * time.Second
}

// locationCacheTTL keeps every form LOCATION_CACHE_TTL has always accepted
// (Go duration, plain seconds, "eod"); a non-positive value means the default.
func locationCacheTTL() time.Duration {
	ttl := utils.GetEnv("LOCATION_CACHE_TTL", defaultLocationCacheTTL)
	if ttl <= 0 {
		return defaultLocationCacheTTL
	}
	return ttl
}

// redisDB returns REDIS_DB and whether it was set to something that is not an
// integer, which the old startup validation reported.
func redisDB() (db int, invalid bool) {
	raw := strings.TrimSpace(os.Getenv("REDIS_DB"))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, true
	}
	return n, false
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
