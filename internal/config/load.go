package config

import (
	"github.com/zazhedho/gokit"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zazhedho/authkit"
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
			Name:     gokit.GetEnv("APP_NAME", ""),
			Env:      gokit.GetEnv("APP_ENV", ""),
			Port:     gokit.GetEnv("PORT", ""),
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
			URL:             gokit.GetEnv("DATABASE_URL", ""),
			Host:            gokit.GetEnv("DB_HOST", ""),
			Port:            gokit.GetEnv("DB_PORT", ""),
			Username:        gokit.GetEnv("DB_USERNAME", ""),
			Password:        gokit.GetEnv("DB_PASS", ""),
			Name:            gokit.GetEnv("DB_NAME", ""),
			SSLMode:         l.str("DB_SSLMODE", "disable"),
			MaxOpenConns:    l.integer("DB_MAX_OPEN_CONNS", 100),
			MaxIdleConns:    l.integer("DB_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: l.duration("DB_CONN_MAX_LIFETIME", time.Hour),
			ConnMaxIdleTime: l.duration("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
		},
		Migrate: Migrate{
			Run:  gokit.GetEnv("RUN_MIGRATION", true),
			Path: l.str("PATH_MIGRATE", "file://migrations"),
		},
		Location: Location{
			ServiceBaseURL: strings.TrimRight(l.str("LOCATION_SERVICE_BASE_URL", defaultLocationServiceBaseURL), "/"),
			SourceYear:     gokit.GetEnv("LOCATION_SOURCE_YEAR", ""),
			ServiceTimeout: locationTimeout(),
			CacheTTL:       locationCacheTTL(),
		},
		Media: Media{
			Enabled:             gokit.GetEnv("MEDIA_ENABLED", false),
			MaxFileSizeBytes:    l.megabytes("MEDIA_MAX_FILE_SIZE_MB", 5),
			AllowedContentTypes: splitList(l.str("MEDIA_ALLOWED_CONTENT_TYPES", defaultAllowedContentTypes)),
			UploadRateLimit:     gokit.GetEnv("MEDIA_UPLOAD_RATE_LIMIT", 20),
			UploadRateWindow:    time.Duration(gokit.GetEnv("MEDIA_UPLOAD_RATE_WINDOW_SECONDS", 60)) * time.Second,
			UploadTimeout:       l.duration("MEDIA_UPLOAD_TIMEOUT", 2*time.Minute),
		},
		Storage: Storage{
			Provider:    gokit.NormalizeKey(l.str("STORAGE_PROVIDER", "minio")),
			Endpoint:    gokit.GetEnv("STORAGE_ENDPOINT", ""),
			AccessKey:   gokit.GetEnv("STORAGE_ACCESS_KEY", ""),
			SecretKey:   gokit.GetEnv("STORAGE_SECRET_KEY", ""),
			Bucket:      gokit.GetEnv("STORAGE_BUCKET_NAME", ""),
			BaseURL:     gokit.GetEnv("STORAGE_BASE_URL", ""),
			Region:      l.str("STORAGE_REGION", "auto"),
			R2AccountID: gokit.GetEnv("R2_ACCOUNT_ID", ""),
			UseSSL:      gokit.GetEnv("STORAGE_USE_SSL", false),
		},
		Auth: authkit.ConfigFromEnv(),
	}

	cfg.Redis = Redis{
		URL:      gokit.GetEnv("REDIS_URL", ""),
		Host:     gokit.GetEnv("REDIS_HOST", ""),
		Port:     l.str("REDIS_PORT", "6379"),
		Password: gokit.GetEnv("REDIS_PASSWORD", ""),
	}
	cfg.Redis.DB, cfg.Redis.dbInvalid = redisDB()

	cfg.SMTP, cfg.smtpPortInvalid = smtpFromEnv()
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
	sec := gokit.GetEnv("LOCATION_SERVICE_TIMEOUT_SECONDS", defaultLocationTimeoutSeconds)
	if sec <= 0 {
		sec = defaultLocationTimeoutSeconds
	}
	return time.Duration(sec) * time.Second
}

// locationCacheTTL keeps every form LOCATION_CACHE_TTL has always accepted
// (Go duration, plain seconds, "eod"); a non-positive value means the default.
func locationCacheTTL() time.Duration {
	ttl := gokit.GetEnv("LOCATION_CACHE_TTL", defaultLocationCacheTTL)
	if ttl <= 0 {
		return defaultLocationCacheTTL
	}
	return ttl
}

// smtpFromEnv reads the SMTP_* variables (and the mail labels) with the names
// and defaults authkit's own env helper uses; an unset value stays empty so
// the mailer applies its default. A port that is not a number is reported
// through the second result and read as unset.
func smtpFromEnv() (s SMTP, portInvalid bool) {
	s = SMTP{
		Host:         gokit.GetEnv("SMTP_HOST", ""),
		User:         gokit.GetEnv("SMTP_USER", ""),
		Password:     gokit.GetEnv("SMTP_PASS", ""),
		From:         gokit.GetEnv("SMTP_FROM", ""),
		OTPSubject:   gokit.GetEnv("SMTP_SUBJECT", ""),
		ResetSubject: gokit.GetEnv("RESET_SUBJECT", ""),
		AppName:      gokit.GetEnv("AUTH_EMAIL_APP_NAME", ""),
	}
	if raw := gokit.GetEnv("SMTP_PORT", ""); raw != "" {
		if validPort(raw) {
			s.Port, _ = strconv.Atoi(raw)
		} else {
			portInvalid = true
		}
	}
	return s, portInvalid
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
