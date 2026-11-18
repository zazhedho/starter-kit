package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
)

const maxSizeMB = 1024

// FromEnv reads the environment as it is (callers load .env and Consul first).
// Unparseable values fall back to defaults and are reported by Validate.
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
		Location: locationFromEnv(&l),
		Auth:     authkit.ConfigFromEnv(),
	}

	cfg.Media, cfg.Storage = mediaFromEnv(&l)

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

// loader reads variables that take Go durations; anything unparsable is
// recorded for Validate instead of being dropped silently.
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

// megabytes reads whole megabytes and returns bytes. It range-checks before
// shifting so huge values cannot wrap; invalid values are recorded and the default is used.
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

// smtpFromEnv reads the SMTP settings; unset values stay empty so the mailer
// applies its defaults. A non-numeric port is reported via portInvalid.
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
// integer, which Validate reports.
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
