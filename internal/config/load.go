package config

import (
	"time"

	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
)

const maxSizeMB = 1024

func FromEnv() Config {
	cfg := Config{
		App: App{
			Name:     gokit.GetEnv("APP_NAME", ""),
			Env:      gokit.GetEnv("APP_ENV", ""),
			Port:     gokit.GetEnv("PORT", ""),
			Timezone: gokit.GetEnv("APP_TIMEZONE", "Asia/Jakarta"),
		},
		HTTP: HTTP{
			ReadHeaderTimeout: gokit.GetEnv("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
			ReadTimeout:       gokit.GetEnv("HTTP_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:      gokit.GetEnv("HTTP_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:       gokit.GetEnv("HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout:   gokit.GetEnv("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
			ShutdownDelay:     gokit.GetEnv("HTTP_SHUTDOWN_DELAY", 5*time.Second),
			MaxBodyBytes:      megabytes("HTTP_MAX_BODY_MB", 10),
			TrustedProxies:    gokit.GetEnv("TRUSTED_PROXIES", []string(nil)),
		},
		Database: Database{
			URL:             gokit.GetEnv("DATABASE_URL", ""),
			Host:            gokit.GetEnv("DB_HOST", ""),
			Port:            gokit.GetEnv("DB_PORT", ""),
			Username:        gokit.GetEnv("DB_USERNAME", ""),
			Password:        gokit.GetEnv("DB_PASS", ""),
			Name:            gokit.GetEnv("DB_NAME", ""),
			SSLMode:         gokit.GetEnv("DB_SSLMODE", "disable"),
			MaxOpenConns:    gokit.GetEnv("DB_MAX_OPEN_CONNS", 100),
			MaxIdleConns:    gokit.GetEnv("DB_MAX_IDLE_CONNS", 10),
			ConnMaxLifetime: gokit.GetEnv("DB_CONN_MAX_LIFETIME", time.Hour),
			ConnMaxIdleTime: gokit.GetEnv("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
		},
		Migrate: Migrate{
			Run:  gokit.GetEnv("RUN_MIGRATION", true),
			Path: gokit.GetEnv("PATH_MIGRATE", "file://migrations"),
		},
		Location: locationFromEnv(),
	}
	cfg.Auth, cfg.authErr = authkit.ConfigFromEnv()

	cfg.Media, cfg.Storage = mediaFromEnv()

	cfg.Redis = Redis{
		URL:      gokit.GetEnv("REDIS_URL", ""),
		Host:     gokit.GetEnv("REDIS_HOST", ""),
		Port:     gokit.GetEnv("REDIS_PORT", "6379"),
		Password: gokit.GetEnv("REDIS_PASSWORD", ""),
		DB:       gokit.GetEnv("REDIS_DB", 0),
	}

	cfg.SMTP = SMTP{
		Host:         gokit.GetEnv("SMTP_HOST", ""),
		Port:         gokit.GetEnv("SMTP_PORT", 0),
		User:         gokit.GetEnv("SMTP_USER", ""),
		Password:     gokit.GetEnv("SMTP_PASS", ""),
		From:         gokit.GetEnv("SMTP_FROM", ""),
		OTPSubject:   gokit.GetEnv("SMTP_SUBJECT", ""),
		ResetSubject: gokit.GetEnv("RESET_SUBJECT", ""),
		AppName:      gokit.GetEnv("AUTH_EMAIL_APP_NAME", ""),
	}

	return cfg
}

func megabytes(key string, def int) int64 {
	n := gokit.GetEnv(key, def)
	if n < 1 || n > maxSizeMB {
		return 0
	}
	return int64(n) << 20
}
