package database

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/zazhedho/logus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/internal/config"
)

// Open connects to PostgreSQL with the given settings and applies the pool
// limits. It never logs or returns the DSN or the password.
func Open(cfg config.Database, timezone string) (*gorm.DB, *sql.DB, error) {
	dsn := cfg.DSN(timezone)
	logus.WriteLog(logus.LogLevelDebug, "database.Open; initialize db connection")

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})
	if err != nil {
		err = redacted(err, dsn, cfg.URL, cfg.Password)
		logus.WriteLog(logus.LogLevelError, "database.Open; "+err.Error())
		return nil, nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		err = redacted(err, dsn, cfg.URL, cfg.Password)
		logus.WriteLog(logus.LogLevelError, "database.Open; sql.DB; "+err.Error())
		return nil, nil, err
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return db, sqlDB, nil
}

// redacted returns an error with the same text minus every secret in it.
func redacted(err error, secrets ...string) error {
	msg := err.Error()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return errors.New(msg)
}
