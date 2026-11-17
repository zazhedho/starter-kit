package database

import (
	"database/sql"
	"errors"
	"net"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zazhedho/logus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"starter-kit/internal/config"
)

// Open connects to PostgreSQL with the given settings and applies the pool
// limits. The driver's error text can quote the DSN, so it is never returned,
// logged, or printed by gorm: a failure is reported as a fixed message that
// names only the kind of problem.
func Open(cfg config.Database, timezone string) (*gorm.DB, *sql.DB, error) {
	logus.WriteLog(logus.LogLevelDebug, "database.Open; initialize db connection")

	db, err := gorm.Open(postgres.Open(cfg.DSN(timezone)), &gorm.Config{
		TranslateError: true,
		// gorm would print the raw driver error, DSN included, before we see it.
		Logger: gormlogger.Discard,
	})
	if err != nil {
		return nil, nil, failed("connect to database: "+classify(err), "database.Open; ")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, nil, failed("obtain database handle", "database.Open; ")
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return db, sqlDB, nil
}

// failed logs msg and returns it as an error.
func failed(msg, logPrefix string) error {
	logus.WriteLog(logus.LogLevelError, logPrefix+msg)
	return errors.New(msg)
}

// classify names the kind of connection failure without using any of the
// driver's text.
func classify(err error) string {
	var parseErr *pgconn.ParseConfigError
	var pgErr *pgconn.PgError
	var netErr net.Error
	switch {
	case errors.As(err, &parseErr):
		return "invalid configuration"
	case errors.As(err, &pgErr) && (pgErr.Code == "28P01" || pgErr.Code == "28000"):
		return "authentication failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	default:
		return "unavailable"
	}
}
