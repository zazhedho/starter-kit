package database

import (
	"database/sql"
	"errors"
	"net"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/zazhedho/logus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"starter-kit/internal/config"
)

// Open connects to PostgreSQL with the given settings and applies the pool
// limits. The connection string is parsed by pgx itself and the session time
// zone is set on the parsed configuration, so neither gorm's driver nor a
// regular expression ever reads the DSN text. The driver's error text can
// quote the DSN, so it is never returned, logged, or printed by gorm: a
// failure is reported as a fixed message that names only the kind of problem.
func Open(cfg config.Database, timezone string) (*gorm.DB, *sql.DB, error) {
	logus.WriteLog(logus.LogLevelDebug, "database.Open; initialize db connection")

	connCfg, err := pgx.ParseConfig(cfg.DSN(timezone))
	if err != nil {
		return nil, nil, failed("connect to database: "+classify(err), "database.Open; ")
	}
	// A time zone written in DATABASE_URL is the operator's choice; otherwise
	// the session uses the configured one.
	if !hasTimeZone(connCfg.RuntimeParams) {
		connCfg.RuntimeParams["TimeZone"] = timezone
	}

	sqlDB := stdlib.OpenDB(*connCfg)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		TranslateError: true,
		// gorm would print the raw driver error, DSN included, before we see it.
		Logger: gormlogger.Discard,
	})
	if err != nil {
		return nil, nil, failed("connect to database: "+classify(err), "database.Open; ")
	}

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return db, sqlDB, nil
}

// hasTimeZone reports whether the parsed settings already name a session time
// zone (PostgreSQL parameter names are case-insensitive).
func hasTimeZone(params map[string]string) bool {
	for k := range params {
		if strings.EqualFold(k, "timezone") {
			return true
		}
	}
	return false
}

// failed logs msg and returns it as an error.
func failed(msg, logPrefix string) error {
	logus.WriteLog(logus.LogLevelError, logPrefix+msg)
	return errors.New(msg)
}

// classify names the kind of connection failure without using any of the
// driver's text, so an operator can tell a configuration problem (the server
// answered and refused) from a network one (it never answered).
func classify(err error) string {
	var parseErr *pgconn.ParseConfigError
	var pgErr *pgconn.PgError
	var netErr net.Error
	switch {
	case errors.As(err, &parseErr):
		return "invalid configuration"
	case errors.As(err, &pgErr) && (pgErr.Code == "28P01" || pgErr.Code == "28000"):
		return "authentication failed"
	case errors.As(err, &pgErr):
		return "server rejected the connection parameters"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	default:
		return "unreachable"
	}
}
