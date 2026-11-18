package database

import (
	"database/sql"
	"errors"
	"net"
	"net/url"
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

// Open connects to PostgreSQL and applies the pool limits. pgx parses the DSN,
// and its errors can quote it, so they are never returned or logged: failures
// map to a fixed message.
func Open(cfg config.Database, timezone string) (*gorm.DB, *sql.DB, error) {
	logus.WriteLog(logus.LogLevelDebug, "database.Open; initialize db connection")

	connCfg, err := pgx.ParseConfig(cfg.DSN(timezone))
	if err != nil {
		return nil, nil, failed("connect to database: "+classify(err), "database.Open; ")
	}
	connCfg.RuntimeParams = sessionParams(connCfg.RuntimeParams, timezone, cfg.URL != "" && urlNamesTimeZone(cfg.URL))

	return attach(stdlib.OpenDB(*connCfg), cfg)
}

// attach wraps an existing pool in gorm, checks the connection, and applies
// the pool limits. On failure the pool is closed and only an error returned.
func attach(sqlDB *sql.DB, cfg config.Database) (*gorm.DB, *sql.DB, error) {
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		TranslateError: true,
		// Silent during the connection check: gorm would print the raw driver
		// error, DSN included, before we see it. The real logger is set below.
		Logger: gormlogger.Discard,
	})
	if err != nil {
		// gorm closes the pool when its own check fails; closing again is
		// harmless and keeps this guarantee independent of gorm's internals.
		_ = sqlDB.Close()
		return nil, nil, failed("connect to database: "+classify(err), "database.Open; ")
	}

	db.Logger = newQueryLogger()

	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return db, sqlDB, nil
}

// sessionParams applies the configured time zone, except when DATABASE_URL
// itself sets one (zoneInURL). Otherwise it replaces any zone already present,
// such as one merged from PGTZ (names are case-insensitive).
func sessionParams(params map[string]string, timezone string, zoneInURL bool) map[string]string {
	out := make(map[string]string, len(params)+1)
	for k, v := range params {
		if strings.EqualFold(k, "timezone") {
			if zoneInURL {
				out[k] = v
			}
			continue
		}
		out[k] = v
	}
	for k := range out {
		if strings.EqualFold(k, "timezone") {
			return out
		}
	}
	out["TimeZone"] = timezone
	return out
}

// urlNamesTimeZone reports whether the DATABASE_URL text itself sets a time zone
// (query parameter or keyword); environment-derived settings do not count.
func urlNamesTimeZone(raw string) bool {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && strings.Contains(raw, "://") {
		for k := range u.Query() {
			if strings.EqualFold(k, "timezone") {
				return true
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(raw), "timezone=")
}

func failed(msg, logPrefix string) error {
	logus.WriteLog(logus.LogLevelError, logPrefix+msg)
	return errors.New(msg)
}

// classify names the failure kind without any driver text: configuration (server
// refused) versus network (no answer).
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
