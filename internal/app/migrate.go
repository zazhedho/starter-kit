package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Register the file:// migration source.
	"github.com/zazhedho/logus"
)

// Migrate brings the schema up to date: authkit's tables first, because the
// project's migrations may reference users and roles, then the project's own
// migrations from the configured path.
func (a *App) Migrate(ctx context.Context) error {
	if a.migrate != nil {
		return a.migrate(ctx)
	}
	if err := a.kit.Migrate(ctx); err != nil {
		return fmt.Errorf("authkit migrations: %w", err)
	}
	if err := migrateProject(ctx, a.sqlDB, a.cfg.Migrate.Path); err != nil {
		return fmt.Errorf("project migrations: %w", err)
	}
	logus.WriteLog(logus.LogLevelInfo, "Migration Success")
	return nil
}

// migrateProject applies the migrations in sourceURL through the already open
// pool, on one dedicated connection that holds golang-migrate's advisory lock.
// The version table is the default schema_migrations. The pool itself is never
// closed; the connection goes back to it on every path. Errors never carry the
// connection settings, because none are built here.
func migrateProject(ctx context.Context, db *sql.DB, sourceURL string) error {
	src, err := source.Open(sourceURL)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	drv, err := postgres.WithConnection(ctx, conn, &postgres.Config{})
	if err != nil {
		_ = src.Close()
		return fmt.Errorf("open driver: %w", err)
	}
	m, err := migrate.NewWithInstance("file", src, "postgres", drv)
	if err != nil {
		_ = src.Close()
		_ = drv.Close()
		return fmt.Errorf("create migrator: %w", err)
	}
	// Close releases the source and the driver; the driver hands the
	// connection back instead of closing it.
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply: %w", err)
	}
	return nil
}
