package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// newExecDB returns a gorm database that really sends statements to sqlmock.
func newExecDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db, mock
}

func TestRegisterLocationRecoversInterruptedJobs(t *testing.T) {
	d := newTestDeps(t, nil)
	db, mock := newExecDB(t)
	d.DB = db
	mock.ExpectExec("UPDATE .location_sync_jobs. SET").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := registerLocation(gin.New(), d); err != nil {
		t.Fatalf("registerLocation: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("interrupted jobs were not recovered by the registrar: %v", err)
	}
}

func TestRegisterLocationReturnsTheRecoveryError(t *testing.T) {
	d := newTestDeps(t, nil)
	db, mock := newExecDB(t)
	d.DB = db
	boom := errors.New("database down")
	mock.ExpectExec("UPDATE .location_sync_jobs. SET").WillReturnError(boom)

	if err := registerLocation(gin.New(), d); !errors.Is(err, boom) {
		t.Fatalf("registerLocation = %v, want it to wrap the recovery error", err)
	}
}

func TestRegisterLocationBoundsStartupRecovery(t *testing.T) {
	old := recoveryTimeout
	recoveryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { recoveryTimeout = old })

	d := newTestDeps(t, nil)
	db, mock := newExecDB(t)
	d.DB = db
	mock.ExpectExec("UPDATE .location_sync_jobs. SET").WillDelayFor(time.Hour).WillReturnResult(sqlmock.NewResult(0, 1))

	done := make(chan error, 1)
	go func() { done <- registerLocation(gin.New(), d) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("registerLocation succeeded although recovery did not finish")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hanging recovery was not bounded")
	}
}

func TestRegisterLocationRegistersAShutdownHook(t *testing.T) {
	d := newTestDeps(t, nil)
	if err := registerLocation(gin.New(), d); err != nil {
		t.Fatalf("registerLocation: %v", err)
	}
	if got := d.Lifecycle.Len(); got != 1 {
		t.Fatalf("registerLocation registered %d shutdown hooks, want 1", got)
	}
	if err := d.Lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("Lifecycle.Close = %v", err)
	}
}
