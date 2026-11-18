package media

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	domainmedia "starter-kit/internal/domain/media"
)

func newMockRepo(t *testing.T) (*gorm.DB, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db, mock
}

func TestMediaRepositoryGetByIDTranslatesNotFound(t *testing.T) {
	db, mock := newMockRepo(t)
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id"}))

	_, err := NewRepository(db).GetByID(context.Background(), "missing")
	if !errors.Is(err, domainmedia.ErrNotFound) {
		t.Fatalf("expected domainmedia.ErrNotFound, got %v", err)
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("gorm error must not leak: %v", err)
	}
}

func TestMediaRepositoryGetByIDKeepsOtherErrors(t *testing.T) {
	db, mock := newMockRepo(t)
	boom := errors.New("connection reset")
	mock.ExpectQuery("SELECT").WillReturnError(boom)

	_, err := NewRepository(db).GetByID(context.Background(), "id-1")
	if !errors.Is(err, boom) || errors.Is(err, domainmedia.ErrNotFound) {
		t.Fatalf("expected the original error, got %v", err)
	}
}
