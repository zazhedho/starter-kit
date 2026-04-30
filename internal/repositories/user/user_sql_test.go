package repositoryuser

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/pkg/filter"
)

func newDryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	sqlDB, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DryRun:                 true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db
}

func TestUserRepositoryDryRun(t *testing.T) {
	repo := NewUserRepo(newDryRunDB(t))
	ctx := context.Background()

	if _, err := repo.GetByEmail(ctx, "jane@example.com"); err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if _, err := repo.GetByPhone(ctx, "08123456789"); err != nil {
		t.Fatalf("get by phone: %v", err)
	}
	if _, _, err := repo.GetAll(ctx, filter.BaseParams{
		Search:         "jane",
		Filters:        map[string]interface{}{"role": "admin", "email": "jane@example.com"},
		OrderBy:        "email",
		OrderDirection: "ASC",
		Limit:          10,
	}); err != nil {
		t.Fatalf("get all: %v", err)
	}
}
