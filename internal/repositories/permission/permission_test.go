package repositorypermission

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

func TestPermissionRepositoryDryRun(t *testing.T) {
	repo := NewPermissionRepo(newDryRunDB(t))
	ctx := context.Background()

	if _, err := repo.GetByName(ctx, "users.read"); err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if _, err := repo.GetByResource(ctx, "users"); err != nil {
		t.Fatalf("get by resource: %v", err)
	}
	if _, _, err := repo.GetAll(ctx, filter.BaseParams{
		Search:         "users",
		Filters:        map[string]interface{}{"resource": "users", "action": "read"},
		OrderBy:        "resource",
		OrderDirection: "ASC",
		Limit:          10,
	}); err != nil {
		t.Fatalf("get all: %v", err)
	}
	if permissions, err := repo.GetUserPermissions(ctx, "user-1"); err != nil || len(permissions) != 0 {
		t.Fatalf("get user permissions: permissions=%v err=%v", permissions, err)
	}
}
