package repositoryrole

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

func TestRoleRepositoryDryRun(t *testing.T) {
	repo := NewRoleRepo(newDryRunDB(t))
	ctx := context.Background()

	if _, err := repo.GetByName(ctx, "admin"); err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if _, _, err := repo.GetAll(ctx, filter.BaseParams{
		Search:         "admin",
		Filters:        map[string]interface{}{"name": "admin", "is_system": false},
		OrderBy:        "name",
		OrderDirection: "ASC",
		Limit:          10,
	}); err != nil {
		t.Fatalf("get all: %v", err)
	}
	if ids, err := repo.GetRolePermissions(ctx, "role-1"); err != nil || len(ids) != 0 {
		t.Fatalf("get role permissions: ids=%v err=%v", ids, err)
	}
	if ids, err := repo.GetRoleMenus(ctx, "role-1"); err != nil || len(ids) != 0 {
		t.Fatalf("get role menus: ids=%v err=%v", ids, err)
	}
}
