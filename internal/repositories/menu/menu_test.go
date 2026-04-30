package repositorymenu

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

func TestMenuRepositoryDryRun(t *testing.T) {
	repo := NewMenuRepo(newDryRunDB(t))
	ctx := context.Background()

	if _, err := repo.GetByName(ctx, "dashboard"); err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if _, _, err := repo.GetAll(ctx, filter.BaseParams{
		Search:         "dash",
		Filters:        map[string]interface{}{"name": "dashboard", "is_active": true},
		OrderBy:        "order_index",
		OrderDirection: "ASC",
		Limit:          10,
	}); err != nil {
		t.Fatalf("get all: %v", err)
	}
	if _, err := repo.GetActiveMenus(ctx); err != nil {
		t.Fatalf("get active menus: %v", err)
	}
	if menus, err := repo.GetUserMenus(ctx, "user-1"); err != nil || len(menus) != 0 {
		t.Fatalf("get user menus: menus=%v err=%v", menus, err)
	}
}
