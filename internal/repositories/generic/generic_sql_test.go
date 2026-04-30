package repositorygeneric

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"starter-kit/pkg/filter"
)

type sampleRecord struct {
	ID     string `gorm:"column:id;primaryKey"`
	Name   string `gorm:"column:name"`
	Status string `gorm:"column:status"`
}

func (sampleRecord) TableName() string {
	return "sample_records"
}

func newDryRunDB(t *testing.T) *gorm.DB {
	t.Helper()

	sqlDB, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	db, err := gorm.Open(postgres.New(postgres.Config{
		Conn:                 sqlDB,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		DryRun:                 true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}

	return db
}

func TestGenericRepositoryDryRunCRUDMethods(t *testing.T) {
	repo := New[sampleRecord](newDryRunDB(t))
	ctx := context.Background()
	record := sampleRecord{ID: "record-1", Name: "Jane", Status: "active"}

	if err := repo.Store(ctx, record); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := repo.GetByID(ctx, "record-1"); err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if _, err := repo.GetOneByField(ctx, "name", "Jane"); err != nil {
		t.Fatalf("get one by field: %v", err)
	}
	if _, err := repo.GetManyByField(ctx, "status", "active"); err != nil {
		t.Fatalf("get many by field: %v", err)
	}
	if exists, err := repo.ExistsByField(ctx, "status", "active"); err != nil || exists {
		t.Fatalf("exists by field: exists=%v err=%v", exists, err)
	}
	if exists, err := repo.ExistsByFields(ctx, map[string]interface{}{"status": "active", "name": "Jane"}); err != nil || exists {
		t.Fatalf("exists by fields: exists=%v err=%v", exists, err)
	}
	if err := repo.Update(ctx, record); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := repo.Delete(ctx, "record-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestGenericRepositoryGetAllDryRunAppliesQueryOptions(t *testing.T) {
	repo := New[sampleRecord](newDryRunDB(t))
	params := filter.BaseParams{
		Search:         "jane",
		Filters:        map[string]interface{}{"status": "active", "ignored": "x"},
		OrderBy:        "name",
		OrderDirection: "DESC",
		Limit:          10,
		Offset:         5,
	}

	ret, total, err := repo.GetAll(context.Background(), params, QueryOptions{
		BaseQuery: func(query *gorm.DB) *gorm.DB {
			return query.Where("deleted_at IS NULL")
		},
		Search:              BuildSearchFunc("name", "status"),
		AllowedFilters:      []string{"status"},
		AllowedOrderColumns: []string{"name", "status"},
	})
	if err != nil {
		t.Fatalf("get all: %v", err)
	}
	_ = ret
	if total != 0 {
		t.Fatalf("expected dry-run total to remain zero, got %d", total)
	}
}

func TestGenericRepositoryGetAllRejectsInvalidOrdering(t *testing.T) {
	repo := New[sampleRecord](newDryRunDB(t))

	_, _, err := repo.GetAll(context.Background(), filter.BaseParams{
		OrderBy:        "unsafe_column",
		OrderDirection: "ASC",
	}, QueryOptions{
		AllowedOrderColumns: []string{"name"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid orderBy column") {
		t.Fatalf("expected invalid order error, got %v", err)
	}
}

func TestBuildSearchFuncAndFilteringBranches(t *testing.T) {
	db := newDryRunDB(t).Model(&sampleRecord{})

	query := BuildSearchFunc("name", "status")(db, "Jane")
	var rows []sampleRecord
	query.Find(&rows)
	if sql := query.Statement.SQL.String(); !strings.Contains(sql, "LOWER(name)") {
		t.Fatalf("expected search SQL to include name column, got %q", sql)
	}

	query = applyFilters(db, map[string]interface{}{
		"name":   "Jane",
		"status": []string{"active", "pending"},
		"empty":  " ",
		"nil":    nil,
	}, QueryOptions{
		AllowedFilters: []string{"name", "status", "empty", "nil"},
	})
	if query == nil {
		t.Fatal("expected filtered query")
	}

	ordered, err := applyOrdering(db, filter.BaseParams{}, QueryOptions{DefaultOrders: []string{"name ASC", "status DESC"}})
	if err != nil || ordered == nil {
		t.Fatalf("default ordering: query=%v err=%v", ordered, err)
	}

	if got := BuildSearchFunc()(db, "Jane"); got != db {
		t.Fatal("expected empty search columns to return original query")
	}
}
