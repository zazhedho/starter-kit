package media

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
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

func TestRepositoryStoreInsertsTheMediaRow(t *testing.T) {
	db, mock := newMockRepo(t)
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))

	err := NewRepository(db).Store(context.Background(), domainmedia.Media{ID: "m-1", OwnerUserID: "u-1", CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Store = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryStoreReturnsDatabaseErrors(t *testing.T) {
	db, mock := newMockRepo(t)
	boom := errors.New("insert failed")
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnError(boom)

	if err := NewRepository(db).Store(context.Background(), domainmedia.Media{ID: "m-1"}); !errors.Is(err, boom) {
		t.Fatalf("Store = %v, want the database error", err)
	}
}

func TestRepositoryGetByIDReturnsTheRow(t *testing.T) {
	db, mock := newMockRepo(t)
	mock.ExpectQuery(`SELECT .* FROM "media"`).WillReturnRows(
		sqlmock.NewRows([]string{"id", "owner_user_id", "url"}).AddRow("m-1", "u-1", "https://cdn/x.png"))

	got, err := NewRepository(db).GetByID(context.Background(), "m-1")
	if err != nil {
		t.Fatalf("GetByID = %v", err)
	}
	if got.ID != "m-1" || got.OwnerUserID != "u-1" || got.URL != "https://cdn/x.png" {
		t.Fatalf("unexpected row %+v", got)
	}
}

// Deleting is a soft delete: the row is updated, not removed, so audit
// references stay valid.
func TestRepositoryDeleteSoftDeletesTheRow(t *testing.T) {
	db, mock := newMockRepo(t)
	mock.ExpectExec(`UPDATE "media" SET "deleted_at"=`).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := NewRepository(db).Delete(context.Background(), "m-1"); err != nil {
		t.Fatalf("Delete = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryDeleteReturnsDatabaseErrors(t *testing.T) {
	db, mock := newMockRepo(t)
	boom := errors.New("update failed")
	mock.ExpectExec(`UPDATE "media"`).WillReturnError(boom)

	if err := NewRepository(db).Delete(context.Background(), "m-1"); !errors.Is(err, boom) {
		t.Fatalf("Delete = %v, want the database error", err)
	}
}

func listRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "owner_user_id", "original_name"}).AddRow("m-1", "u-1", "cat.png")
}

func expectCount(mock sqlmock.Sqlmock, total int) {
	mock.ExpectQuery(`SELECT count\(\*\) FROM "media"`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(total))
}

func TestRepositoryListAppliesSearchFiltersAndOrder(t *testing.T) {
	db, mock := newMockRepo(t)
	expectCount(mock, 41)
	mock.ExpectQuery(`SELECT \* FROM "media" WHERE .*LOWER\(original_name\) LIKE LOWER\(.*owner_user_id = .*"media"."deleted_at" IS NULL ORDER BY size ASC LIMIT .* OFFSET`).
		WillReturnRows(listRows())

	items, total, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{
		Search: "cat", OwnerUserID: "u-1", ContentType: "image/png",
		OrderBy: "size", OrderDirection: "asc", Page: 2, Limit: 20, Offset: 20,
	})
	if err != nil {
		t.Fatalf("List = %v", err)
	}
	if total != 41 || len(items) != 1 || items[0].ID != "m-1" {
		t.Fatalf("got total=%d items=%+v", total, items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryListFiltersByOwnerAndContentType(t *testing.T) {
	db, mock := newMockRepo(t)
	mock.ExpectQuery(`SELECT count\(\*\) FROM "media" WHERE`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT \* FROM "media" WHERE`).WillReturnRows(listRows())

	_, _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OwnerUserID: "u-1", ContentType: "image/png", Limit: 20})
	if err != nil {
		t.Fatalf("List = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryListFallsBackToDefaultOrderForDisallowedColumn(t *testing.T) {
	for _, orderBy := range []string{"object_key", "url", "size; DROP TABLE media", "owner_user_id"} {
		t.Run(orderBy, func(t *testing.T) {
			db, mock := newMockRepo(t)
			expectCount(mock, 1)
			mock.ExpectQuery(`ORDER BY created_at DESC LIMIT`).WillReturnRows(listRows())

			if _, _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OrderBy: orderBy, OrderDirection: "asc", Limit: 20}); err != nil {
				t.Fatalf("List = %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryListFallsBackToDefaultOrderForBadDirection(t *testing.T) {
	db, mock := newMockRepo(t)
	expectCount(mock, 1)
	mock.ExpectQuery(`ORDER BY created_at DESC LIMIT`).WillReturnRows(listRows())

	if _, _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OrderBy: "size", OrderDirection: "sideways; DROP", Limit: 20}); err != nil {
		t.Fatalf("List = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryListReturnsDatabaseErrors(t *testing.T) {
	db, mock := newMockRepo(t)
	boom := errors.New("count failed")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "media"`)).WillReturnError(boom)

	if _, _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{Limit: 20}); !errors.Is(err, boom) {
		t.Fatalf("List = %v, want the database error", err)
	}
}
