package media

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/gorm"

	domainmedia "starter-kit/internal/domain/media"
	dtomedia "starter-kit/internal/dto/media"
	"starter-kit/internal/testutil/routertest"
)

func TestMediaRepositoryGetByIDTranslatesNotFound(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
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
	db, mock := routertest.NewExecDB(t)
	boom := errors.New("connection reset")
	mock.ExpectQuery("SELECT").WillReturnError(boom)

	_, err := NewRepository(db).GetByID(context.Background(), "id-1")
	if !errors.Is(err, boom) || errors.Is(err, domainmedia.ErrNotFound) {
		t.Fatalf("expected the original error, got %v", err)
	}
}

func TestRepositoryStoreInsertsTheMediaRow(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnResult(sqlmock.NewResult(1, 1))

	err := NewRepository(db).Store(context.Background(), &domainmedia.Media{ID: "m-1", OwnerUserID: "u-1", CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("Store = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryStoreReturnsDatabaseErrors(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
	boom := errors.New("insert failed")
	mock.ExpectExec(`INSERT INTO "media"`).WillReturnError(boom)

	if err := NewRepository(db).Store(context.Background(), &domainmedia.Media{ID: "m-1"}); !errors.Is(err, boom) {
		t.Fatalf("Store = %v, want the database error", err)
	}
}

func TestRepositoryGetByIDReturnsTheRow(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
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
	db, mock := routertest.NewExecDB(t)
	mock.ExpectExec(`UPDATE "media" SET "deleted_at"=`).WillReturnResult(sqlmock.NewResult(0, 1))

	if err := NewRepository(db).Delete(context.Background(), "m-1"); err != nil {
		t.Fatalf("Delete = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// gokit answers ErrNotFound when no row matched (a second delete, or a race);
// the repository turns it into the domain error the handler maps to 404.
func TestRepositoryDeleteTranslatesNoMatchToTheDomainError(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
	mock.ExpectExec(`UPDATE "media" SET "deleted_at"=`).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := NewRepository(db).Delete(context.Background(), "m-1"); !errors.Is(err, domainmedia.ErrNotFound) {
		t.Fatalf("Delete = %v, want domainmedia.ErrNotFound", err)
	}
}

func TestRepositoryDeleteReturnsDatabaseErrors(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
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
	db, mock := routertest.NewExecDB(t)
	expectCount(mock, 41)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT * FROM "media" WHERE (LOWER("original_name") LIKE LOWER($1) ESCAPE '\') AND "content_type" = $2 AND "owner_user_id" = $3 AND "media"."deleted_at" IS NULL ORDER BY "size","id" LIMIT $4 OFFSET $5`)).
		WillReturnRows(listRows())

	res, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{
		Search: "cat", OwnerUserID: "u-1", ContentType: "image/png",
		OrderBy: "size", OrderDirection: "asc", Page: 2, Limit: 20,
	})
	if err != nil {
		t.Fatalf("List = %v", err)
	}
	if res.Total != 41 || len(res.Items) != 1 || res.Items[0].ID != "m-1" || res.Limit != 20 {
		t.Fatalf("got %+v", res)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The repository is the one place the page size is capped (gokit's
// QueryOptions.MaxLimit) and it reports the limit it applied.
func TestRepositoryListCapsTheLimitAndReportsIt(t *testing.T) {
	for _, c := range []struct {
		name  string
		limit int
		want  int
	}{
		{"within the cap", 50, 50},
		{"the cap itself", 100, 100},
		{"above the cap", 5000, 100},
		{"minus one is not unbounded", -1, 100},
		{"zero is the cap too", 0, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, mock := routertest.NewExecDB(t)
			expectCount(mock, 500)
			mock.ExpectQuery(`SELECT \* FROM "media" .* LIMIT \$\d+`).
				WithArgs(c.want).
				WillReturnRows(listRows())

			res, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{Page: 1, Limit: c.limit})
			if err != nil {
				t.Fatalf("List = %v", err)
			}
			if res.Limit != c.want {
				t.Fatalf("reported limit = %d, want %d", res.Limit, c.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryListFiltersByOwnerAndContentType(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
	mock.ExpectQuery(`SELECT count\(\*\) FROM "media" WHERE`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT \* FROM "media" WHERE`).WillReturnRows(listRows())

	_, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OwnerUserID: "u-1", ContentType: "image/png", Limit: 20})
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
			db, mock := routertest.NewExecDB(t)
			expectCount(mock, 1)
			mock.ExpectQuery(`ORDER BY "created_at" DESC,"id" DESC LIMIT`).WillReturnRows(listRows())

			if _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OrderBy: orderBy, OrderDirection: "asc", Limit: 20}); err != nil {
				t.Fatalf("List = %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryListFallsBackToDefaultOrderForBadDirection(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
	expectCount(mock, 1)
	mock.ExpectQuery(`ORDER BY "created_at" DESC,"id" DESC LIMIT`).WillReturnRows(listRows())

	if _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OrderBy: "size", OrderDirection: "sideways; DROP", Limit: 20}); err != nil {
		t.Fatalf("List = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryListReturnsDatabaseErrors(t *testing.T) {
	db, mock := routertest.NewExecDB(t)
	boom := errors.New("count failed")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT count(*) FROM "media"`)).WillReturnError(boom)

	if _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{Limit: 20}); !errors.Is(err, boom) {
		t.Fatalf("List = %v, want the database error", err)
	}
}

// The generated ORDER BY is pinned in full: the id tie-breaker keeps pages from
// skipping or repeating rows that share the sort value.
func TestRepositoryListOrderByPinsTheTieBreaker(t *testing.T) {
	cases := []struct {
		name, orderBy, direction, want string
	}{
		{"default", "", "", `ORDER BY "created_at" DESC,"id" DESC LIMIT`},
		{"explicit ascending", "size", "asc", `ORDER BY "size","id" LIMIT`},
		{"explicit descending", "original_name", "DESC", `ORDER BY "original_name" DESC,"id" DESC LIMIT`},
		{"column without direction", "size", "", `ORDER BY "created_at" DESC,"id" DESC LIMIT`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, mock := routertest.NewExecDB(t)
			expectCount(mock, 1)
			mock.ExpectQuery(regexp.QuoteMeta(c.want)).WillReturnRows(listRows())

			if _, err := NewRepository(db).List(context.Background(), dtomedia.ListRequest{OrderBy: c.orderBy, OrderDirection: c.direction, Limit: 20}); err != nil {
				t.Fatalf("List = %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
