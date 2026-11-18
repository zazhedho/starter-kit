package location

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	domainlocation "starter-kit/internal/domain/location"
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

func TestLocationRepositoryDryRunReads(t *testing.T) {
	repo := NewRepository(newDryRunDB(t))
	ctx := context.Background()

	if _, err := repo.ListProvinces(ctx); err != nil {
		t.Fatalf("list provinces: %v", err)
	}
	if _, err := repo.ListCitiesByProvince(ctx, "31"); err != nil {
		t.Fatalf("list cities: %v", err)
	}
	if _, err := repo.ListDistrictsByCity(ctx, "3171"); err != nil {
		t.Fatalf("list districts: %v", err)
	}
	if _, err := repo.ListVillagesByDistrict(ctx, "317101"); err != nil {
		t.Fatalf("list villages: %v", err)
	}
	if _, err := repo.GetProvinceByCode(ctx, "31"); err != nil {
		t.Fatalf("get province: %v", err)
	}
	if _, err := repo.GetCityByCode(ctx, "3171"); err != nil {
		t.Fatalf("get city: %v", err)
	}
	if _, err := repo.GetDistrictByCode(ctx, "317101"); err != nil {
		t.Fatalf("get district: %v", err)
	}
}

func TestLocationRepositoryDryRunUpserts(t *testing.T) {
	repo := NewRepository(newDryRunDB(t))
	ctx := context.Background()
	if err := repo.UpsertProvinces(ctx, []domainlocation.Province{{Code: "31", Name: "DKI Jakarta"}}); err != nil {
		t.Fatalf("upsert provinces: %v", err)
	}
	if err := repo.UpsertCities(ctx, []domainlocation.City{{Code: "3171", ProvinceCode: "31", Name: "Jakarta Selatan"}}); err != nil {
		t.Fatalf("upsert cities: %v", err)
	}
	if err := repo.UpsertDistricts(ctx, []domainlocation.District{{Code: "317101", CityCode: "3171", Name: "Tebet"}}); err != nil {
		t.Fatalf("upsert districts: %v", err)
	}
	if err := repo.UpsertVillages(ctx, []domainlocation.Village{{Code: "31710101", DistrictCode: "317101", Name: "Tebet Barat"}}); err != nil {
		t.Fatalf("upsert villages: %v", err)
	}
}

func TestLocationRepositoryDryRunSyncJobs(t *testing.T) {
	repo := NewRepository(newDryRunDB(t))
	ctx := context.Background()
	job := &domainlocation.SyncJob{ID: "job-1", Status: "queued"}
	if err := repo.CreateSyncJob(ctx, job); err != nil {
		t.Fatalf("create sync job: %v", err)
	}
	if err := repo.UpdateSyncJob(ctx, job); err != nil {
		t.Fatalf("update sync job: %v", err)
	}
	if _, err := repo.GetSyncJobByID(ctx, "job-1"); err != nil {
		t.Fatalf("get sync job: %v", err)
	}
	if _, err := repo.GetActiveSyncJob(ctx); err != nil {
		t.Fatalf("get active sync job: %v", err)
	}
	if err := repo.FailActiveSyncJobs(ctx, "stopped"); err != nil {
		t.Fatalf("fail active sync jobs: %v", err)
	}
}

func TestLocationRepositoryUpsertIgnoresUnknownType(t *testing.T) {
	repo := NewRepository(newDryRunDB(t))
	if err := repo.upsert(context.Background(), "code", []string{"unsupported"}); err != nil {
		t.Fatalf("unsupported upsert should be ignored: %v", err)
	}
}

func newNoRowsRepo(t *testing.T) (*gorm.DB, sqlmock.Sqlmock) {
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

func TestLocationRepositoryTranslatesNotFound(t *testing.T) {
	ctx := context.Background()
	lookups := map[string]func(r *Repository) error{
		"province": func(r *Repository) error {
			_, err := r.GetProvinceByCode(ctx, "99")
			return err
		},
		"city": func(r *Repository) error {
			_, err := r.GetCityByCode(ctx, "9999")
			return err
		},
		"district": func(r *Repository) error {
			_, err := r.GetDistrictByCode(ctx, "999999")
			return err
		},
		"job": func(r *Repository) error {
			_, err := r.GetSyncJobByID(ctx, "missing")
			return err
		},
		"active": func(r *Repository) error { _, err := r.GetActiveSyncJob(ctx); return err },
	}
	for name, lookup := range lookups {
		t.Run(name, func(t *testing.T) {
			db, mock := newNoRowsRepo(t)
			mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id"}))
			err := lookup(NewRepository(db))
			if !errors.Is(err, domainlocation.ErrNotFound) {
				t.Fatalf("expected domainlocation.ErrNotFound, got %v", err)
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("gorm error must not leak: %v", err)
			}
		})
	}
}

func TestLocationRepositoryKeepsOtherErrors(t *testing.T) {
	db, mock := newNoRowsRepo(t)
	boom := errors.New("connection reset")
	mock.ExpectQuery("SELECT").WillReturnError(boom)
	_, err := NewRepository(db).GetProvinceByCode(context.Background(), "31")
	if !errors.Is(err, boom) || errors.Is(err, domainlocation.ErrNotFound) {
		t.Fatalf("expected the original error, got %v", err)
	}
}
