package location

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func TestGetProvinceMapsRepositoryRows(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{
		provinces: []domainlocation.Province{
			{Code: "11", Name: "Aceh"},
			{Code: "12", Name: "Sumatera Utara"},
		},
	}, Options{})

	got, err := svc.GetProvince(context.Background())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	want := []dtolocation.Location{{Code: "11", Name: "Aceh"}, {Code: "12", Name: "Sumatera Utara"}}
	if len(got) != len(want) {
		t.Fatalf("expected %d rows, got %+v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}

func TestLocationServiceReadMethodsMapRepositoryRows(t *testing.T) {
	now := time.Now()
	svc := NewService(&locationRepoTestDouble{
		cities:    []domainlocation.City{{Code: "3171", Name: "Jakarta Selatan"}},
		districts: []domainlocation.District{{Code: "317101", Name: "Tebet"}},
		villages:  []domainlocation.Village{{Code: "31710101", Name: "Tebet Barat"}},
		syncJob: domainlocation.SyncJob{
			ID:        "job-1",
			Status:    "done",
			Level:     "province",
			CreatedAt: now,
			UpdatedAt: &now,
		},
	}, Options{})

	if got, err := svc.GetCity(context.Background(), "31"); err != nil || len(got) != 1 || got[0].Code != "3171" {
		t.Fatalf("get city: got=%+v err=%v", got, err)
	}
	if got, err := svc.GetDistrict(context.Background(), "3171"); err != nil || len(got) != 1 || got[0].Code != "317101" {
		t.Fatalf("get district: got=%+v err=%v", got, err)
	}
	if got, err := svc.GetVillage(context.Background(), "317101"); err != nil || len(got) != 1 || got[0].Code != "31710101" {
		t.Fatalf("get village: got=%+v err=%v", got, err)
	}
	if got, err := svc.GetSyncJob(context.Background(), "job-1"); err != nil || got.ID != "job-1" {
		t.Fatalf("get sync job: got=%+v err=%v", got, err)
	}
}

func TestLocationServiceReadMethodsReturnRepositoryErrors(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{listErr: errors.New("database down")}, Options{})
	ctx := context.Background()

	if _, err := svc.GetProvince(ctx); err == nil {
		t.Fatal("expected province error")
	}
	if _, err := svc.GetCity(ctx, "31"); err == nil {
		t.Fatal("expected city error")
	}
	if _, err := svc.GetDistrict(ctx, "3171"); err == nil {
		t.Fatal("expected district error")
	}
	if _, err := svc.GetVillage(ctx, "317101"); err == nil {
		t.Fatal("expected village error")
	}
}

func TestStartSyncRejectsMissingScopedCodes(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}, Options{})

	_, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "city"}, "user-1")
	if err == nil || err.Error() != "province_code is required for city sync" {
		t.Fatalf("expected city sync validation error, got %v", err)
	}

	_, err = svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "district", ProvinceCode: "31"}, "user-1")
	if err == nil || err.Error() != "province_code and city_code are required for district sync" {
		t.Fatalf("expected district sync validation error, got %v", err)
	}

	_, err = svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "village", ProvinceCode: "31", CityCode: "3171"}, "user-1")
	if err == nil || err.Error() != "province_code, city_code, and district_code are required for village sync" {
		t.Fatalf("expected village sync validation error, got %v", err)
	}

	_, err = svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "unknown"}, "user-1")
	if err == nil || err.Error() != "invalid sync level" {
		t.Fatalf("expected invalid level error, got %v", err)
	}
	if !errors.Is(err, domainlocation.ErrInvalidSync) {
		t.Fatalf("expected validation errors to match domainlocation.ErrInvalidSync, got %v", err)
	}
	_, err = svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "city"}, "user-1")
	if !errors.Is(err, domainlocation.ErrInvalidSync) {
		t.Fatalf("expected scoped-code error to match domainlocation.ErrInvalidSync, got %v", err)
	}
}

func TestStartSyncReturnsActiveJobWhenAlreadyRunning(t *testing.T) {
	now := time.Now()
	svc := NewService(&locationRepoTestDouble{
		activeJob: domainlocation.SyncJob{
			ID:        "job-1",
			Status:    "running",
			Level:     "all",
			Message:   "running",
			CreatedAt: now,
			UpdatedAt: &now,
		},
	}, Options{})

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "all"}, "user-1")
	if !errors.Is(err, domainlocation.ErrSyncRunning) {
		t.Fatalf("expected domainlocation.ErrSyncRunning, got %v", err)
	}
	if got.ID != "job-1" || got.Status != "running" {
		t.Fatalf("expected active job response, got %+v", got)
	}
}

func TestStartSyncCreatesQueuedJobWithDefaults(t *testing.T) {
	repo := &locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}
	svc := NewService(repo, Options{})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "user-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if got.Status != "queued" || got.Level != "province" {
		t.Fatalf("unexpected job response: %+v", got)
	}
	if repo.createdJob == nil {
		t.Fatal("expected sync job to be created")
	}
	if repo.createdJob.RequestedBy != "user-1" {
		t.Fatalf("expected requested user id, got %+v", repo.createdJob)
	}
}

func TestStartSyncRepositoryErrors(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{activeJobErr: errors.New("database down")}, Options{})
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "all"}, "user-1"); err == nil {
		t.Fatal("expected active job lookup error")
	}

	svc = NewService(&locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound, createSyncJobErr: errors.New("database down")}, Options{})
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "all"}, "user-1"); err == nil {
		t.Fatal("expected create sync job error")
	}
}

func TestStartSyncUsesInjectedIDAndRequester(t *testing.T) {
	repo := &locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}
	svc := NewService(repo, Options{NewID: func() string { return "job-fixed" }})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "user-9")
	if err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	if got.ID != "job-fixed" || repo.createdJob.ID != "job-fixed" || repo.createdJob.RequestedBy != "user-9" {
		t.Fatalf("job = %+v, created = %+v", got, repo.createdJob)
	}
}

// Without an injected generator the service issues UUIDv7 ids, the version
// gokit.CreateUUID produces, so job ids stay time-ordered.
func TestDefaultJobIDIsUUIDv7(t *testing.T) {
	repo := &locationRepoTestDouble{activeJobErr: domainlocation.ErrNotFound}
	svc := NewService(repo, Options{})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "u")
	if err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	if id, err := uuid.Parse(got.ID); err != nil || id.Version() != 7 {
		t.Fatalf("job id %q is not a UUIDv7 (err=%v)", got.ID, err)
	}
}
