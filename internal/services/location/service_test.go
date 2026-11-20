package location

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func TestGetProvinceMapsRepositoryRows(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{
		provinces: []domainlocation.Province{{Code: "11", Name: "Aceh"}, {Code: "12", Name: "Sumatera Utara"}},
	}, nil)

	got, err := svc.GetProvince(context.Background())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	want := []dtolocation.Location{{Code: "11", Name: "Aceh"}, {Code: "12", Name: "Sumatera Utara"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestReadMethodsMapRepositoryRows(t *testing.T) {
	now := time.Now()
	svc := newTestService(t, &locationRepoTestDouble{
		cities:    []domainlocation.City{{Code: "3171", Name: "Jakarta Selatan"}},
		districts: []domainlocation.District{{Code: "317101", Name: "Tebet"}},
		villages:  []domainlocation.Village{{Code: "31710101", Name: "Tebet Barat"}},
		syncJob:   domainlocation.SyncJob{ID: "job-1", Status: "done", Level: "province", CreatedAt: now, UpdatedAt: &now},
	}, nil)
	ctx := context.Background()

	if got, err := svc.GetCity(ctx, "31"); err != nil || len(got) != 1 || got[0].Code != "3171" {
		t.Fatalf("get city: got=%+v err=%v", got, err)
	}
	if got, err := svc.GetDistrict(ctx, "3171"); err != nil || len(got) != 1 || got[0].Code != "317101" {
		t.Fatalf("get district: got=%+v err=%v", got, err)
	}
	if got, err := svc.GetVillage(ctx, "317101"); err != nil || len(got) != 1 || got[0].Code != "31710101" {
		t.Fatalf("get village: got=%+v err=%v", got, err)
	}
	if got, err := svc.GetSyncJob(ctx, "job-1"); err != nil || got.ID != "job-1" {
		t.Fatalf("get sync job: got=%+v err=%v", got, err)
	}
}

func TestReadMethodsReturnRepositoryErrors(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{listErr: errors.New("database down")}, nil)
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

func TestGetSyncJobMapsAMissingRowToErrSyncJobNotFound(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{syncJobErr: domainlocation.ErrNotFound}, nil)
	_, err := svc.GetSyncJob(context.Background(), "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a10")
	if !errors.Is(err, domainlocation.ErrSyncJobNotFound) || !errors.Is(err, domainlocation.ErrNotFound) {
		t.Fatalf("GetSyncJob = %v, want ErrSyncJobNotFound that also matches ErrNotFound", err)
	}
}

func TestStartSyncRejectsMissingScopedCodes(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{}, nil)
	cases := []struct {
		req  dtolocation.SyncRequest
		want string
	}{
		{dtolocation.SyncRequest{Level: "city"}, "province_code is required for city sync"},
		{dtolocation.SyncRequest{Level: "district", ProvinceCode: "31"}, "province_code and city_code are required for district sync"},
		{dtolocation.SyncRequest{Level: "village", ProvinceCode: "31", CityCode: "3171"}, "province_code, city_code, and district_code are required for village sync"},
		{dtolocation.SyncRequest{Level: "unknown"}, "invalid sync level"},
	}
	for _, c := range cases {
		_, err := svc.StartSync(context.Background(), c.req, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99")
		if err == nil || err.Error() != c.want || !errors.Is(err, domainlocation.ErrInvalidSync) {
			t.Fatalf("StartSync(%+v) = %v, want ErrInvalidSync %q", c.req, err, c.want)
		}
	}
}

func TestStartSyncRejectsAMissingOrMalformedRequester(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{}, nil)
	for _, requestedBy := range []string{"", "   ", "user-1"} {
		_, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, requestedBy)
		if !errors.Is(err, domainlocation.ErrInvalidSync) {
			t.Fatalf("StartSync(requestedBy=%q) = %v, want ErrInvalidSync", requestedBy, err)
		}
	}
}

func TestStartSyncRejectsCodesThatAreNotDigits(t *testing.T) {
	long := strings.Repeat("1", 21)
	bad := []dtolocation.SyncRequest{
		{Level: "city", ProvinceCode: "3*"},
		{Level: "city", ProvinceCode: "31?"},
		{Level: "city", ProvinceCode: "[1-9]"},
		{Level: "city", ProvinceCode: "31 "},
		{Level: "city", ProvinceCode: long},
		{Level: "district", ProvinceCode: "31", CityCode: "31*"},
		{Level: "village", ProvinceCode: "31", CityCode: "3171", DistrictCode: "../1"},
		{Level: "province", ProvinceCode: "x"},
	}
	for _, req := range bad {
		repo := &locationRepoTestDouble{}
		svc := newTestService(t, repo, nil)
		_, err := svc.StartSync(context.Background(), req, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99")
		if !errors.Is(err, domainlocation.ErrInvalidCode) {
			t.Fatalf("StartSync(%+v) = %v, want ErrInvalidCode", req, err)
		}
		if repo.createdJob != nil || len(repo.failStale) != 0 {
			t.Fatalf("StartSync(%+v) reached the repository", req)
		}
	}
}

func TestStartSyncReturnsTheActiveJobWhenOneIsAlreadyRunning(t *testing.T) {
	now := time.Now()
	repo := &locationRepoTestDouble{
		createSyncJobErr: domainlocation.ErrSyncRunning,
		activeJob:        domainlocation.SyncJob{ID: "job-1", Status: "running", Level: "all", Message: "running", CreatedAt: now, UpdatedAt: &now},
	}
	svc := newTestService(t, repo, nil)

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "all"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99")
	if !errors.Is(err, domainlocation.ErrSyncRunning) {
		t.Fatalf("expected ErrSyncRunning, got %v", err)
	}
	if got.ID != "job-1" || got.Status != "running" {
		t.Fatalf("expected active job response, got %+v", got)
	}
}

func TestStartSyncCreatesAQueuedJobOwnedByThisInstance(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{InstanceID: "instance-a", StaleAfter: 90 * time.Second, HeartbeatInterval: time.Hour})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got.Status != "queued" || got.Level != "province" {
		t.Fatalf("unexpected job response: %+v", got)
	}
	job := repo.createdJob
	if job == nil || job.RequestedBy != "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99" || job.OwnerInstanceID != "instance-a" || !job.HeartbeatAt.IsZero() {
		t.Fatalf("created job = %+v, want owner instance-a, the requester and a heartbeat left to the database", job)
	}
	if len(repo.failStale) != 1 {
		t.Fatalf("stale jobs were failed %d times, want once", len(repo.failStale))
	}
	if repo.failStale[0] != 90*time.Second {
		t.Fatalf("repository was told %v, want StaleAfter (90s)", repo.failStale[0])
	}
}

func TestStartSyncRepositoryErrors(t *testing.T) {
	boom := errors.New("database down")
	svc := newTestService(t, &locationRepoTestDouble{failStaleErr: boom}, nil)
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "all"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); !errors.Is(err, boom) {
		t.Fatalf("StartSync = %v, want the stale-job error", err)
	}

	svc = newTestService(t, &locationRepoTestDouble{createSyncJobErr: boom}, nil)
	if _, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "all"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99"); !errors.Is(err, boom) {
		t.Fatalf("StartSync = %v, want the create error", err)
	}
}

func TestStartSyncUsesInjectedIDAndRequester(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{NewID: func() string { return "job-fixed" }, HeartbeatInterval: time.Hour})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99")
	if err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	if got.ID != "job-fixed" || repo.createdJob.ID != "job-fixed" || repo.createdJob.RequestedBy != "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99" {
		t.Fatalf("job = %+v, created = %+v", got, repo.createdJob)
	}
}

func TestDefaultJobIDIsUUIDv7(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := newTestService(t, repo, nil)

	got, err := svc.StartSync(context.Background(), dtolocation.SyncRequest{Level: "province"}, "2d5ea3a8-1e0f-4b8c-8f0e-1b6f5c1b2a99")
	if err != nil {
		t.Fatalf("StartSync = %v", err)
	}
	if id, err := uuid.Parse(got.ID); err != nil || id.Version() != 7 {
		t.Fatalf("job id %q is not a UUIDv7 (err=%v)", got.ID, err)
	}
}

func TestEachServiceInstanceHasItsOwnID(t *testing.T) {
	a := NewService(&locationRepoTestDouble{}, Options{})
	b := NewService(&locationRepoTestDouble{}, Options{})
	t.Cleanup(func() { _ = a.Close(context.Background()); _ = b.Close(context.Background()) })
	if a.instanceID == "" || a.instanceID == b.instanceID {
		t.Fatalf("instance ids %q and %q must be set and distinct", a.instanceID, b.instanceID)
	}
}
