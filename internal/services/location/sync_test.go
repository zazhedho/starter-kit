package location

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func TestSyncAll(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := newScopedSync(t, repo)
	var reports int
	result, err := svc.sync(context.Background(), dtolocation.SyncRequest{Level: "all"}, func(domainlocation.SyncProgress) { reports++ })
	if err != nil {
		t.Fatalf("sync all: %v", err)
	}
	if result.ProvinceCount != 1 || result.CityCount != 1 || result.DistrictCount != 1 || result.VillageCount != 1 || result.Message != "Full location sync completed" {
		t.Fatalf("unexpected sync result: %+v", result)
	}
	if reports == 0 {
		t.Fatal("expected progress reports")
	}
	if repo.upsertProvinceCount != 1 || repo.upsertCityCount != 1 || repo.upsertDistrictCount != 1 || repo.upsertVillageCount != 1 {
		t.Fatalf("expected all upserts, repo=%+v", repo)
	}
}

func TestSyncIndividualLevels(t *testing.T) {
	tests := []struct {
		req  dtolocation.SyncRequest
		want domainlocation.SyncProgress
	}{
		{dtolocation.SyncRequest{Level: "province"}, domainlocation.SyncProgress{Message: "Province sync completed", ProvinceCount: 1}},
		{dtolocation.SyncRequest{Level: "city", ProvinceCode: "31"}, domainlocation.SyncProgress{Message: "City sync completed", CityCount: 1}},
		{dtolocation.SyncRequest{Level: "district", ProvinceCode: "31", CityCode: "3171"}, domainlocation.SyncProgress{Message: "District sync completed", DistrictCount: 1}},
		{dtolocation.SyncRequest{Level: "village", ProvinceCode: "31", CityCode: "3171", DistrictCode: "317101"}, domainlocation.SyncProgress{Message: "Village sync completed", VillageCount: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.req.Level, func(t *testing.T) {
			svc := newScopedSync(t, &locationRepoTestDouble{})
			got, err := svc.sync(context.Background(), tt.req, func(domainlocation.SyncProgress) {})
			if err != nil || got != tt.want {
				t.Fatalf("sync = %+v, %v, want %+v", got, err, tt.want)
			}
		})
	}
}

// A level the Location Service has no rows for is a no-op, not a failure (gorm
// refuses to insert an empty list, and an empty answer is a valid one).
func TestSyncOfALevelWithNoRowsSucceeds(t *testing.T) {
	svc := newTestService(t, &locationRepoTestDouble{}, answering(`[]`))
	got, err := svc.sync(context.Background(), dtolocation.SyncRequest{Level: "city", ProvinceCode: "31"}, func(domainlocation.SyncProgress) {})
	if err != nil || got.CityCount != 0 {
		t.Fatalf("sync = %+v, %v", got, err)
	}
}

func TestSyncUpsertErrors(t *testing.T) {
	tests := []struct {
		name string
		repo *locationRepoTestDouble
		req  dtolocation.SyncRequest
	}{
		{"province", &locationRepoTestDouble{upsertProvinceErr: errors.New("database down")}, dtolocation.SyncRequest{Level: "province"}},
		{"city", &locationRepoTestDouble{upsertCityErr: errors.New("database down")}, dtolocation.SyncRequest{Level: "city", ProvinceCode: "31"}},
		{"district", &locationRepoTestDouble{upsertDistrictErr: errors.New("database down")}, dtolocation.SyncRequest{Level: "district", ProvinceCode: "31", CityCode: "3171"}},
		{"village", &locationRepoTestDouble{upsertVillageErr: errors.New("database down")}, dtolocation.SyncRequest{Level: "village", ProvinceCode: "31", CityCode: "3171", DistrictCode: "317101"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newScopedSync(t, tt.repo)
			if _, err := svc.sync(context.Background(), tt.req, func(domainlocation.SyncProgress) {}); err == nil {
				t.Fatal("expected upsert error")
			}
		})
	}
}

func TestSyncDropsOnlyTheCacheKeysItTouched(t *testing.T) {
	cache := newFakeCache()
	svc := NewService(&locationRepoTestDouble{}, Options{Cache: cache, HeartbeatInterval: time.Hour})
	svc.httpClient = &http.Client{Transport: scopedUpstream()}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	if _, err := svc.sync(context.Background(), dtolocation.SyncRequest{Level: "city", ProvinceCode: "31"}, func(domainlocation.SyncProgress) {}); err != nil {
		t.Fatal(err)
	}
	if len(cache.deletes) != 1 || cache.deletes[0] != "location:city:31" {
		t.Fatalf("deleted %v, want only location:city:31", cache.deletes)
	}
}

// startedJob runs a job to its end on a fresh service and returns the repository double.
func runJob(t *testing.T, repo *locationRepoTestDouble, rt http.RoundTripper, opts Options, req dtolocation.SyncRequest) *Service {
	t.Helper()
	opts.HeartbeatInterval = orDefault(opts.HeartbeatInterval, time.Hour)
	svc := NewService(repo, opts)
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	svc.runSyncJob("job-1", req)
	return svc
}

func TestRunSyncJobRecordsStartProgressAndCompletion(t *testing.T) {
	repo := &locationRepoTestDouble{}
	runJob(t, repo, answering(`[{"code":"31","name":"DKI Jakarta"}]`), Options{InstanceID: "instance-a"}, dtolocation.SyncRequest{Level: "province"})

	if len(repo.started) != 1 || repo.started[0] != "job-1" {
		t.Fatalf("started = %v", repo.started)
	}
	got := repo.lastFinish(t)
	if got.Status != "completed" || got.Message != "Location sync completed" || got.ErrorMessage != "" {
		t.Fatalf("final state = %+v", got)
	}
	// The counts reach the job through a progress write, not a whole-row save.
	if last := repo.progress[len(repo.progress)-1]; last.ProvinceCount != 1 {
		t.Fatalf("last progress = %+v, want the final counts", last)
	}
}

func TestRunSyncJobRecordsAFailure(t *testing.T) {
	repo := &locationRepoTestDouble{}
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("network down") })
	runJob(t, repo, rt, Options{}, dtolocation.SyncRequest{Level: "province"})

	got := repo.lastFinish(t)
	if got.Status != "failed" || got.Message != "Location sync failed" || !strings.Contains(got.ErrorMessage, "network down") {
		t.Fatalf("final state = %+v", got)
	}
}

func TestRunSyncJobThatCannotStartIsLoggedNotFinished(t *testing.T) {
	repo := &locationRepoTestDouble{startErr: domainlocation.ErrNotFound}
	up := answering(`[{"code":"31","name":"DKI Jakarta"}]`)
	runJob(t, repo, up, Options{}, dtolocation.SyncRequest{Level: "province"})
	if up.calls() != 0 {
		t.Fatal("a job that could not be started must not run")
	}
}

// Many progress reports in a short time become a handful of writes.
func TestProgressWritesAreThrottled(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := NewService(repo, Options{ProgressInterval: time.Hour, HeartbeatInterval: time.Hour})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	w := &progressWriter{s: svc, jobID: "job-1"}

	for i := range 100 {
		w.report(context.Background(), domainlocation.SyncProgress{Message: "step", CityCount: i})
	}
	if _, _, progress := repo.counts(); progress != 1 {
		t.Fatalf("100 reports inside one interval wrote %d times, want 1", progress)
	}

	svc.progressInterval = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	w.report(context.Background(), domainlocation.SyncProgress{Message: "later", CityCount: 100})
	if _, _, progress := repo.counts(); progress != 2 {
		t.Fatalf("a report after the interval must write, writes = %d", progress)
	}
}

func TestARunningJobSendsHeartbeats(t *testing.T) {
	repo := &locationRepoTestDouble{}
	release := make(chan struct{})
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-release
		return okResponse(`[{"code":"31","name":"DKI Jakarta"}]`), nil
	})
	svc := NewService(repo, Options{HeartbeatInterval: 5 * time.Millisecond})
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	done := make(chan struct{})
	go func() { svc.runSyncJob("job-1", dtolocation.SyncRequest{Level: "province"}); close(done) }()
	deadline := time.After(5 * time.Second)
	for {
		if _, touches, _ := repo.counts(); touches >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("a running job sent fewer than 3 heartbeats")
		case <-time.After(time.Millisecond):
		}
	}
	close(release)
	<-done
	if repo.lastFinish(t).Status != "completed" {
		t.Fatal("the job did not complete")
	}
}

// When another instance has taken the job over (its heartbeat looked stale), this
// instance must stop and must not write a final state over the takeover.
func TestAJobThatWasTakenOverStopsWithoutFinishing(t *testing.T) {
	repo := &locationRepoTestDouble{touchErr: domainlocation.ErrNotFound}
	started := make(chan struct{})
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-req.Context().Done() // runs until the job is canceled
		return nil, req.Context().Err()
	})
	svc := NewService(repo, Options{HeartbeatInterval: 5 * time.Millisecond})
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	done := make(chan struct{})
	go func() { svc.runSyncJob("job-1", dtolocation.SyncRequest{Level: "province"}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a job that lost its ownership kept running")
	}
	if finishes, _, _ := repo.counts(); finishes != 0 {
		t.Fatalf("the job recorded %d final states over the takeover", finishes)
	}
}

// A progress write that finds the job gone means another instance took it over:
// the job stops at once instead of waiting for the next heartbeat.
func TestAProgressWriteThatLostTheJobCancelsIt(t *testing.T) {
	repo := &locationRepoTestDouble{progressErr: domainlocation.ErrNotFound}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	svc := NewService(repo, Options{HeartbeatInterval: time.Hour})
	svc.httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	done := make(chan struct{})
	go func() { svc.runSyncJob("job-1", dtolocation.SyncRequest{Level: "province"}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a job whose progress write lost ownership kept running")
	}
	if finishes, _, _ := repo.counts(); finishes != 0 {
		t.Fatalf("the job recorded %d final states over the takeover", finishes)
	}
}
