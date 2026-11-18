package location

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

func TestLocationSyncAll(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := newScopedLocationSyncService(t, repo)
	var progressCalls int
	result, err := svc.sync(context.Background(), dtolocation.SyncRequest{Level: "all", Year: "2026"}, func(progress syncProgress) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("sync all: %v", err)
	}
	if result.ProvinceCount != 1 || result.CityCount != 1 || result.DistrictCount != 1 || result.VillageCount != 1 {
		t.Fatalf("unexpected sync result: %+v", result)
	}
	if progressCalls == 0 {
		t.Fatal("expected progress callbacks")
	}
	if repo.upsertProvinceCount != 1 || repo.upsertCityCount != 1 || repo.upsertDistrictCount != 1 || repo.upsertVillageCount != 1 {
		t.Fatalf("expected all upserts, repo=%+v", repo)
	}
}

func TestLocationSyncIndividualLevels(t *testing.T) {
	makeService := func(repo *locationRepoTestDouble) *Service {
		return newTestService(t, repo, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{}`
			switch {
			case strings.Contains(req.URL.Path, "/api/locations/provinces"):
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"31","name":"DKI Jakarta"}]}`
			case strings.Contains(req.URL.Path, "/api/locations/regencies"):
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"71","name":"Jakarta Selatan"}]}`
			case strings.Contains(req.URL.Path, "/api/locations/districts"):
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","name":"Tebet"}]}`
			case strings.Contains(req.URL.Path, "/api/locations/villages"):
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","name":"Tebet Barat"}]}`
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}))
	}

	tests := []dtolocation.SyncRequest{
		{Level: "province", Year: "2026"},
		{Level: "city", Year: "2026", ProvinceCode: "31"},
		{Level: "district", Year: "2026", ProvinceCode: "31", CityCode: "3171"},
		{Level: "village", Year: "2026", ProvinceCode: "31", CityCode: "3171", DistrictCode: "317101"},
	}

	for _, req := range tests {
		t.Run(req.Level, func(t *testing.T) {
			repo := &locationRepoTestDouble{}
			svc := makeService(repo)
			result, err := svc.sync(context.Background(), req, func(progress syncProgress) {})
			if err != nil {
				t.Fatalf("expected sync success, got %v", err)
			}
			if result.Message == "" {
				t.Fatalf("expected result message, got %+v", result)
			}
		})
	}

	svc := makeService(&locationRepoTestDouble{})
	if _, err := svc.sync(context.Background(), dtolocation.SyncRequest{Level: "bad"}, func(progress syncProgress) {}); err == nil {
		t.Fatal("expected invalid sync level error")
	}
}

func TestLocationSyncUpsertErrors(t *testing.T) {
	makeService := func(repo *locationRepoTestDouble) *Service {
		return newTestService(t, repo, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"31","name":"DKI Jakarta"}]}`
			if strings.Contains(req.URL.Path, "/api/locations/regencies") {
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"71","name":"Jakarta Selatan"}]}`
			}
			if strings.Contains(req.URL.Path, "/api/locations/districts") {
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","name":"Tebet"}]}`
			}
			if strings.Contains(req.URL.Path, "/api/locations/villages") {
				body = `{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"01","name":"Tebet Barat"}]}`
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}))
	}

	tests := []struct {
		name string
		repo *locationRepoTestDouble
		req  dtolocation.SyncRequest
	}{
		{name: "province", repo: &locationRepoTestDouble{upsertProvinceErr: errors.New("database down")}, req: dtolocation.SyncRequest{Level: "province", Year: "2026"}},
		{name: "city", repo: &locationRepoTestDouble{upsertCityErr: errors.New("database down")}, req: dtolocation.SyncRequest{Level: "city", Year: "2026", ProvinceCode: "31"}},
		{name: "district", repo: &locationRepoTestDouble{upsertDistrictErr: errors.New("database down")}, req: dtolocation.SyncRequest{Level: "district", Year: "2026", ProvinceCode: "31", CityCode: "3171"}},
		{name: "village", repo: &locationRepoTestDouble{upsertVillageErr: errors.New("database down")}, req: dtolocation.SyncRequest{Level: "village", Year: "2026", ProvinceCode: "31", CityCode: "3171", DistrictCode: "317101"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := makeService(tt.repo)
			if _, err := svc.sync(context.Background(), tt.req, func(progress syncProgress) {}); err == nil {
				t.Fatal("expected upsert error")
			}
		})
	}
}

func TestRunSyncJobCompletesAndHandlesGuards(t *testing.T) {
	now := time.Now()
	repo := &locationRepoTestDouble{syncJob: domainlocation.SyncJob{ID: "job-1", Status: "queued", Level: "province", Year: "2026", CreatedAt: now}}
	svc := newTestService(t, repo, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"log_id":"test","code":200,"status":true,"message":"Success","data":[{"code":"31","name":"DKI Jakarta"}]}`)), Header: make(http.Header)}, nil
	}))

	svc.runSyncJob("job-1", dtolocation.SyncRequest{Level: "province", Year: "2026"})
	if len(repo.updatedJobs) < 2 {
		t.Fatalf("expected running and completed job updates, got %+v", repo.updatedJobs)
	}
	if got := repo.updatedJobs[len(repo.updatedJobs)-1]; got.Status != "completed" || got.ProvinceCount != 1 {
		t.Fatalf("expected completed job, got %+v", got)
	}

	repo = &locationRepoTestDouble{syncJob: domainlocation.SyncJob{ID: "job-2", Status: "queued", CreatedAt: now}}
	svc = newTestService(t, repo, nil)
	svc.syncing.Store(true)
	svc.runSyncJob("job-2", dtolocation.SyncRequest{Level: "province", Year: "2026"})
	if len(repo.updatedJobs) != 1 || repo.updatedJobs[0].Status != "failed" {
		t.Fatalf("expected busy sync to mark failed, got %+v", repo.updatedJobs)
	}
}

func TestLocationSyncProgressAndFailureHelpers(t *testing.T) {
	now := time.Now()
	repo := &locationRepoTestDouble{syncJob: domainlocation.SyncJob{ID: "job-1", Status: "running", CreatedAt: now}}
	svc := newTestService(t, repo, nil)

	job := domainlocation.SyncJob{ID: "job-1"}
	svc.applySyncProgress(&job, syncProgress{Message: "halfway", ProvinceCount: 1})
	if job.Message != "halfway" || job.ProvinceCount != 1 || job.UpdatedAt == nil {
		t.Fatalf("unexpected progress application: %+v", job)
	}

	svc.markSyncJobFailed("job-1", "failed")
	if repo.syncJob.Status != "running" {
		t.Fatalf("test double should keep original sync job copy, got %+v", repo.syncJob)
	}
}
