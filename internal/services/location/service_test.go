package servicelocation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/dto"
	"strings"
	"testing"
	"time"

	redismock "github.com/go-redis/redismock/v9"
	"gorm.io/gorm"
)

type locationRepoTestDouble struct {
	provinces []domainlocation.Province
	cities    []domainlocation.City
	districts []domainlocation.District
	villages  []domainlocation.Village

	activeJob    domainlocation.SyncJob
	activeJobErr error
	syncJob      domainlocation.SyncJob
	syncJobErr   error
	createdJob   *domainlocation.SyncJob
	failMessage  string

	upsertProvinceCount int
	upsertCityCount     int
	upsertDistrictCount int
	upsertVillageCount  int
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (m *locationRepoTestDouble) ListProvinces(ctx context.Context) ([]domainlocation.Province, error) {
	return append([]domainlocation.Province{}, m.provinces...), nil
}
func (m *locationRepoTestDouble) ListCitiesByProvince(ctx context.Context, provinceCode string) ([]domainlocation.City, error) {
	return append([]domainlocation.City{}, m.cities...), nil
}
func (m *locationRepoTestDouble) ListDistrictsByCity(ctx context.Context, cityCode string) ([]domainlocation.District, error) {
	return append([]domainlocation.District{}, m.districts...), nil
}
func (m *locationRepoTestDouble) ListVillagesByDistrict(ctx context.Context, districtCode string) ([]domainlocation.Village, error) {
	return append([]domainlocation.Village{}, m.villages...), nil
}
func (m *locationRepoTestDouble) GetProvinceByCode(ctx context.Context, code string) (domainlocation.Province, error) {
	return domainlocation.Province{}, errors.New("not implemented")
}
func (m *locationRepoTestDouble) GetCityByCode(ctx context.Context, code string) (domainlocation.City, error) {
	return domainlocation.City{}, errors.New("not implemented")
}
func (m *locationRepoTestDouble) GetDistrictByCode(ctx context.Context, code string) (domainlocation.District, error) {
	return domainlocation.District{}, errors.New("not implemented")
}
func (m *locationRepoTestDouble) UpsertProvinces(ctx context.Context, items []domainlocation.Province) error {
	m.upsertProvinceCount += len(items)
	return nil
}
func (m *locationRepoTestDouble) UpsertCities(ctx context.Context, items []domainlocation.City) error {
	m.upsertCityCount += len(items)
	return nil
}
func (m *locationRepoTestDouble) UpsertDistricts(ctx context.Context, items []domainlocation.District) error {
	m.upsertDistrictCount += len(items)
	return nil
}
func (m *locationRepoTestDouble) UpsertVillages(ctx context.Context, items []domainlocation.Village) error {
	m.upsertVillageCount += len(items)
	return nil
}
func (m *locationRepoTestDouble) CreateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	copyJob := *job
	m.createdJob = &copyJob
	return nil
}
func (m *locationRepoTestDouble) UpdateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	return nil
}
func (m *locationRepoTestDouble) GetSyncJobByID(ctx context.Context, id string) (domainlocation.SyncJob, error) {
	if m.syncJobErr != nil {
		return domainlocation.SyncJob{}, m.syncJobErr
	}
	return m.syncJob, nil
}
func (m *locationRepoTestDouble) GetActiveSyncJob(ctx context.Context) (domainlocation.SyncJob, error) {
	if m.activeJobErr != nil {
		return domainlocation.SyncJob{}, m.activeJobErr
	}
	return m.activeJob, nil
}
func (m *locationRepoTestDouble) FailActiveSyncJobs(ctx context.Context, message string) error {
	m.failMessage = message
	return nil
}

func TestGetProvinceMapsRepositoryRows(t *testing.T) {
	svc := NewLocationService(&locationRepoTestDouble{
		provinces: []domainlocation.Province{
			{Code: "11", Name: "Aceh"},
			{Code: "12", Name: "Sumatera Utara"},
		},
	})

	got, err := svc.GetProvince(context.Background())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	want := []dto.Location{{Code: "11", Name: "Aceh"}, {Code: "12", Name: "Sumatera Utara"}}
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
	svc := NewLocationService(&locationRepoTestDouble{
		cities:    []domainlocation.City{{Code: "3171", Name: "Jakarta Selatan"}},
		districts: []domainlocation.District{{Code: "317101", Name: "Tebet"}},
		villages:  []domainlocation.Village{{Code: "31710101", Name: "Tebet Barat"}},
		syncJob: domainlocation.SyncJob{
			ID:        "job-1",
			Status:    "done",
			Level:     "province",
			Year:      "2026",
			CreatedAt: now,
			UpdatedAt: &now,
		},
	})

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

func TestStartSyncRejectsMissingScopedCodes(t *testing.T) {
	svc := NewLocationService(&locationRepoTestDouble{activeJobErr: gorm.ErrRecordNotFound})

	_, err := svc.StartSync(context.Background(), dto.SyncLocationRequest{Level: "city"}, "user-1")
	if err == nil || err.Error() != "province_code is required for city sync" {
		t.Fatalf("expected city sync validation error, got %v", err)
	}
}

func TestStartSyncReturnsActiveJobWhenAlreadyRunning(t *testing.T) {
	now := time.Now()
	svc := NewLocationService(&locationRepoTestDouble{
		activeJob: domainlocation.SyncJob{
			ID:        "job-1",
			Status:    "running",
			Level:     "all",
			Year:      "2025",
			Message:   "running",
			CreatedAt: now,
			UpdatedAt: &now,
		},
	})

	got, err := svc.StartSync(context.Background(), dto.SyncLocationRequest{Level: "all", Year: "2025"}, "user-1")
	if !errors.Is(err, ErrLocationSyncRunning) {
		t.Fatalf("expected ErrLocationSyncRunning, got %v", err)
	}
	if got.ID != "job-1" || got.Status != "running" {
		t.Fatalf("expected active job response, got %+v", got)
	}
}

func TestStartSyncCreatesQueuedJobWithDefaults(t *testing.T) {
	t.Setenv("LOCATION_SOURCE_YEAR", "2026")
	repo := &locationRepoTestDouble{activeJobErr: gorm.ErrRecordNotFound}
	svc := NewLocationService(repo)

	got, err := svc.StartSync(context.Background(), dto.SyncLocationRequest{Level: "province"}, "user-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if got.Status != "queued" || got.Level != "province" || got.Year != "2026" {
		t.Fatalf("unexpected job response: %+v", got)
	}
	if repo.createdJob == nil {
		t.Fatal("expected sync job to be created")
	}
	if repo.createdJob.RequestedBy != "user-1" {
		t.Fatalf("expected requested user id, got %+v", repo.createdJob)
	}
}

func TestLocationHelperCacheKeysAndCodeNormalization(t *testing.T) {
	t.Setenv("LOCATION_CACHE_TTL", "-1s")
	if locationCacheTTL() != defaultLocationCacheTTL {
		t.Fatal("expected invalid cache ttl to fall back to default")
	}
	if provinceCacheKey() != "location:province" {
		t.Fatalf("unexpected province cache key")
	}
	if cityCacheKey("11") != "location:city:11" || districtCacheKey("1101") != "location:district:1101" || villageCacheKey("110101") != "location:village:110101" {
		t.Fatal("unexpected scoped cache keys")
	}
	if locationCachePrefix() != "location:" {
		t.Fatal("unexpected cache prefix")
	}
	if got := normalizeChildCode("11", "01"); got != "1101" {
		t.Fatalf("expected normalized child code, got %q", got)
	}
	if got := normalizeChildCode("11", "1101"); got != "1101" {
		t.Fatalf("expected existing parent prefix to be preserved, got %q", got)
	}
	wantCandidates := []string{"01", "1101"}
	if got := childCodeCandidates("11", "1101"); !reflect.DeepEqual(got, wantCandidates) {
		t.Fatalf("expected %v, got %v", wantCandidates, got)
	}
}

func TestLocationCacheHelpersUseRedis(t *testing.T) {
	client, mock := redismock.NewClientMock()
	svc := &LocationService{Redis: client}
	ctx := context.Background()

	mock.ExpectGet("location:province").SetVal(`[{"code":"11","name":"Aceh"}]`)
	got, ok := svc.getCachedLocations(ctx, "location:province")
	if !ok || len(got) != 1 || got[0].Code != "11" {
		t.Fatalf("expected cached locations, ok=%v got=%+v", ok, got)
	}

	mock.Regexp().ExpectSet("location:province", `.+`, defaultLocationCacheTTL).SetVal("OK")
	svc.setCachedLocations(ctx, "location:province", []dto.Location{{Code: "11", Name: "Aceh"}})

	mock.ExpectScan(0, "location:*", 100).SetVal([]string{"location:province", "location:city:11"}, 0)
	mock.ExpectDel("location:province", "location:city:11").SetVal(2)
	svc.deleteCacheKeys("location:")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestLocationMapAndSortHelpers(t *testing.T) {
	provinces := sortProvinces([]domainlocation.Province{{Code: "12", Name: "Zulu"}, {Code: "11", Name: "Aceh"}})
	if provinces[0].Name != "Aceh" {
		t.Fatalf("expected province sort by name, got %+v", provinces)
	}
	cities := sortCities([]domainlocation.City{{Code: "2", Name: "Zulu"}, {Code: "1", Name: "Aceh"}})
	if cities[0].Name != "Aceh" {
		t.Fatalf("expected city sort by name, got %+v", cities)
	}
	districts := sortDistricts([]domainlocation.District{{Code: "2", Name: "Zulu"}, {Code: "1", Name: "Aceh"}})
	if districts[0].Name != "Aceh" {
		t.Fatalf("expected district sort by name, got %+v", districts)
	}
	villages := sortVillages([]domainlocation.Village{{Code: "2", Name: "Zulu"}, {Code: "1", Name: "Aceh"}})
	if villages[0].Name != "Aceh" {
		t.Fatalf("expected village sort by name, got %+v", villages)
	}
	if got := mapCities([]domainlocation.City{{Code: "1101", Name: "Banda Aceh"}}); len(got) != 1 || got[0].Code != "1101" {
		t.Fatalf("unexpected city mapping: %+v", got)
	}
	if got := mapDistricts([]domainlocation.District{{Code: "110101", Name: "Kuta Alam"}}); len(got) != 1 || got[0].Name != "Kuta Alam" {
		t.Fatalf("unexpected district mapping: %+v", got)
	}
	if got := mapVillages([]domainlocation.Village{{Code: "11010101", Name: "Village"}}); len(got) != 1 || got[0].Code != "11010101" {
		t.Fatalf("unexpected village mapping: %+v", got)
	}
}

func TestFetchLocationMapHandlesHTTPResponses(t *testing.T) {
	svc := &LocationService{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"11":"Aceh"}`)),
			Header:     make(http.Header),
		}, nil
	})}}
	got, err := svc.fetchLocationMap(context.Background(), "https://example.com/location", "province")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got["11"] != "Aceh" {
		t.Fatalf("unexpected location map: %+v", got)
	}

	svc.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := svc.fetchLocationMap(context.Background(), "https://example.com/location", "province"); err == nil {
		t.Fatal("expected status error")
	}
}

func TestLocationFetchScopedLevelsAndSyncAll(t *testing.T) {
	repo := &locationRepoTestDouble{}
	svc := &LocationService{
		Repo: repo,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{}`
			switch {
			case strings.Contains(req.URL.Path, "list_pro"):
				body = `{"31":"DKI Jakarta"}`
			case strings.Contains(req.URL.Path, "list_kab"):
				body = `{"71":"Jakarta Selatan"}`
			case strings.Contains(req.URL.Path, "list_kec"):
				body = `{"01":"Tebet"}`
			case strings.Contains(req.URL.Path, "list_des"):
				body = `{"01":"Tebet Barat"}`
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})},
	}
	ctx := context.Background()

	cities, err := svc.fetchCities(ctx, "2026", "31")
	if err != nil || len(cities) != 1 || cities[0].Code != "3171" {
		t.Fatalf("fetch cities: cities=%+v err=%v", cities, err)
	}
	districts, err := svc.fetchDistricts(ctx, "2026", "31", "3171")
	if err != nil || len(districts) != 1 || districts[0].Code != "317101" {
		t.Fatalf("fetch districts: districts=%+v err=%v", districts, err)
	}
	villages, err := svc.fetchVillages(ctx, "2026", "31", "3171", "317101")
	if err != nil || len(villages) != 1 || villages[0].Code != "31710101" {
		t.Fatalf("fetch villages: villages=%+v err=%v", villages, err)
	}

	var progressCalls int
	result, err := svc.sync(ctx, dto.SyncLocationRequest{Level: "all", Year: "2026"}, func(progress syncProgress) {
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

func TestLocationSyncProgressAndFailureHelpers(t *testing.T) {
	now := time.Now()
	repo := &locationRepoTestDouble{syncJob: domainlocation.SyncJob{ID: "job-1", Status: "running", CreatedAt: now}}
	svc := &LocationService{Repo: repo}

	job := domainlocation.SyncJob{ID: "job-1"}
	svc.applySyncProgress(&job, syncProgress{Message: "halfway", ProvinceCount: 1})
	if job.Message != "halfway" || job.ProvinceCount != 1 || job.UpdatedAt == nil {
		t.Fatalf("unexpected progress application: %+v", job)
	}

	svc.markSyncJobFailed(context.Background(), "job-1", "failed")
	if repo.syncJob.Status != "running" {
		t.Fatalf("test double should keep original sync job copy, got %+v", repo.syncJob)
	}
}
