package location

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	domainlocation "starter-kit/internal/domain/location"
)

type locationRepoTestDouble struct {
	provinces []domainlocation.Province
	cities    []domainlocation.City
	districts []domainlocation.District
	villages  []domainlocation.Village
	listErr   error

	knownProvinces map[string]domainlocation.Province
	knownCities    map[string]domainlocation.City
	knownDistricts map[string]domainlocation.District

	activeJob                                                                  domainlocation.SyncJob
	syncJob                                                                    domainlocation.SyncJob
	syncJobErr                                                                 error
	createSyncJobErr, startErr, touchErr, finishErr, failStaleErr, progressErr error

	upsertProvinceErr, upsertCityErr, upsertDistrictErr, upsertVillageErr error

	mu                  sync.Mutex
	lookups             int
	createdJob          *domainlocation.SyncJob
	started             []string
	progress            []domainlocation.SyncProgress
	touches             int
	finishes            []domainlocation.SyncFinish
	failStale           []time.Duration
	failStaleMessage    string
	upsertProvinceCount int
	upsertCityCount     int
	upsertDistrictCount int
	upsertVillageCount  int
	upsertedCities      []domainlocation.City
	upsertedVillages    []domainlocation.Village
	deadlines           []time.Time
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (m *locationRepoTestDouble) ListProvinces(context.Context) ([]domainlocation.Province, error) {
	return append([]domainlocation.Province{}, m.provinces...), m.listErr
}

func (m *locationRepoTestDouble) ListCitiesByProvince(context.Context, string) ([]domainlocation.City, error) {
	return append([]domainlocation.City{}, m.cities...), m.listErr
}

func (m *locationRepoTestDouble) ListDistrictsByCity(context.Context, string) ([]domainlocation.District, error) {
	return append([]domainlocation.District{}, m.districts...), m.listErr
}

func (m *locationRepoTestDouble) ListVillagesByDistrict(context.Context, string) ([]domainlocation.Village, error) {
	return append([]domainlocation.Village{}, m.villages...), m.listErr
}

func (m *locationRepoTestDouble) GetProvinceByCode(_ context.Context, code string) (domainlocation.Province, error) {
	m.mu.Lock()
	m.lookups++
	m.mu.Unlock()
	if p, ok := m.knownProvinces[code]; ok {
		return p, nil
	}
	return domainlocation.Province{}, domainlocation.ErrNotFound
}

func (m *locationRepoTestDouble) GetCityByCode(_ context.Context, code string) (domainlocation.City, error) {
	m.mu.Lock()
	m.lookups++
	m.mu.Unlock()
	if c, ok := m.knownCities[code]; ok {
		return c, nil
	}
	return domainlocation.City{}, domainlocation.ErrNotFound
}

func (m *locationRepoTestDouble) GetDistrictByCode(_ context.Context, code string) (domainlocation.District, error) {
	m.mu.Lock()
	m.lookups++
	m.mu.Unlock()
	if d, ok := m.knownDistricts[code]; ok {
		return d, nil
	}
	return domainlocation.District{}, domainlocation.ErrNotFound
}

func (m *locationRepoTestDouble) UpsertProvinces(_ context.Context, items []domainlocation.Province) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertProvinceErr != nil {
		return m.upsertProvinceErr
	}
	m.upsertProvinceCount += len(items)
	return nil
}

func (m *locationRepoTestDouble) UpsertCities(_ context.Context, items []domainlocation.City) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertCityErr != nil {
		return m.upsertCityErr
	}
	m.upsertCityCount += len(items)
	m.upsertedCities = append(m.upsertedCities, items...)
	return nil
}

func (m *locationRepoTestDouble) UpsertDistricts(_ context.Context, items []domainlocation.District) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertDistrictErr != nil {
		return m.upsertDistrictErr
	}
	m.upsertDistrictCount += len(items)
	return nil
}

func (m *locationRepoTestDouble) UpsertVillages(_ context.Context, items []domainlocation.Village) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertVillageErr != nil {
		return m.upsertVillageErr
	}
	m.upsertVillageCount += len(items)
	m.upsertedVillages = append(m.upsertedVillages, items...)
	return nil
}

func (m *locationRepoTestDouble) CreateSyncJob(_ context.Context, job *domainlocation.SyncJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createSyncJobErr != nil {
		return m.createSyncJobErr
	}
	m.createdJob = new(*job)
	return nil
}

func (m *locationRepoTestDouble) GetSyncJobByID(context.Context, string) (domainlocation.SyncJob, error) {
	return m.syncJob, m.syncJobErr
}

func (m *locationRepoTestDouble) GetActiveSyncJob(context.Context) (domainlocation.SyncJob, error) {
	if m.activeJob.ID == "" {
		return domainlocation.SyncJob{}, domainlocation.ErrNotFound
	}
	return m.activeJob, nil
}

func (m *locationRepoTestDouble) StartSyncJob(_ context.Context, id, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = append(m.started, id)
	return m.startErr
}

func (m *locationRepoTestDouble) SaveSyncProgress(_ context.Context, _, _ string, p domainlocation.SyncProgress, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress = append(m.progress, p)
	return m.progressErr
}

func (m *locationRepoTestDouble) TouchSyncJob(context.Context, string, string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touches++
	return m.touchErr
}

func (m *locationRepoTestDouble) FinishSyncJob(ctx context.Context, _, _ string, f domainlocation.SyncFinish, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dl, _ := ctx.Deadline()
	m.deadlines = append(m.deadlines, dl)
	m.finishes = append(m.finishes, f)
	return m.finishErr
}

func (m *locationRepoTestDouble) FailStaleSyncJobs(_ context.Context, staleAfter time.Duration, _ time.Time, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStale = append(m.failStale, staleAfter)
	m.failStaleMessage = message
	return m.failStaleErr
}

func (m *locationRepoTestDouble) lastFinish(t *testing.T) domainlocation.SyncFinish {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.finishes) == 0 {
		t.Fatal("the job never recorded a final state")
	}
	return m.finishes[len(m.finishes)-1]
}

func (m *locationRepoTestDouble) counts() (finishes, touches, progress int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.finishes), m.touches, len(m.progress)
}

type upstream struct {
	mu       sync.Mutex
	requests []string
	handle   func(req *http.Request) *http.Response
}

func (u *upstream) RoundTrip(req *http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.requests = append(u.requests, req.URL.RequestURI())
	u.mu.Unlock()
	return u.handle(req), nil
}

func (u *upstream) calls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

func okResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func answering(body string) *upstream {
	return &upstream{handle: func(*http.Request) *http.Response { return okResponse(body) }}
}

func newTestService(t *testing.T, repo Repository, rt http.RoundTripper) *Service {
	t.Helper()
	svc := NewService(repo, Options{HeartbeatInterval: time.Hour})
	if rt != nil {
		svc.httpClient = &http.Client{Transport: rt}
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc
}
