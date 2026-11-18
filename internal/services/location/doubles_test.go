package location

import (
	"context"
	"errors"
	"net/http"
	"testing"

	domainlocation "starter-kit/internal/domain/location"
)

type locationRepoTestDouble struct {
	provinces []domainlocation.Province
	cities    []domainlocation.City
	districts []domainlocation.District
	villages  []domainlocation.Village
	city      domainlocation.City
	district  domainlocation.District
	listErr   error

	activeJob    domainlocation.SyncJob
	activeJobErr error
	syncJob      domainlocation.SyncJob
	syncJobErr   error
	createdJob   *domainlocation.SyncJob
	updatedJobs  []domainlocation.SyncJob
	failMessage  string

	upsertProvinceCount int
	upsertCityCount     int
	upsertDistrictCount int
	upsertVillageCount  int
	upsertProvinceErr   error
	upsertCityErr       error
	upsertDistrictErr   error
	upsertVillageErr    error
	createSyncJobErr    error
	updateSyncJobErr    error
	failActiveErr       error
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (m *locationRepoTestDouble) ListProvinces(ctx context.Context) ([]domainlocation.Province, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return append([]domainlocation.Province{}, m.provinces...), nil
}

func (m *locationRepoTestDouble) ListCitiesByProvince(ctx context.Context, provinceCode string) ([]domainlocation.City, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return append([]domainlocation.City{}, m.cities...), nil
}

func (m *locationRepoTestDouble) ListDistrictsByCity(ctx context.Context, cityCode string) ([]domainlocation.District, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return append([]domainlocation.District{}, m.districts...), nil
}

func (m *locationRepoTestDouble) ListVillagesByDistrict(ctx context.Context, districtCode string) ([]domainlocation.Village, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return append([]domainlocation.Village{}, m.villages...), nil
}

func (m *locationRepoTestDouble) GetProvinceByCode(ctx context.Context, code string) (domainlocation.Province, error) {
	return domainlocation.Province{}, errors.New("not implemented")
}

func (m *locationRepoTestDouble) GetCityByCode(ctx context.Context, code string) (domainlocation.City, error) {
	if m.city.Code != "" {
		return m.city, nil
	}
	for _, city := range m.cities {
		if city.Code == code {
			return city, nil
		}
	}
	return domainlocation.City{}, domainlocation.ErrNotFound
}

func (m *locationRepoTestDouble) GetDistrictByCode(ctx context.Context, code string) (domainlocation.District, error) {
	if m.district.Code != "" {
		return m.district, nil
	}
	for _, district := range m.districts {
		if district.Code == code {
			return district, nil
		}
	}
	return domainlocation.District{}, domainlocation.ErrNotFound
}

func (m *locationRepoTestDouble) UpsertProvinces(ctx context.Context, items []domainlocation.Province) error {
	if m.upsertProvinceErr != nil {
		return m.upsertProvinceErr
	}
	m.upsertProvinceCount += len(items)
	return nil
}

func (m *locationRepoTestDouble) UpsertCities(ctx context.Context, items []domainlocation.City) error {
	if m.upsertCityErr != nil {
		return m.upsertCityErr
	}
	m.upsertCityCount += len(items)
	return nil
}

func (m *locationRepoTestDouble) UpsertDistricts(ctx context.Context, items []domainlocation.District) error {
	if m.upsertDistrictErr != nil {
		return m.upsertDistrictErr
	}
	m.upsertDistrictCount += len(items)
	return nil
}

func (m *locationRepoTestDouble) UpsertVillages(ctx context.Context, items []domainlocation.Village) error {
	if m.upsertVillageErr != nil {
		return m.upsertVillageErr
	}
	m.upsertVillageCount += len(items)
	return nil
}

func (m *locationRepoTestDouble) CreateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	if m.createSyncJobErr != nil {
		return m.createSyncJobErr
	}
	m.createdJob = new(*job)
	return nil
}

func (m *locationRepoTestDouble) UpdateSyncJob(ctx context.Context, job *domainlocation.SyncJob) error {
	copyJob := *job
	m.updatedJobs = append(m.updatedJobs, copyJob)
	return m.updateSyncJobErr
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
	return m.failActiveErr
}

// newTestService builds a Service through the constructor and, when rt is not
// nil, swaps the HTTP transport so no network is used.
func newTestService(t *testing.T, repo Repository, rt http.RoundTripper) *Service {
	t.Helper()
	svc := NewService(repo, Options{})
	if rt != nil {
		svc.httpClient = &http.Client{Transport: rt}
	}
	return svc
}
