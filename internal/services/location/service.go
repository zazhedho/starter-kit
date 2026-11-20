package location

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

// Service holds the location use cases. Build it with NewService; a running
// sync belongs to the Service until Close.
type Service struct {
	repo       Repository
	cache      Cache
	httpClient *http.Client
	newID      func() string
	syncing    atomic.Bool

	baseURL  string
	cacheTTL time.Duration

	// lifecycle: background sync jobs run under baseCtx, which Close cancels.
	baseCtx context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	jobs    sync.WaitGroup
	// settleBy is the deadline Close was given: the final state write of a
	// canceled job must end by then. Zero until Close is called with one.
	settleBy time.Time
}

// NewService builds the service. It performs no I/O: call RecoverInterruptedJobs
// once at startup, and Close at shutdown.
func NewService(repo Repository, opts Options) *Service {
	// Zero would mean "no timeout" to http.Client; never allow that, so a
	// project that builds Options by hand stays safe.
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	cache := opts.Cache
	if cache == nil {
		cache = noopCache{}
	}
	newID := opts.NewID
	if newID == nil {
		newID = newUUIDv7
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	return &Service{
		repo:       repo,
		cache:      cache,
		httpClient: &http.Client{Timeout: timeout},
		newID:      newID,
		baseURL:    opts.BaseURL,
		cacheTTL:   opts.CacheTTL,
		baseCtx:    baseCtx,
		cancel:     cancel,
	}
}

// newUUIDv7 returns a time-ordered UUID, falling back to a random one if the
// clock source fails. The router normally injects the same behavior.
func newUUIDv7() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}

func (s *Service) GetProvince(ctx context.Context) ([]dtolocation.Location, error) {
	cacheKey := provinceKey()
	if data, ok := s.cache.Get(ctx, cacheKey); ok {
		if len(data) > 0 {
			return data, nil
		}
	}

	rows, err := s.repo.ListProvinces(ctx)
	if err != nil {
		return nil, err
	}

	locations := mapProvinces(rows)
	if len(locations) == 0 {
		fetched, fetchErr := s.fetchProvinces(ctx)
		if fetchErr != nil {
			return nil, fetchErr
		}
		if err := s.repo.UpsertProvinces(ctx, fetched); err != nil {
			return nil, err
		}
		locations = mapProvinces(fetched)
	}
	s.setLocationCache(ctx, cacheKey, locations)
	return locations, nil
}

func (s *Service) GetCity(ctx context.Context, provinceCode string) ([]dtolocation.Location, error) {
	cacheKey := cityKey(provinceCode)
	if data, ok := s.cache.Get(ctx, cacheKey); ok {
		if len(data) > 0 {
			return data, nil
		}
	}

	rows, err := s.repo.ListCitiesByProvince(ctx, provinceCode)
	if err != nil {
		return nil, err
	}

	locations := mapCities(rows)
	if len(locations) == 0 {
		fetched, fetchErr := s.fetchCities(ctx, provinceCode)
		if fetchErr != nil {
			return nil, fetchErr
		}
		if err := s.repo.UpsertCities(ctx, fetched); err != nil {
			return nil, err
		}
		locations = mapCities(fetched)
	}
	s.setLocationCache(ctx, cacheKey, locations)
	return locations, nil
}

func (s *Service) GetDistrict(ctx context.Context, cityCode string) ([]dtolocation.Location, error) {
	cacheKey := districtKey(cityCode)
	if data, ok := s.cache.Get(ctx, cacheKey); ok {
		if len(data) > 0 {
			return data, nil
		}
	}

	rows, err := s.repo.ListDistrictsByCity(ctx, cityCode)
	if err != nil {
		return nil, err
	}

	locations := mapDistricts(rows)
	if len(locations) == 0 {
		city, cityErr := s.repo.GetCityByCode(ctx, cityCode)
		if cityErr != nil {
			return nil, cityErr
		}
		fetched, fetchErr := s.fetchDistricts(ctx, city.ProvinceCode, cityCode)
		if fetchErr != nil {
			return nil, fetchErr
		}
		if err := s.repo.UpsertDistricts(ctx, fetched); err != nil {
			return nil, err
		}
		locations = mapDistricts(fetched)
	}
	s.setLocationCache(ctx, cacheKey, locations)
	return locations, nil
}

func (s *Service) GetVillage(ctx context.Context, districtCode string) ([]dtolocation.Location, error) {
	cacheKey := villageKey(districtCode)
	if data, ok := s.cache.Get(ctx, cacheKey); ok {
		if len(data) > 0 {
			return data, nil
		}
	}

	rows, err := s.repo.ListVillagesByDistrict(ctx, districtCode)
	if err != nil {
		return nil, err
	}

	locations := mapVillages(rows)
	if len(locations) == 0 {
		district, districtErr := s.repo.GetDistrictByCode(ctx, districtCode)
		if districtErr != nil {
			return nil, districtErr
		}
		city, cityErr := s.repo.GetCityByCode(ctx, district.CityCode)
		if cityErr != nil {
			return nil, cityErr
		}
		fetched, fetchErr := s.fetchVillages(ctx, city.ProvinceCode, district.CityCode, districtCode)
		if fetchErr != nil {
			return nil, fetchErr
		}
		if err := s.repo.UpsertVillages(ctx, fetched); err != nil {
			return nil, err
		}
		locations = mapVillages(fetched)
	}
	s.setLocationCache(ctx, cacheKey, locations)
	return locations, nil
}

// StartSync queues a sync job and runs it in the background. requestedBy is the
// id of the user who asked for it.
func (s *Service) StartSync(ctx context.Context, req dtolocation.SyncRequest, requestedBy string) (dtolocation.SyncJob, error) {
	normalizedReq, err := s.normalizeAndValidateRequest(req)
	if err != nil {
		return dtolocation.SyncJob{}, err
	}

	activeJob, err := s.repo.GetActiveSyncJob(ctx)
	switch {
	case err == nil:
		return mapSyncJob(activeJob), domainlocation.ErrSyncRunning
	case !errors.Is(err, domainlocation.ErrNotFound):
		return dtolocation.SyncJob{}, err
	}

	now := time.Now()
	job := domainlocation.SyncJob{
		ID:           s.newID(),
		Status:       "queued",
		Level:        normalizedReq.Level,
		ProvinceCode: normalizedReq.ProvinceCode,
		CityCode:     normalizedReq.CityCode,
		DistrictCode: normalizedReq.DistrictCode,
		RequestedBy:  requestedBy,
		Message:      "Location sync queued",
		CreatedAt:    now,
		UpdatedAt:    &now,
	}

	if !s.startJob() {
		return dtolocation.SyncJob{}, ErrClosed
	}
	if err := s.repo.CreateSyncJob(ctx, &job); err != nil {
		s.jobs.Done()
		return dtolocation.SyncJob{}, err
	}

	go func() {
		defer s.jobs.Done()
		s.runSyncJob(job.ID, normalizedReq)
	}()

	return mapSyncJob(job), nil
}

func (s *Service) GetSyncJob(ctx context.Context, id string) (dtolocation.SyncJob, error) {
	job, err := s.repo.GetSyncJobByID(ctx, id)
	if err != nil {
		return dtolocation.SyncJob{}, err
	}

	return mapSyncJob(job), nil
}

func (s *Service) normalizeAndValidateRequest(req dtolocation.SyncRequest) (dtolocation.SyncRequest, error) {
	req.Level = normalizeSyncLevel(req.Level)

	switch req.Level {
	case "province":
		return req, nil
	case "city":
		if req.ProvinceCode == "" {
			return dtolocation.SyncRequest{}, domainlocation.NewInvalidSync("province_code is required for city sync")
		}
		return req, nil
	case "district":
		if req.ProvinceCode == "" || req.CityCode == "" {
			return dtolocation.SyncRequest{}, domainlocation.NewInvalidSync("province_code and city_code are required for district sync")
		}
		return req, nil
	case "village":
		if req.ProvinceCode == "" || req.CityCode == "" || req.DistrictCode == "" {
			return dtolocation.SyncRequest{}, domainlocation.NewInvalidSync("province_code, city_code, and district_code are required for village sync")
		}
		return req, nil
	case "all":
		return req, nil
	default:
		return dtolocation.SyncRequest{}, domainlocation.NewInvalidSync("invalid sync level")
	}
}

func normalizeSyncLevel(level string) string {
	switch level {
	case "", "all":
		return "all"
	case "province", "city", "district", "village":
		return level
	default:
		return level
	}
}
