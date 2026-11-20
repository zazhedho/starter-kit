package location

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

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
	instanceID string

	baseURL     string
	maxResponse int64
	cacheTTL    time.Duration

	heartbeatInterval time.Duration
	staleAfter        time.Duration
	progressInterval  time.Duration

	// misses and flights keep a burst of reads for an empty level from calling
	// the Location Service once per request.
	misses  *missCache
	flights singleflight.Group

	// lifecycle: background sync jobs run under baseCtx, which Interrupt cancels.
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
	cache := opts.Cache
	if cache == nil {
		cache = noopCache{}
	}
	newID := opts.NewID
	if newID == nil {
		newID = newUUIDv7
	}
	instanceID := opts.InstanceID
	if instanceID == "" {
		instanceID = uuid.NewString()
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	return &Service{
		repo:  repo,
		cache: cache,
		// Zero would mean "no timeout" to http.Client; never allow that, so a
		// project that builds Options by hand stays safe. The Location Service
		// is not trusted to redirect: a redirect is an error status.
		httpClient: &http.Client{
			Timeout:       orDefault(opts.Timeout, defaultHTTPTimeout),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		newID:             newID,
		instanceID:        instanceID,
		baseURL:           opts.BaseURL,
		maxResponse:       orDefault(opts.MaxResponseBytes, defaultMaxResponseBytes),
		cacheTTL:          opts.CacheTTL,
		heartbeatInterval: orDefault(opts.HeartbeatInterval, defaultHeartbeat),
		staleAfter:        orDefault(opts.StaleAfter, defaultStaleAfter),
		progressInterval:  orDefault(opts.ProgressInterval, defaultProgressInterval),
		misses:            newMissCache(orDefault(opts.MissTTL, defaultMissTTL), orDefault(opts.FailureTTL, defaultFailureTTL)),
		baseCtx:           baseCtx,
		cancel:            cancel,
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
	return readLevel(ctx, s, level[domainlocation.Province]{
		key:    provinceKey(),
		list:   s.repo.ListProvinces,
		view:   viewProvince,
		fetch:  s.fetchProvinces,
		upsert: s.repo.UpsertProvinces,
	})
}

// GetCity lists the cities of a province; ErrNotFound when the province is unknown.
func (s *Service) GetCity(ctx context.Context, provinceCode string) ([]dtolocation.Location, error) {
	if err := validateCode("province_code", provinceCode); err != nil {
		return nil, err
	}
	return readLevel(ctx, s, level[domainlocation.City]{
		key: cityKey(provinceCode),
		list: func(ctx context.Context) ([]domainlocation.City, error) {
			return s.repo.ListCitiesByProvince(ctx, provinceCode)
		},
		view: viewCity,
		fetch: func(ctx context.Context) ([]domainlocation.City, error) {
			if _, err := s.repo.GetProvinceByCode(ctx, provinceCode); err != nil {
				return nil, err
			}
			return s.fetchCities(ctx, provinceCode)
		},
		upsert: s.repo.UpsertCities,
	})
}

// GetDistrict lists the districts of a city; ErrNotFound when the city is unknown.
func (s *Service) GetDistrict(ctx context.Context, cityCode string) ([]dtolocation.Location, error) {
	if err := validateCode("city_code", cityCode); err != nil {
		return nil, err
	}
	return readLevel(ctx, s, level[domainlocation.District]{
		key: districtKey(cityCode),
		list: func(ctx context.Context) ([]domainlocation.District, error) {
			return s.repo.ListDistrictsByCity(ctx, cityCode)
		},
		view: viewDistrict,
		fetch: func(ctx context.Context) ([]domainlocation.District, error) {
			city, err := s.repo.GetCityByCode(ctx, cityCode)
			if err != nil {
				return nil, err
			}
			return s.fetchDistricts(ctx, city.ProvinceCode, cityCode)
		},
		upsert: s.repo.UpsertDistricts,
	})
}

// GetVillage lists the villages of a district; ErrNotFound when the district
// or its city is unknown.
func (s *Service) GetVillage(ctx context.Context, districtCode string) ([]dtolocation.Location, error) {
	if err := validateCode("district_code", districtCode); err != nil {
		return nil, err
	}
	return readLevel(ctx, s, level[domainlocation.Village]{
		key: villageKey(districtCode),
		list: func(ctx context.Context) ([]domainlocation.Village, error) {
			return s.repo.ListVillagesByDistrict(ctx, districtCode)
		},
		view: viewVillage,
		fetch: func(ctx context.Context) ([]domainlocation.Village, error) {
			district, err := s.repo.GetDistrictByCode(ctx, districtCode)
			if err != nil {
				return nil, err
			}
			city, err := s.repo.GetCityByCode(ctx, district.CityCode)
			if err != nil {
				return nil, err
			}
			return s.fetchVillages(ctx, city.ProvinceCode, district.CityCode, districtCode)
		},
		upsert: s.repo.UpsertVillages,
	})
}

// StartSync queues a sync job and runs it in the background. requestedBy is the
// id of the user who asked for it. When another job is queued or running, on
// this or any other instance, it answers ErrSyncRunning with that job.
func (s *Service) StartSync(ctx context.Context, req dtolocation.SyncRequest, requestedBy string) (dtolocation.SyncJob, error) {
	req, err := normalizeAndValidateRequest(req)
	if err != nil {
		return dtolocation.SyncJob{}, err
	}
	if _, err := uuid.Parse(strings.TrimSpace(requestedBy)); err != nil {
		return dtolocation.SyncJob{}, domainlocation.NewInvalidSync("requested_by must be a user id")
	}
	if !s.startJob() {
		return dtolocation.SyncJob{}, domainlocation.ErrShuttingDown
	}

	// A job whose instance died would hold the single active slot forever.
	now := time.Now()
	if err := s.repo.FailStaleSyncJobs(ctx, now.Add(-s.staleAfter), now, staleMessage); err != nil {
		s.jobs.Done()
		return dtolocation.SyncJob{}, err
	}

	job := domainlocation.SyncJob{
		ID:              s.newID(),
		Status:          "queued",
		Level:           req.Level,
		ProvinceCode:    req.ProvinceCode,
		CityCode:        req.CityCode,
		DistrictCode:    req.DistrictCode,
		RequestedBy:     requestedBy,
		Message:         "Location sync queued",
		CreatedAt:       now,
		UpdatedAt:       &now,
		OwnerInstanceID: s.instanceID,
		HeartbeatAt:     now,
	}
	if err := s.repo.CreateSyncJob(ctx, &job); err != nil {
		s.jobs.Done()
		if errors.Is(err, domainlocation.ErrSyncRunning) {
			active, getErr := s.repo.GetActiveSyncJob(ctx)
			if getErr != nil {
				return dtolocation.SyncJob{}, err
			}
			return mapSyncJob(active), err
		}
		return dtolocation.SyncJob{}, err
	}

	go func() {
		defer s.jobs.Done()
		s.runSyncJob(job.ID, req)
	}()

	return mapSyncJob(job), nil
}

// GetSyncJob returns a job, or ErrSyncJobNotFound.
func (s *Service) GetSyncJob(ctx context.Context, id string) (dtolocation.SyncJob, error) {
	job, err := s.repo.GetSyncJobByID(ctx, id)
	if errors.Is(err, domainlocation.ErrNotFound) {
		return dtolocation.SyncJob{}, domainlocation.ErrSyncJobNotFound
	}
	if err != nil {
		return dtolocation.SyncJob{}, err
	}
	return mapSyncJob(job), nil
}

// normalizeAndValidateRequest defaults the level to "all" and checks that the
// level is known and that the codes it needs, and any other given, are codes.
func normalizeAndValidateRequest(req dtolocation.SyncRequest) (dtolocation.SyncRequest, error) {
	if req.Level == "" {
		req.Level = "all"
	}

	var required []string // the codes the level needs, in hierarchy order
	switch req.Level {
	case "all", "province":
	case "city":
		required = []string{"province_code"}
	case "district":
		required = []string{"province_code", "city_code"}
	case "village":
		required = []string{"province_code", "city_code", "district_code"}
	default:
		return dtolocation.SyncRequest{}, domainlocation.NewInvalidSync("invalid sync level")
	}

	given := map[string]string{"province_code": req.ProvinceCode, "city_code": req.CityCode, "district_code": req.DistrictCode}
	for _, field := range required {
		if given[field] == "" {
			return dtolocation.SyncRequest{}, domainlocation.NewInvalidSync(requiredMessage(req.Level, required))
		}
	}
	for _, field := range []string{"province_code", "city_code", "district_code"} {
		if given[field] != "" {
			if err := validateCode(field, given[field]); err != nil {
				return dtolocation.SyncRequest{}, err
			}
		}
	}
	return req, nil
}

func requiredMessage(level string, fields []string) string {
	switch len(fields) {
	case 1:
		return fields[0] + " is required for " + level + " sync"
	case 2:
		return fields[0] + " and " + fields[1] + " are required for " + level + " sync"
	default:
		return fields[0] + ", " + fields[1] + ", and " + fields[2] + " are required for " + level + " sync"
	}
}
