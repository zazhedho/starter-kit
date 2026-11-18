package location

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
	"sync/atomic"
	"time"
)

type Service struct {
	repo       Repository
	cache      Cache
	httpClient *http.Client
	syncing    atomic.Bool

	baseURL    string
	sourceYear string
	cacheTTL   time.Duration
}

// Options is what the service needs besides its repository. Cache may be nil,
// which disables caching.
type Options struct {
	Cache             Cache
	BaseURL           string
	SourceYear        string
	Timeout, CacheTTL time.Duration
}

type syncProgress struct {
	Message       string
	ProvinceCount int
	CityCount     int
	DistrictCount int
	VillageCount  int
}

// defaultHTTPTimeout bounds outbound calls when Options.Timeout is not positive.
const defaultHTTPTimeout = 20 * time.Second

func NewService(repo Repository, opts Options) *Service {
	// Zero would mean "no timeout" to http.Client; never allow that, so a
	// project that builds Options by hand stays safe.
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	service := &Service{
		repo:       repo,
		cache:      opts.Cache,
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    opts.BaseURL,
		sourceYear: opts.SourceYear,
		cacheTTL:   opts.CacheTTL,
	}

	if err := service.repo.FailActiveSyncJobs(context.Background(), "Service restarted before the previous location sync completed."); err != nil {
		logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("failed to mark interrupted location sync jobs: %v", err))
	}

	return service
}

func (s *Service) GetProvince(ctx context.Context) ([]dtolocation.Location, error) {
	cacheKey := provinceKey()
	if data, ok := s.cacheOrNoop().Get(ctx, cacheKey); ok {
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
		fetched, fetchErr := s.fetchProvinces(ctx, "")
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
	if data, ok := s.cacheOrNoop().Get(ctx, cacheKey); ok {
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
		fetched, fetchErr := s.fetchCities(ctx, "", provinceCode)
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
	if data, ok := s.cacheOrNoop().Get(ctx, cacheKey); ok {
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
		fetched, fetchErr := s.fetchDistricts(ctx, "", city.ProvinceCode, cityCode)
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
	if data, ok := s.cacheOrNoop().Get(ctx, cacheKey); ok {
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
		fetched, fetchErr := s.fetchVillages(ctx, "", city.ProvinceCode, district.CityCode, districtCode)
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

func (s *Service) StartSync(ctx context.Context, req dtolocation.SyncRequest) (dtolocation.SyncJob, error) {
	normalizedReq, err := s.normalizeAndValidateRequest(req)
	if err != nil {
		return dtolocation.SyncJob{}, err
	}
	requestedByUserID := authkit.ScopeFrom(ctx).ActorUserID()

	activeJob, err := s.repo.GetActiveSyncJob(ctx)
	switch {
	case err == nil:
		return mapSyncJob(activeJob), domainlocation.ErrSyncRunning
	case !errors.Is(err, domainlocation.ErrNotFound):
		return dtolocation.SyncJob{}, err
	}

	now := time.Now()
	job := domainlocation.SyncJob{
		ID:           gokit.CreateUUID(),
		Status:       "queued",
		Level:        normalizedReq.Level,
		Year:         normalizedReq.Year,
		ProvinceCode: normalizedReq.ProvinceCode,
		CityCode:     normalizedReq.CityCode,
		DistrictCode: normalizedReq.DistrictCode,
		RequestedBy:  requestedByUserID,
		Message:      "Location sync queued",
		CreatedAt:    now,
		UpdatedAt:    &now,
	}

	if err := s.repo.CreateSyncJob(ctx, &job); err != nil {
		return dtolocation.SyncJob{}, err
	}

	go s.runSyncJob(job.ID, normalizedReq)

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
	req.Year = s.normalizeSyncYear(req.Year)

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

func (s *Service) runSyncJob(jobID string, req dtolocation.SyncRequest) {
	jobCtx := context.Background()
	if !s.syncing.CompareAndSwap(false, true) {
		s.markSyncJobFailed(jobCtx, jobID, "Another location sync is already running in this service instance.")
		return
	}
	defer s.syncing.Store(false)

	job, err := s.repo.GetSyncJobByID(jobCtx, jobID)
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to load location sync job %s: %v", jobID, err))
		return
	}

	startedAt := time.Now()
	job.Status = "running"
	job.Message = "Location sync is running"
	job.StartedAt = &startedAt
	job.UpdatedAt = &startedAt
	if err := s.repo.UpdateSyncJob(jobCtx, &job); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as running: %v", jobID, err))
		return
	}

	result, err := s.sync(jobCtx, req, func(progress syncProgress) {
		s.applySyncProgress(&job, progress)
		if updateErr := s.repo.UpdateSyncJob(jobCtx, &job); updateErr != nil {
			logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("failed to update location sync job progress %s: %v", job.ID, updateErr))
		}
	})
	if err != nil {
		s.markSyncJobFailed(jobCtx, job.ID, err.Error())
		return
	}

	s.applySyncProgress(&job, result)
	finishedAt := time.Now()
	job.Status = "completed"
	job.Message = "Location sync completed"
	job.ErrorMessage = ""
	job.FinishedAt = &finishedAt
	job.UpdatedAt = &finishedAt
	if err := s.repo.UpdateSyncJob(jobCtx, &job); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as completed: %v", job.ID, err))
	}
}

func (s *Service) markSyncJobFailed(ctx context.Context, jobID, errorMessage string) {
	job, err := s.repo.GetSyncJobByID(ctx, jobID)
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to load location sync job %s for failure update: %v", jobID, err))
		return
	}

	finishedAt := time.Now()
	job.Status = "failed"
	job.Message = "Location sync failed"
	job.ErrorMessage = errorMessage
	job.FinishedAt = &finishedAt
	job.UpdatedAt = &finishedAt
	if err := s.repo.UpdateSyncJob(ctx, &job); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as failed: %v", job.ID, err))
	}
}

func (s *Service) applySyncProgress(job *domainlocation.SyncJob, progress syncProgress) {
	job.Message = progress.Message
	job.ProvinceCount = progress.ProvinceCount
	job.CityCount = progress.CityCount
	job.DistrictCount = progress.DistrictCount
	job.VillageCount = progress.VillageCount
	job.UpdatedAt = new(time.Now())
}

func (s *Service) sync(ctx context.Context, req dtolocation.SyncRequest, progress func(syncProgress)) (syncProgress, error) {
	switch req.Level {
	case "province":
		progress(syncProgress{Message: "Fetching provinces"})
		provinces, err := s.fetchProvinces(ctx, req.Year)
		if err != nil {
			return syncProgress{}, err
		}
		if err := s.repo.UpsertProvinces(ctx, provinces); err != nil {
			return syncProgress{}, err
		}
		s.cacheOrNoop().DeleteKeys(context.Background(), provinceKey())
		return syncProgress{
			Message:       "Province sync completed",
			ProvinceCount: len(provinces),
		}, nil
	case "city":
		progress(syncProgress{Message: fmt.Sprintf("Fetching cities for province %s", req.ProvinceCode)})
		cities, err := s.fetchCities(ctx, req.Year, req.ProvinceCode)
		if err != nil {
			return syncProgress{}, err
		}
		if err := s.repo.UpsertCities(ctx, cities); err != nil {
			return syncProgress{}, err
		}
		s.cacheOrNoop().DeleteKeys(context.Background(), cityKey(req.ProvinceCode))
		return syncProgress{
			Message:   "City sync completed",
			CityCount: len(cities),
		}, nil
	case "district":
		progress(syncProgress{Message: fmt.Sprintf("Fetching districts for city %s", req.CityCode)})
		districts, err := s.fetchDistricts(ctx, req.Year, req.ProvinceCode, req.CityCode)
		if err != nil {
			return syncProgress{}, err
		}
		if err := s.repo.UpsertDistricts(ctx, districts); err != nil {
			return syncProgress{}, err
		}
		s.cacheOrNoop().DeleteKeys(context.Background(), districtKey(req.CityCode))
		return syncProgress{
			Message:       "District sync completed",
			DistrictCount: len(districts),
		}, nil
	case "village":
		progress(syncProgress{Message: fmt.Sprintf("Fetching villages for district %s", req.DistrictCode)})
		villages, err := s.fetchVillages(ctx, req.Year, req.ProvinceCode, req.CityCode, req.DistrictCode)
		if err != nil {
			return syncProgress{}, err
		}
		if err := s.repo.UpsertVillages(ctx, villages); err != nil {
			return syncProgress{}, err
		}
		s.cacheOrNoop().DeleteKeys(context.Background(), villageKey(req.DistrictCode))
		return syncProgress{
			Message:      "Village sync completed",
			VillageCount: len(villages),
		}, nil
	case "all":
		return s.syncAll(ctx, req.Year, progress)
	default:
		return syncProgress{}, errors.New("invalid sync level")
	}
}

func (s *Service) syncAll(ctx context.Context, year string, progress func(syncProgress)) (syncProgress, error) {
	progress(syncProgress{Message: "Fetching provinces"})
	provinces, err := s.fetchProvinces(ctx, year)
	if err != nil {
		return syncProgress{}, err
	}
	if err := s.repo.UpsertProvinces(ctx, provinces); err != nil {
		return syncProgress{}, err
	}
	s.cacheOrNoop().DeleteKeys(context.Background(), provinceKey())

	totals := syncProgress{ProvinceCount: len(provinces)}
	progress(syncProgress{
		Message:       "Provinces synced",
		ProvinceCount: len(provinces),
	})

	for provinceIndex, province := range provinces {
		if err := s.syncProvince(ctx, year, provinces, provinceIndex, province, &totals, progress); err != nil {
			return syncProgress{}, err
		}
	}

	s.cacheOrNoop().DeleteKeys(context.Background(), cachePrefix)
	return syncProgress{
		Message:       "Full location sync completed",
		ProvinceCount: len(provinces),
		CityCount:     totals.CityCount,
		DistrictCount: totals.DistrictCount,
		VillageCount:  totals.VillageCount,
	}, nil
}

func (s *Service) syncProvince(ctx context.Context, year string, provinces []domainlocation.Province, index int, province domainlocation.Province, totals *syncProgress, progress func(syncProgress)) error {
	cities, err := s.fetchCities(ctx, year, province.Code)
	if err != nil {
		return err
	}
	if len(cities) > 0 {
		if err := s.repo.UpsertCities(ctx, cities); err != nil {
			return err
		}
		totals.CityCount += len(cities)
		s.cacheOrNoop().DeleteKeys(context.Background(), cityKey(province.Code))
	}
	progress(syncProgress{
		Message:       fmt.Sprintf("Processed province %d/%d: %s", index+1, len(provinces), province.Name),
		ProvinceCount: totals.ProvinceCount,
		CityCount:     totals.CityCount,
		DistrictCount: totals.DistrictCount,
		VillageCount:  totals.VillageCount,
	})

	for cityIndex, city := range cities {
		if err := s.syncCity(ctx, year, province, city, totals); err != nil {
			return err
		}
		progress(syncProgress{
			Message:       fmt.Sprintf("Processed city %d/%d in province %s", cityIndex+1, len(cities), province.Name),
			ProvinceCount: totals.ProvinceCount,
			CityCount:     totals.CityCount,
			DistrictCount: totals.DistrictCount,
			VillageCount:  totals.VillageCount,
		})
	}
	return nil
}

func (s *Service) syncCity(ctx context.Context, year string, province domainlocation.Province, city domainlocation.City, totals *syncProgress) error {
	districts, err := s.fetchDistricts(ctx, year, province.Code, city.Code)
	if err != nil {
		return err
	}
	if len(districts) > 0 {
		if err := s.repo.UpsertDistricts(ctx, districts); err != nil {
			return err
		}
		totals.DistrictCount += len(districts)
		s.cacheOrNoop().DeleteKeys(context.Background(), districtKey(city.Code))
	}
	for _, district := range districts {
		villages, err := s.fetchVillages(ctx, year, province.Code, city.Code, district.Code)
		if err != nil {
			return err
		}
		if len(villages) == 0 {
			continue
		}
		if err := s.repo.UpsertVillages(ctx, villages); err != nil {
			return err
		}
		totals.VillageCount += len(villages)
		s.cacheOrNoop().DeleteKeys(context.Background(), villageKey(district.Code))
	}
	return nil
}

func (s *Service) fetchProvinces(ctx context.Context, year string) ([]domainlocation.Province, error) {
	_ = year
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/provinces", nil), "province")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.Province, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.Province{
			Code:      code,
			Name:      name,
			CreatedAt: now,
		})
	}

	return sortProvinces(items), nil
}

func (s *Service) fetchCities(ctx context.Context, year, provinceCode string) ([]domainlocation.City, error) {
	_ = year
	cleanProvinceCode := normalizeCodeSegment(provinceCode)
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/regencies", map[string]string{
		"province_code": cleanProvinceCode,
		"code_format":   "short",
	}), "city")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.City, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.City{
			Code:         normalizeChildCode(cleanProvinceCode, code),
			ProvinceCode: cleanProvinceCode,
			Name:         name,
			CreatedAt:    now,
		})
	}

	return sortCities(items), nil
}

func (s *Service) fetchDistricts(ctx context.Context, year, provinceCode, cityCode string) ([]domainlocation.District, error) {
	_ = year
	cleanProvinceCode := normalizeCodeSegment(provinceCode)
	cleanCityCode := normalizeCodeSegment(cityCode)
	cityParam := childCodeParam(cleanProvinceCode, cleanCityCode)
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/districts", map[string]string{
		"province_code": cleanProvinceCode,
		"regency_code":  cityParam,
		"code_format":   "short",
	}), "district")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.District, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.District{
			Code:      normalizeChildCode(cleanCityCode, code),
			CityCode:  cleanCityCode,
			Name:      name,
			CreatedAt: now,
		})
	}

	return sortDistricts(items), nil
}

func (s *Service) fetchVillages(ctx context.Context, year, provinceCode, cityCode, districtCode string) ([]domainlocation.Village, error) {
	_ = year
	cleanProvinceCode := normalizeCodeSegment(provinceCode)
	cleanCityCode := normalizeCodeSegment(cityCode)
	cleanDistrictCode := normalizeCodeSegment(districtCode)
	dataMap, err := s.fetchLocationMap(ctx, s.locationServiceURL("/api/locations/villages", map[string]string{
		"province_code": cleanProvinceCode,
		"regency_code":  childCodeParam(cleanProvinceCode, cleanCityCode),
		"district_code": childCodeParam(cleanCityCode, cleanDistrictCode),
		"code_format":   "short",
	}), "village")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.Village, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.Village{
			Code:         normalizeChildCode(cleanDistrictCode, code),
			DistrictCode: cleanDistrictCode,
			Name:         name,
			CreatedAt:    now,
		})
	}

	return sortVillages(items), nil
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

func (s *Service) normalizeSyncYear(year string) string {
	if year != "" {
		return year
	}

	if s.sourceYear != "" {
		return s.sourceYear
	}

	return fmt.Sprintf("%d", time.Now().Year())
}
