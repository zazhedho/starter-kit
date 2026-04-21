package servicelocation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/dto"
	interfacelocation "starter-kit/internal/interfaces/location"
	"starter-kit/pkg/logger"
	"starter-kit/utils"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type LocationService struct {
	Repo       interfacelocation.RepoLocationInterface
	Redis      *redis.Client
	HTTPClient *http.Client
	syncing    atomic.Bool
}

type syncProgress struct {
	Message       string
	ProvinceCount int
	CityCount     int
	DistrictCount int
	VillageCount  int
}

var ErrLocationSyncRunning = errors.New("location sync is already running")

func NewLocationService(repo interfacelocation.RepoLocationInterface, redisClients ...*redis.Client) *LocationService {
	var redisClient *redis.Client
	if len(redisClients) > 0 {
		redisClient = redisClients[0]
	}

	service := &LocationService{
		Repo:       repo,
		Redis:      redisClient,
		HTTPClient: &http.Client{Timeout: 20 * time.Second},
	}

	if err := service.Repo.FailActiveSyncJobs(context.Background(), "Service restarted before the previous location sync completed."); err != nil {
		logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("failed to mark interrupted location sync jobs: %v", err))
	}

	return service
}

func (s *LocationService) GetProvince(ctx context.Context) ([]dto.Location, error) {
	cacheKey := provinceCacheKey()
	if data, ok := s.getCachedLocations(ctx, cacheKey); ok {
		return data, nil
	}

	rows, err := s.Repo.ListProvinces(ctx)
	if err != nil {
		return nil, err
	}

	locations := mapProvinces(rows)
	s.setCachedLocations(ctx, cacheKey, locations)
	return locations, nil
}

func (s *LocationService) GetCity(ctx context.Context, provinceCode string) ([]dto.Location, error) {
	cacheKey := cityCacheKey(provinceCode)
	if data, ok := s.getCachedLocations(ctx, cacheKey); ok {
		return data, nil
	}

	rows, err := s.Repo.ListCitiesByProvince(ctx, provinceCode)
	if err != nil {
		return nil, err
	}

	locations := mapCities(rows)
	s.setCachedLocations(ctx, cacheKey, locations)
	return locations, nil
}

func (s *LocationService) GetDistrict(ctx context.Context, cityCode string) ([]dto.Location, error) {
	cacheKey := districtCacheKey(cityCode)
	if data, ok := s.getCachedLocations(ctx, cacheKey); ok {
		return data, nil
	}

	rows, err := s.Repo.ListDistrictsByCity(ctx, cityCode)
	if err != nil {
		return nil, err
	}

	locations := mapDistricts(rows)
	s.setCachedLocations(ctx, cacheKey, locations)
	return locations, nil
}

func (s *LocationService) GetVillage(ctx context.Context, districtCode string) ([]dto.Location, error) {
	cacheKey := villageCacheKey(districtCode)
	if data, ok := s.getCachedLocations(ctx, cacheKey); ok {
		return data, nil
	}

	rows, err := s.Repo.ListVillagesByDistrict(ctx, districtCode)
	if err != nil {
		return nil, err
	}

	locations := mapVillages(rows)
	s.setCachedLocations(ctx, cacheKey, locations)
	return locations, nil
}

func (s *LocationService) StartSync(ctx context.Context, req dto.SyncLocationRequest, requestedByUserID string) (dto.LocationSyncJob, error) {
	normalizedReq, err := s.normalizeAndValidateRequest(req)
	if err != nil {
		return dto.LocationSyncJob{}, err
	}

	activeJob, err := s.Repo.GetActiveSyncJob(ctx)
	switch {
	case err == nil:
		return mapSyncJob(activeJob), ErrLocationSyncRunning
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return dto.LocationSyncJob{}, err
	}

	now := time.Now()
	job := domainlocation.SyncJob{
		ID:           utils.CreateUUID(),
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

	if err := s.Repo.CreateSyncJob(ctx, &job); err != nil {
		return dto.LocationSyncJob{}, err
	}

	go s.runSyncJob(job.ID, normalizedReq)

	return mapSyncJob(job), nil
}

func (s *LocationService) GetSyncJob(ctx context.Context, id string) (dto.LocationSyncJob, error) {
	job, err := s.Repo.GetSyncJobByID(ctx, id)
	if err != nil {
		return dto.LocationSyncJob{}, err
	}

	return mapSyncJob(job), nil
}

func (s *LocationService) normalizeAndValidateRequest(req dto.SyncLocationRequest) (dto.SyncLocationRequest, error) {
	req.Level = normalizeSyncLevel(req.Level)
	req.Year = normalizeSyncYear(req.Year)

	switch req.Level {
	case "province":
		return req, nil
	case "city":
		if req.ProvinceCode == "" {
			return dto.SyncLocationRequest{}, errors.New("province_code is required for city sync")
		}
		return req, nil
	case "district":
		if req.ProvinceCode == "" || req.CityCode == "" {
			return dto.SyncLocationRequest{}, errors.New("province_code and city_code are required for district sync")
		}
		return req, nil
	case "village":
		if req.ProvinceCode == "" || req.CityCode == "" || req.DistrictCode == "" {
			return dto.SyncLocationRequest{}, errors.New("province_code, city_code, and district_code are required for village sync")
		}
		return req, nil
	case "all":
		return req, nil
	default:
		return dto.SyncLocationRequest{}, errors.New("invalid sync level")
	}
}

func (s *LocationService) runSyncJob(jobID string, req dto.SyncLocationRequest) {
	jobCtx := context.Background()
	if !s.syncing.CompareAndSwap(false, true) {
		s.markSyncJobFailed(jobCtx, jobID, "Another location sync is already running in this service instance.")
		return
	}
	defer s.syncing.Store(false)

	job, err := s.Repo.GetSyncJobByID(jobCtx, jobID)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("failed to load location sync job %s: %v", jobID, err))
		return
	}

	startedAt := time.Now()
	job.Status = "running"
	job.Message = "Location sync is running"
	job.StartedAt = &startedAt
	job.UpdatedAt = &startedAt
	if err := s.Repo.UpdateSyncJob(jobCtx, &job); err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as running: %v", jobID, err))
		return
	}

	result, err := s.sync(jobCtx, req, func(progress syncProgress) {
		s.applySyncProgress(&job, progress)
		if updateErr := s.Repo.UpdateSyncJob(jobCtx, &job); updateErr != nil {
			logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("failed to update location sync job progress %s: %v", job.ID, updateErr))
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
	if err := s.Repo.UpdateSyncJob(jobCtx, &job); err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as completed: %v", job.ID, err))
	}
}

func (s *LocationService) markSyncJobFailed(ctx context.Context, jobID, errorMessage string) {
	job, err := s.Repo.GetSyncJobByID(ctx, jobID)
	if err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("failed to load location sync job %s for failure update: %v", jobID, err))
		return
	}

	finishedAt := time.Now()
	job.Status = "failed"
	job.Message = "Location sync failed"
	job.ErrorMessage = errorMessage
	job.FinishedAt = &finishedAt
	job.UpdatedAt = &finishedAt
	if err := s.Repo.UpdateSyncJob(ctx, &job); err != nil {
		logger.WriteLog(logger.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as failed: %v", job.ID, err))
	}
}

func (s *LocationService) applySyncProgress(job *domainlocation.SyncJob, progress syncProgress) {
	job.Message = progress.Message
	job.ProvinceCount = progress.ProvinceCount
	job.CityCount = progress.CityCount
	job.DistrictCount = progress.DistrictCount
	job.VillageCount = progress.VillageCount
	job.UpdatedAt = new(time.Now())
}

func (s *LocationService) sync(ctx context.Context, req dto.SyncLocationRequest, progress func(syncProgress)) (syncProgress, error) {
	switch req.Level {
	case "province":
		progress(syncProgress{Message: "Fetching provinces"})
		provinces, err := s.fetchProvinces(ctx, req.Year)
		if err != nil {
			return syncProgress{}, err
		}
		if err := s.Repo.UpsertProvinces(ctx, provinces); err != nil {
			return syncProgress{}, err
		}
		s.deleteCacheKeys(provinceCacheKey())
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
		if err := s.Repo.UpsertCities(ctx, cities); err != nil {
			return syncProgress{}, err
		}
		s.deleteCacheKeys(cityCacheKey(req.ProvinceCode))
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
		if err := s.Repo.UpsertDistricts(ctx, districts); err != nil {
			return syncProgress{}, err
		}
		s.deleteCacheKeys(districtCacheKey(req.CityCode))
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
		if err := s.Repo.UpsertVillages(ctx, villages); err != nil {
			return syncProgress{}, err
		}
		s.deleteCacheKeys(villageCacheKey(req.DistrictCode))
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

func (s *LocationService) syncAll(ctx context.Context, year string, progress func(syncProgress)) (syncProgress, error) {
	progress(syncProgress{Message: "Fetching provinces"})
	provinces, err := s.fetchProvinces(ctx, year)
	if err != nil {
		return syncProgress{}, err
	}
	if err := s.Repo.UpsertProvinces(ctx, provinces); err != nil {
		return syncProgress{}, err
	}
	s.deleteCacheKeys(provinceCacheKey())

	var (
		cityCount     int
		districtCount int
		villageCount  int
	)
	progress(syncProgress{
		Message:       "Provinces synced",
		ProvinceCount: len(provinces),
	})

	for provinceIndex, province := range provinces {
		cities, err := s.fetchCities(ctx, year, province.Code)
		if err != nil {
			return syncProgress{}, err
		}
		if len(cities) > 0 {
			if err := s.Repo.UpsertCities(ctx, cities); err != nil {
				return syncProgress{}, err
			}
			cityCount += len(cities)
			s.deleteCacheKeys(cityCacheKey(province.Code))
		}

		progress(syncProgress{
			Message:       fmt.Sprintf("Processed province %d/%d: %s", provinceIndex+1, len(provinces), province.Name),
			ProvinceCount: len(provinces),
			CityCount:     cityCount,
			DistrictCount: districtCount,
			VillageCount:  villageCount,
		})

		for cityIndex, city := range cities {
			districts, err := s.fetchDistricts(ctx, year, province.Code, city.Code)
			if err != nil {
				return syncProgress{}, err
			}
			if len(districts) > 0 {
				if err := s.Repo.UpsertDistricts(ctx, districts); err != nil {
					return syncProgress{}, err
				}
				districtCount += len(districts)
				s.deleteCacheKeys(districtCacheKey(city.Code))
			}

			for _, district := range districts {
				villages, err := s.fetchVillages(ctx, year, province.Code, city.Code, district.Code)
				if err != nil {
					return syncProgress{}, err
				}
				if len(villages) > 0 {
					if err := s.Repo.UpsertVillages(ctx, villages); err != nil {
						return syncProgress{}, err
					}
					villageCount += len(villages)
					s.deleteCacheKeys(villageCacheKey(district.Code))
				}
			}

			progress(syncProgress{
				Message:       fmt.Sprintf("Processed city %d/%d in province %s", cityIndex+1, len(cities), province.Name),
				ProvinceCount: len(provinces),
				CityCount:     cityCount,
				DistrictCount: districtCount,
				VillageCount:  villageCount,
			})
		}
	}

	s.deleteCacheKeys(locationCachePrefix())
	return syncProgress{
		Message:       "Full location sync completed",
		ProvinceCount: len(provinces),
		CityCount:     cityCount,
		DistrictCount: districtCount,
		VillageCount:  villageCount,
	}, nil
}

func (s *LocationService) fetchProvinces(ctx context.Context, year string) ([]domainlocation.Province, error) {
	dataMap, err := s.fetchLocationMap(ctx, fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_pro?thn=%s", year), "province")
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

func (s *LocationService) fetchCities(ctx context.Context, year, provinceCode string) ([]domainlocation.City, error) {
	dataMap, err := s.fetchLocationMap(ctx, fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_kab?thn=%s&lvl=11&pro=%s", year, provinceCode), "city")
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.City, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.City{
			Code:         normalizeChildCode(provinceCode, code),
			ProvinceCode: provinceCode,
			Name:         name,
			CreatedAt:    now,
		})
	}

	return sortCities(items), nil
}

func (s *LocationService) fetchDistricts(ctx context.Context, year, provinceCode, cityCode string) ([]domainlocation.District, error) {
	var (
		dataMap map[string]string
		err     error
	)

	for _, cityParam := range childCodeCandidates(provinceCode, cityCode) {
		dataMap, err = s.fetchLocationMap(ctx, fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_kec?thn=%s&lvl=12&pro=%s&kab=%s", year, provinceCode, cityParam), "district")
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.District, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.District{
			Code:      normalizeChildCode(cityCode, code),
			CityCode:  cityCode,
			Name:      name,
			CreatedAt: now,
		})
	}

	return sortDistricts(items), nil
}

func (s *LocationService) fetchVillages(ctx context.Context, year, provinceCode, cityCode, districtCode string) ([]domainlocation.Village, error) {
	var (
		dataMap map[string]string
		err     error
	)

	cityCandidates := childCodeCandidates(provinceCode, cityCode)
	districtCandidates := childCodeCandidates(cityCode, districtCode)

	for _, cityParam := range cityCandidates {
		for _, districtParam := range districtCandidates {
			dataMap, err = s.fetchLocationMap(ctx, fmt.Sprintf("https://sipedas.pertanian.go.id/api/wilayah/list_des?thn=%s&lvl=13&pro=%s&kab=%s&kec=%s", year, provinceCode, cityParam, districtParam), "village")
			if err == nil {
				break
			}
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	items := make([]domainlocation.Village, 0, len(dataMap))
	now := time.Now()
	for code, name := range dataMap {
		items = append(items, domainlocation.Village{
			Code:         normalizeChildCode(districtCode, code),
			DistrictCode: districtCode,
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

func normalizeSyncYear(year string) string {
	if year != "" {
		return year
	}

	defaultYear := utils.GetEnv("LOCATION_SOURCE_YEAR", "")
	if defaultYear != "" {
		return defaultYear
	}

	return fmt.Sprintf("%d", time.Now().Year())
}

var _ interfacelocation.ServiceLocationInterface = (*LocationService)(nil)
