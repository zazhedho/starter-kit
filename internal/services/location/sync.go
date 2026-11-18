package location

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zazhedho/logus"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

type syncProgress struct {
	Message       string
	ProvinceCount int
	CityCount     int
	DistrictCount int
	VillageCount  int
}

// runSyncJob runs one job under the service's lifecycle context. When Close
// cancels it, the job ends as failed/interrupted, the same state
// RecoverInterruptedJobs would give it after a restart.
func (s *Service) runSyncJob(jobID string, req dtolocation.SyncRequest) {
	jobCtx := s.baseCtx
	if !s.syncing.CompareAndSwap(false, true) {
		s.markSyncJobFailed(jobID, "Another location sync is already running in this service instance.")
		return
	}
	defer s.syncing.Store(false)

	if jobCtx.Err() != nil {
		s.markSyncJobInterrupted(jobID)
		return
	}

	job, err := s.repo.GetSyncJobByID(jobCtx, jobID)
	if err != nil {
		s.markIfInterrupted(jobCtx, jobID)
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to load location sync job %s: %v", jobID, err))
		return
	}

	startedAt := time.Now()
	job.Status = "running"
	job.Message = "Location sync is running"
	job.StartedAt = &startedAt
	job.UpdatedAt = &startedAt
	if err := s.repo.UpdateSyncJob(jobCtx, &job); err != nil {
		s.markIfInterrupted(jobCtx, jobID)
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
		if jobCtx.Err() != nil {
			s.markSyncJobInterrupted(job.ID)
			return
		}
		s.markSyncJobFailed(job.ID, err.Error())
		return
	}

	// The job finished; record it even if shutdown began a moment ago.
	ctx, cancel := s.settleContext()
	defer cancel()
	s.applySyncProgress(&job, result)
	finishedAt := time.Now()
	job.Status = "completed"
	job.Message = "Location sync completed"
	job.ErrorMessage = ""
	job.FinishedAt = &finishedAt
	job.UpdatedAt = &finishedAt
	if err := s.repo.UpdateSyncJob(ctx, &job); err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to mark location sync job %s as completed: %v", job.ID, err))
	}
}

func (s *Service) markSyncJobFailed(jobID, errorMessage string) {
	s.finishFailed(jobID, "Location sync failed", errorMessage)
}

// markSyncJobInterrupted ends a job cut short by shutdown with the exact
// message and error text FailActiveSyncJobs would write.
func (s *Service) markSyncJobInterrupted(jobID string) {
	s.finishFailed(jobID, "Location sync interrupted", shutdownMessage)
}

func (s *Service) finishFailed(jobID, message, errorMessage string) {
	ctx, cancel := s.settleContext()
	defer cancel()
	job, err := s.repo.GetSyncJobByID(ctx, jobID)
	if err != nil {
		logus.WriteLog(logus.LogLevelError, fmt.Sprintf("failed to load location sync job %s for failure update: %v", jobID, err))
		return
	}

	finishedAt := time.Now()
	job.Status = "failed"
	job.Message = message
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
		s.cache.DeleteKeys(context.Background(), provinceKey())
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
		s.cache.DeleteKeys(context.Background(), cityKey(req.ProvinceCode))
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
		s.cache.DeleteKeys(context.Background(), districtKey(req.CityCode))
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
		s.cache.DeleteKeys(context.Background(), villageKey(req.DistrictCode))
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
	s.cache.DeleteKeys(context.Background(), provinceKey())

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

	s.cache.DeleteKeys(context.Background(), cachePrefix)
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
		s.cache.DeleteKeys(context.Background(), cityKey(province.Code))
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
		s.cache.DeleteKeys(context.Background(), districtKey(city.Code))
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
		s.cache.DeleteKeys(context.Background(), villageKey(district.Code))
	}
	return nil
}
