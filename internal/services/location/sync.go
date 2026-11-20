package location

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zazhedho/logus"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

// A sync is an upsert: it adds rows and updates names, and removes nothing. A
// location the Location Service stopped listing stays in the tables.

// runSyncJob runs one job of this instance until Interrupt cancels it. A
// heartbeat shows it is alive; a job taken over by another instance stops.
func (s *Service) runSyncJob(jobID string, req dtolocation.SyncRequest) {
	ctx, cancelJob := context.WithCancel(s.baseCtx)
	defer cancelJob()

	if ctx.Err() != nil {
		s.markInterrupted(jobID)
		return
	}
	if err := s.repo.StartSyncJob(ctx, jobID, s.instanceID, time.Now()); err != nil {
		s.markIfInterrupted(ctx, jobID)
		logus.Logf(logus.LevelError, "failed to mark location sync job %s as running: %v", jobID, err)
		return
	}

	stopHeartbeat := s.beat(ctx, cancelJob, jobID)
	defer stopHeartbeat()

	progress := &progressWriter{s: s, ctx: ctx, jobID: jobID}
	result, err := s.sync(ctx, req, progress.report)
	if err != nil {
		switch {
		case s.baseCtx.Err() != nil:
			s.markInterrupted(jobID)
		case ctx.Err() != nil:
			logus.Logf(logus.LevelWarn, "location sync job %s was taken over by another instance; stopping", jobID)
		default:
			s.markFailed(jobID, err.Error())
		}
		return
	}

	// The job finished; record it even if shutdown began a moment ago.
	s.settle(jobID, func(ctx context.Context) error {
		if err := s.repo.SaveSyncProgress(ctx, jobID, s.instanceID, result, time.Now()); err != nil {
			return err
		}
		return s.repo.FinishSyncJob(ctx, jobID, s.instanceID, domainlocation.SyncFinish{
			Status: "completed", Message: "Location sync completed",
		}, time.Now())
	}, "completed")
}

// beat reports the job's heartbeat every heartbeatInterval until the returned
// stop function is called. When the job no longer belongs to this instance it
// cancels the job.
func (s *Service) beat(ctx context.Context, cancelJob context.CancelFunc, jobID string) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(s.heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := s.repo.TouchSyncJob(ctx, jobID, s.instanceID, time.Now())
				switch {
				case errors.Is(err, domainlocation.ErrNotFound):
					cancelJob()
					return
				case err != nil && ctx.Err() == nil:
					logus.Logf(logus.LevelWarn, "failed to send the heartbeat of location sync job %s: %v", jobID, err)
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

// progressWriter stores a job's progress, at most once per progressInterval so
// that a sync of thousands of rows does not become thousands of writes.
type progressWriter struct {
	s     *Service
	ctx   context.Context
	jobID string

	mu   sync.Mutex
	last time.Time
}

func (w *progressWriter) report(p domainlocation.SyncProgress) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.last.IsZero() && time.Since(w.last) < w.s.progressInterval {
		return
	}
	w.last = time.Now()
	if err := w.s.repo.SaveSyncProgress(w.ctx, w.jobID, w.s.instanceID, p, time.Now()); err != nil && w.ctx.Err() == nil {
		logus.Logf(logus.LevelWarn, "failed to update location sync job progress %s: %v", w.jobID, err)
	}
}

func (s *Service) markFailed(jobID, errorMessage string) {
	s.finishFailed(jobID, "Location sync failed", errorMessage)
}

// markInterrupted ends a job cut short by shutdown with the message and error
// text a stale takeover writes.
func (s *Service) markInterrupted(jobID string) {
	s.finishFailed(jobID, "Location sync interrupted", shutdownMessage)
}

func (s *Service) finishFailed(jobID, message, errorMessage string) {
	s.settle(jobID, func(ctx context.Context) error {
		return s.repo.FinishSyncJob(ctx, jobID, s.instanceID, domainlocation.SyncFinish{
			Status: "failed", Message: message, ErrorMessage: errorMessage,
		}, time.Now())
	}, "failed")
}

// markIfInterrupted records the interrupted state when ctx was canceled, so a
// job that never got going is not left queued.
func (s *Service) markIfInterrupted(ctx context.Context, jobID string) {
	if ctx.Err() != nil {
		s.markInterrupted(jobID)
	}
}

// syncLevel fetches one level, stores it and drops the cache keys it covers.
func syncLevel[T any](ctx context.Context, s *Service, report func(domainlocation.SyncProgress), message string,
	fetch func(context.Context) ([]T, error), upsert func(context.Context, []T) error, cacheKey string) ([]T, error) {
	report(domainlocation.SyncProgress{Message: message})
	rows, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	if err := upsert(ctx, rows); err != nil {
		return nil, err
	}
	s.invalidate(cacheKey)
	return rows, nil
}

func (s *Service) sync(ctx context.Context, req dtolocation.SyncRequest, report func(domainlocation.SyncProgress)) (domainlocation.SyncProgress, error) {
	switch req.Level {
	case "province":
		rows, err := syncLevel(ctx, s, report, "Fetching provinces", s.fetchProvinces, s.repo.UpsertProvinces, provinceKey())
		return domainlocation.SyncProgress{Message: "Province sync completed", ProvinceCount: len(rows)}, err
	case "city":
		rows, err := syncLevel(ctx, s, report, fmt.Sprintf("Fetching cities for province %s", req.ProvinceCode),
			func(ctx context.Context) ([]domainlocation.City, error) { return s.fetchCities(ctx, req.ProvinceCode) },
			s.repo.UpsertCities, cityKey(req.ProvinceCode))
		return domainlocation.SyncProgress{Message: "City sync completed", CityCount: len(rows)}, err
	case "district":
		rows, err := syncLevel(ctx, s, report, fmt.Sprintf("Fetching districts for city %s", req.CityCode),
			func(ctx context.Context) ([]domainlocation.District, error) {
				return s.fetchDistricts(ctx, req.ProvinceCode, req.CityCode)
			},
			s.repo.UpsertDistricts, districtKey(req.CityCode))
		return domainlocation.SyncProgress{Message: "District sync completed", DistrictCount: len(rows)}, err
	case "village":
		rows, err := syncLevel(ctx, s, report, fmt.Sprintf("Fetching villages for district %s", req.DistrictCode),
			func(ctx context.Context) ([]domainlocation.Village, error) {
				return s.fetchVillages(ctx, req.ProvinceCode, req.CityCode, req.DistrictCode)
			},
			s.repo.UpsertVillages, villageKey(req.DistrictCode))
		return domainlocation.SyncProgress{Message: "Village sync completed", VillageCount: len(rows)}, err
	case "all":
		return s.syncAll(ctx, report)
	default:
		return domainlocation.SyncProgress{}, errors.New("invalid sync level")
	}
}

func (s *Service) syncAll(ctx context.Context, report func(domainlocation.SyncProgress)) (domainlocation.SyncProgress, error) {
	provinces, err := syncLevel(ctx, s, report, "Fetching provinces", s.fetchProvinces, s.repo.UpsertProvinces, provinceKey())
	if err != nil {
		return domainlocation.SyncProgress{}, err
	}

	totals := domainlocation.SyncProgress{ProvinceCount: len(provinces)}
	report(domainlocation.SyncProgress{Message: "Provinces synced", ProvinceCount: len(provinces)})

	for i, province := range provinces {
		if err := s.syncProvince(ctx, provinces, i, province, &totals, report); err != nil {
			return domainlocation.SyncProgress{}, err
		}
	}

	s.invalidate(cachePrefix)
	totals.Message = "Full location sync completed"
	return totals, nil
}

func (s *Service) syncProvince(ctx context.Context, provinces []domainlocation.Province, index int, province domainlocation.Province, totals *domainlocation.SyncProgress, report func(domainlocation.SyncProgress)) error {
	cities, err := s.fetchCities(ctx, province.Code)
	if err != nil {
		return err
	}
	if len(cities) > 0 {
		if err := s.repo.UpsertCities(ctx, cities); err != nil {
			return err
		}
		totals.CityCount += len(cities)
		s.invalidate(cityKey(province.Code))
	}
	report(withMessage(*totals, fmt.Sprintf("Processed province %d/%d: %s", index+1, len(provinces), province.Name)))

	for cityIndex, city := range cities {
		if err := s.syncCity(ctx, province, city, totals); err != nil {
			return err
		}
		report(withMessage(*totals, fmt.Sprintf("Processed city %d/%d in province %s", cityIndex+1, len(cities), province.Name)))
	}
	return nil
}

func (s *Service) syncCity(ctx context.Context, province domainlocation.Province, city domainlocation.City, totals *domainlocation.SyncProgress) error {
	districts, err := s.fetchDistricts(ctx, province.Code, city.Code)
	if err != nil {
		return err
	}
	if len(districts) > 0 {
		if err := s.repo.UpsertDistricts(ctx, districts); err != nil {
			return err
		}
		totals.DistrictCount += len(districts)
		s.invalidate(districtKey(city.Code))
	}
	for _, district := range districts {
		villages, err := s.fetchVillages(ctx, province.Code, city.Code, district.Code)
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
		s.invalidate(villageKey(district.Code))
	}
	return nil
}

func withMessage(p domainlocation.SyncProgress, message string) domainlocation.SyncProgress {
	p.Message = message
	return p
}
