package servicelocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	domainlocation "starter-kit/internal/domain/location"
	"starter-kit/internal/dto"
	"starter-kit/pkg/logger"
	"starter-kit/utils"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultLocationCacheTTL = 180 * 24 * time.Hour

func locationCacheTTL() time.Duration {
	ttl := utils.GetEnv("LOCATION_CACHE_TTL", defaultLocationCacheTTL)
	if ttl <= 0 {
		return defaultLocationCacheTTL
	}

	return ttl
}

func (s *LocationService) fetchLocationMap(ctx context.Context, url, entity string) (map[string]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare %s request: %w", entity, err)
	}

	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", entity, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for %s: %d", entity, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response body: %w", entity, err)
	}

	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, fmt.Errorf("failed to decode %s response: %w", entity, err)
	}

	return dataMap, nil
}

func provinceCacheKey() string {
	return "location:province"
}

func cityCacheKey(provinceCode string) string {
	return fmt.Sprintf("location:city:%s", provinceCode)
}

func districtCacheKey(cityCode string) string {
	return fmt.Sprintf("location:district:%s", cityCode)
}

func villageCacheKey(districtCode string) string {
	return fmt.Sprintf("location:village:%s", districtCode)
}

func locationCachePrefix() string {
	return "location:"
}

func (s *LocationService) getCachedLocations(cacheKey string) ([]dto.Location, bool) {
	if s.Redis == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cached, err := s.Redis.Get(ctx, cacheKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache get failed; key=%s; err=%v", cacheKey, err))
		}
		return nil, false
	}

	var locations []dto.Location
	if err := json.Unmarshal([]byte(cached), &locations); err != nil {
		logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache unmarshal failed; key=%s; err=%v", cacheKey, err))
		return nil, false
	}

	return locations, true
}

func (s *LocationService) setCachedLocations(cacheKey string, locations []dto.Location) {
	if s.Redis == nil {
		return
	}

	payload, err := json.Marshal(locations)
	if err != nil {
		logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache marshal failed; key=%s; err=%v", cacheKey, err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.Redis.Set(ctx, cacheKey, payload, locationCacheTTL()).Err(); err != nil {
		logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache set failed; key=%s; err=%v", cacheKey, err))
	}
}

func (s *LocationService) deleteCacheKeys(pattern string) {
	if s.Redis == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var keys []string
	var cursor uint64
	for {
		foundKeys, nextCursor, err := s.Redis.Scan(ctx, cursor, pattern+"*", 100).Result()
		if err != nil {
			logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache scan failed; pattern=%s; err=%v", pattern, err))
			return
		}
		keys = append(keys, foundKeys...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(keys) == 0 {
		return
	}
	if err := s.Redis.Del(ctx, keys...).Err(); err != nil {
		logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache delete failed; pattern=%s; err=%v", pattern, err))
	}
}

func mapProvinces(rows []domainlocation.Province) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapCities(rows []domainlocation.City) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapDistricts(rows []domainlocation.District) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func mapVillages(rows []domainlocation.Village) []dto.Location {
	locations := make([]dto.Location, 0, len(rows))
	for _, row := range rows {
		locations = append(locations, dto.Location{Code: row.Code, Name: row.Name})
	}
	return locations
}

func sortProvinces(items []domainlocation.Province) []domainlocation.Province {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func sortCities(items []domainlocation.City) []domainlocation.City {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func sortDistricts(items []domainlocation.District) []domainlocation.District {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func sortVillages(items []domainlocation.Village) []domainlocation.Village {
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

func mapSyncJob(job domainlocation.SyncJob) dto.LocationSyncJob {
	return dto.LocationSyncJob{
		ID:            job.ID,
		Status:        job.Status,
		Level:         job.Level,
		Year:          job.Year,
		ProvinceCode:  job.ProvinceCode,
		CityCode:      job.CityCode,
		DistrictCode:  job.DistrictCode,
		RequestedBy:   job.RequestedBy,
		Message:       job.Message,
		ErrorMessage:  job.ErrorMessage,
		ProvinceCount: job.ProvinceCount,
		CityCount:     job.CityCount,
		DistrictCount: job.DistrictCount,
		VillageCount:  job.VillageCount,
		StartedAt:     formatTimeISO(job.StartedAt),
		FinishedAt:    formatTimeISO(job.FinishedAt),
		CreatedAt:     job.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     formatTimeISO(job.UpdatedAt),
	}
}

func formatTimeISO(value *time.Time) string {
	if value == nil {
		return ""
	}

	return value.Format(time.RFC3339)
}

func normalizeChildCode(parentCode, code string) string {
	trimmedCode := strings.TrimSpace(code)
	if trimmedCode == "" {
		return ""
	}

	trimmedParent := strings.TrimSpace(parentCode)
	if trimmedParent == "" {
		return trimmedCode
	}

	if strings.HasPrefix(trimmedCode, trimmedParent) && len(trimmedCode) > len(trimmedParent) {
		return trimmedCode
	}

	return trimmedParent + trimmedCode
}

func childCodeCandidates(parentCode, code string) []string {
	trimmedCode := strings.TrimSpace(code)
	if trimmedCode == "" {
		return nil
	}

	candidates := make([]string, 0, 2)
	trimmedParent := strings.TrimSpace(parentCode)
	if trimmedParent != "" && strings.HasPrefix(trimmedCode, trimmedParent) {
		suffix := strings.TrimPrefix(trimmedCode, trimmedParent)
		if suffix != "" {
			candidates = append(candidates, suffix)
		}
	}

	candidates = append(candidates, trimmedCode)

	unique := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		unique = append(unique, candidate)
	}

	return unique
}
