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

func fetchResponseBody(url, entity string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", entity, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

func unmarshalLocationMap(body []byte) (map[string]string, error) {
	var dataMap map[string]string
	if err := json.Unmarshal(body, &dataMap); err != nil {
		return nil, err
	}

	return dataMap, nil
}

func toSortedLocations(dataMap map[string]string) []domainlocation.Location {
	locations := make([]domainlocation.Location, 0, len(dataMap))
	for code, name := range dataMap {
		locations = append(locations, domainlocation.Location{
			Code: code,
			Name: name,
		})
	}

	sort.Slice(locations, func(i, j int) bool {
		return locations[i].Name < locations[j].Name
	})

	return locations
}

func locationCacheKey(entity string, parts ...string) string {
	return fmt.Sprintf("cache:location:%s:%s", entity, strings.Join(parts, ":"))
}

func (s *LocationService) getCachedLocations(cacheKey string) ([]domainlocation.Location, bool) {
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

	var locations []domainlocation.Location
	if err := json.Unmarshal([]byte(cached), &locations); err != nil {
		logger.WriteLog(logger.LogLevelWarn, fmt.Sprintf("location cache unmarshal failed; key=%s; err=%v", cacheKey, err))
		return nil, false
	}

	return locations, true
}

func (s *LocationService) setCachedLocations(cacheKey string, locations []domainlocation.Location) {
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
