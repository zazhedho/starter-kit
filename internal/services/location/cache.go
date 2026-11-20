package location

import (
	"context"
	"fmt"

	dtolocation "starter-kit/internal/dto/location"
)

// Cache key formats. Deployed Redis data uses these exact strings, so they
// must never change without a migration plan; cache_test.go pins them.
const cachePrefix = "location:"

func provinceKey() string { return "location:province" }

func cityKey(provinceCode string) string { return fmt.Sprintf("location:city:%s", provinceCode) }

func districtKey(cityCode string) string { return fmt.Sprintf("location:district:%s", cityCode) }

func villageKey(districtCode string) string { return fmt.Sprintf("location:village:%s", districtCode) }

func (s *Service) setLocationCache(ctx context.Context, cacheKey string, locations []dtolocation.Location) {
	// A non-positive TTL would store the entry without expiry; skip instead.
	if len(locations) == 0 || s.cacheTTL <= 0 {
		return
	}
	s.cache.Set(ctx, cacheKey, locations, s.cacheTTL)
}

// invalidate deletes the cached keys that start with prefix. It outlives a
// canceled sync so a stale entry is never left behind.
func (s *Service) invalidate(prefix string) {
	s.cache.DeleteKeys(context.Background(), prefix)
}
