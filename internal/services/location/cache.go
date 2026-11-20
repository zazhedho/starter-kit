package location

import (
	"context"
	"fmt"

	dtolocation "starter-kit/internal/dto/location"
)

// Deployed Redis data uses these exact strings: never change them without a migration plan.
const cachePrefix = "location:"

func provinceKey() string { return "location:province" }

func cityKey(provinceCode string) string { return fmt.Sprintf("location:city:%s", provinceCode) }

func districtKey(cityCode string) string { return fmt.Sprintf("location:district:%s", cityCode) }

func villageKey(districtCode string) string { return fmt.Sprintf("location:village:%s", districtCode) }

func (s *Service) setLocationCache(ctx context.Context, cacheKey string, locations []dtolocation.Location) {
	if len(locations) == 0 || s.cacheTTL <= 0 {
		return
	}
	s.cache.Set(ctx, cacheKey, locations, s.cacheTTL)
}

// Outlives a canceled sync so a stale entry is never left behind.
func (s *Service) invalidate(prefix string) {
	s.cache.DeleteKeys(context.Background(), prefix)
}
