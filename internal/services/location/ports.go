package servicelocation

import (
	"context"
	"time"

	"starter-kit/internal/dto"
)

// Cache is the read-through cache the location service uses. Implementations
// live in internal/infrastructure/cache and must treat every failure as a miss
// (Get) or a no-op (Set, DeleteKeys): the cache is an optimisation, never a
// dependency.
type Cache interface {
	Get(ctx context.Context, key string) ([]dto.Location, bool)
	Set(ctx context.Context, key string, locations []dto.Location, ttl time.Duration)
	// DeleteKeys removes every key that starts with prefix.
	DeleteKeys(ctx context.Context, prefix string)
}

// noopCache stands in when no Cache is configured: every lookup misses.
type noopCache struct{}

func (noopCache) Get(context.Context, string) ([]dto.Location, bool)         { return nil, false }
func (noopCache) Set(context.Context, string, []dto.Location, time.Duration) {}
func (noopCache) DeleteKeys(context.Context, string)                         {}

func (s *LocationService) cacheOrNoop() Cache {
	if s.cache == nil {
		return noopCache{}
	}
	return s.cache
}
