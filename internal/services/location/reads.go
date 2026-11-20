package location

import (
	"context"

	dtolocation "starter-kit/internal/dto/location"
)

// level describes how one level of the hierarchy is read: from the cache, then
// the table, then, when the table has nothing, from the Location Service.
type level[T any] struct {
	key  string
	list func(ctx context.Context) ([]T, error)
	view func(T) dtolocation.Location
	// fetch checks that the parent exists locally and returns the rows the
	// Location Service has for it; it never returns rows of another parent.
	fetch  func(ctx context.Context) ([]T, error)
	upsert func(ctx context.Context, rows []T) error
}

func readLevel[T any](ctx context.Context, s *Service, l level[T]) ([]dtolocation.Location, error) {
	if data, ok := s.cache.Get(ctx, l.key); ok && len(data) > 0 {
		return data, nil
	}

	rows, err := l.list(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		if rows, err = fillLevel(ctx, s, l); err != nil {
			return nil, err
		}
	}

	locations := views(rows, l.view)
	s.setLocationCache(ctx, l.key, locations)
	return locations, nil
}

// fillLevel fetches and stores a level the table has no rows for. Concurrent
// reads of the same level share one call, and an empty answer is remembered for
// a while, so a public read cannot make the service call the Location Service
// over and over.
func fillLevel[T any](ctx context.Context, s *Service, l level[T]) ([]T, error) {
	if s.misses.has(l.key) {
		return nil, nil
	}
	// The call is shared, so it must not end with the first caller's request.
	shared := context.WithoutCancel(ctx)
	rows, err, _ := s.flights.Do(l.key, func() (any, error) {
		fetched, err := l.fetch(shared)
		if err != nil {
			return nil, err
		}
		if len(fetched) == 0 {
			s.misses.add(l.key)
			return fetched, nil
		}
		return fetched, l.upsert(shared, fetched)
	})
	if err != nil {
		return nil, err
	}
	return rows.([]T), nil
}
