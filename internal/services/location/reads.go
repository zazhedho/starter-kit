package location

import (
	"context"
	"errors"
	"fmt"

	domainlocation "starter-kit/internal/domain/location"
	dtolocation "starter-kit/internal/dto/location"
)

// errRecentFailure answers a read while a failed Location Service call is remembered.
var errRecentFailure = fmt.Errorf("%w: the call failed a moment ago", domainlocation.ErrUpstream)

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
// reads share one call, and an empty answer or a brief failure is remembered, so
// public reads cannot hammer the Location Service.
func fillLevel[T any](ctx context.Context, s *Service, l level[T]) ([]T, error) {
	if failed, found := s.misses.lookup(l.key); found {
		if failed {
			return nil, errRecentFailure
		}
		return nil, nil
	}
	// The call is shared, so it must not end with the first caller's request.
	shared := context.WithoutCancel(ctx)
	rows, err, _ := s.flights.Do(l.key, func() (any, error) {
		fetched, err := l.fetch(shared)
		if errors.Is(err, domainlocation.ErrUpstream) {
			s.misses.addFailure(l.key)
		}
		if err != nil {
			return nil, err
		}
		if len(fetched) == 0 {
			s.misses.addEmpty(l.key)
			return fetched, nil
		}
		return fetched, l.upsert(shared, fetched)
	})
	if err != nil {
		return nil, err
	}
	return rows.([]T), nil
}
