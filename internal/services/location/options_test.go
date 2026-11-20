package location

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	dtolocation "starter-kit/internal/dto/location"
)

func TestNewLocationServiceNeverDisablesTheHTTPTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		svc := NewService(&locationRepoTestDouble{}, Options{Timeout: timeout})
		if svc.httpClient.Timeout != defaultHTTPTimeout {
			t.Errorf("Timeout %v: client timeout = %v, want %v", timeout, svc.httpClient.Timeout, defaultHTTPTimeout)
		}
	}
	svc := NewService(&locationRepoTestDouble{}, Options{Timeout: 3 * time.Second})
	if svc.httpClient.Timeout != 3*time.Second {
		t.Errorf("explicit timeout not kept: %v", svc.httpClient.Timeout)
	}
}

// fakeCache is an in-memory cache that records what the service asks of it, so
// service rules can be tested without Redis.
type fakeCache struct {
	mu      sync.Mutex
	entries map[string]time.Duration
	data    map[string][]dtolocation.Location
	gets    []string
	deletes []string
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string]time.Duration{}, data: map[string][]dtolocation.Location{}}
}

func locationsOf(code, name string) []dtolocation.Location {
	return []dtolocation.Location{{Code: code, Name: name}}
}

func (f *fakeCache) Get(_ context.Context, key string) ([]dtolocation.Location, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, key)
	data, ok := f.data[key]
	return data, ok
}

func (f *fakeCache) Set(_ context.Context, key string, _ []dtolocation.Location, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[key] = ttl
}

func (f *fakeCache) DeleteKeys(_ context.Context, prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, prefix)
}

func TestLocationCacheIsSkippedWithoutPositiveTTL(t *testing.T) {
	cache := newFakeCache()
	locations := []dtolocation.Location{{Code: "11", Name: "Aceh"}}

	for _, ttl := range []time.Duration{0, -time.Minute} {
		svc := NewService(&locationRepoTestDouble{}, Options{Cache: cache, CacheTTL: ttl})
		svc.setLocationCache(context.Background(), "location:province", locations)
		if _, ok := cache.entries["location:province"]; ok {
			t.Fatalf("CacheTTL %v: an entry was written to the cache", ttl)
		}
	}

	svc := NewService(&locationRepoTestDouble{}, Options{Cache: cache, CacheTTL: time.Minute})
	svc.setLocationCache(context.Background(), "location:province", locations)
	if ttl, ok := cache.entries["location:province"]; !ok {
		t.Fatal("a positive TTL must cache")
	} else if ttl != time.Minute {
		t.Fatalf("cached entry has ttl %v, want %v", ttl, time.Minute)
	}
}

func TestNewLocationServiceWithoutCacheAlwaysMisses(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{}, Options{CacheTTL: time.Minute})
	if svc.cache == nil {
		t.Fatal("the constructor must install a cache when none is given")
	}
	svc.setLocationCache(context.Background(), "location:province", []dtolocation.Location{{Code: "11", Name: "Aceh"}})
	if _, ok := svc.cache.Get(context.Background(), "location:province"); ok {
		t.Fatal("a service without a cache must always miss")
	}
}

func TestNewServiceDefaultsItsLimits(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{}, Options{})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	if svc.maxResponse != 4<<20 || svc.heartbeatInterval != 15*time.Second || svc.staleAfter != 2*time.Minute || svc.progressInterval != 2*time.Second {
		t.Fatalf("defaults = %d, %v, %v, %v", svc.maxResponse, svc.heartbeatInterval, svc.staleAfter, svc.progressInterval)
	}
	if svc.staleAfter <= 2*svc.heartbeatInterval {
		t.Fatal("a job must survive at least a couple of missed heartbeats before it counts as stale")
	}
	svc = NewService(&locationRepoTestDouble{}, Options{MaxResponseBytes: 1 << 20, StaleAfter: time.Second})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	if svc.maxResponse != 1<<20 || svc.staleAfter != time.Second {
		t.Fatalf("explicit options not kept: %d, %v", svc.maxResponse, svc.staleAfter)
	}
}

func TestTheHTTPClientDoesNotFollowRedirects(t *testing.T) {
	svc := NewService(&locationRepoTestDouble{}, Options{})
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	if err := svc.httpClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}
