package location

import (
	"context"
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

// fakeCache records writes so service rules can be tested without Redis.
type fakeCache struct {
	entries map[string]time.Duration
}

func newFakeCache() *fakeCache { return &fakeCache{entries: map[string]time.Duration{}} }

func (f *fakeCache) Get(context.Context, string) ([]dtolocation.Location, bool) { return nil, false }
func (f *fakeCache) Set(_ context.Context, key string, _ []dtolocation.Location, ttl time.Duration) {
	f.entries[key] = ttl
}
func (f *fakeCache) DeleteKeys(context.Context, string) {}

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
	svc.setLocationCache(context.Background(), "location:province", []dtolocation.Location{{Code: "11", Name: "Aceh"}})
	if _, ok := svc.cacheOrNoop().Get(context.Background(), "location:province"); ok {
		t.Fatal("a service without a cache must always miss")
	}
}
