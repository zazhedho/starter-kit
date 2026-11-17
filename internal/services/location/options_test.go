package servicelocation

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"starter-kit/internal/dto"
)

func TestNewLocationServiceNeverDisablesTheHTTPTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		svc := NewLocationService(&locationRepoTestDouble{}, Options{Timeout: timeout})
		if svc.HTTPClient.Timeout != defaultHTTPTimeout {
			t.Errorf("Timeout %v: client timeout = %v, want %v", timeout, svc.HTTPClient.Timeout, defaultHTTPTimeout)
		}
	}
	svc := NewLocationService(&locationRepoTestDouble{}, Options{Timeout: 3 * time.Second})
	if svc.HTTPClient.Timeout != 3*time.Second {
		t.Errorf("explicit timeout not kept: %v", svc.HTTPClient.Timeout)
	}
}

func TestLocationCacheIsSkippedWithoutPositiveTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	locations := []dto.Location{{Code: "11", Name: "Aceh"}}

	for _, ttl := range []time.Duration{0, -time.Minute} {
		svc := NewLocationService(&locationRepoTestDouble{}, Options{Redis: client, CacheTTL: ttl})
		svc.setLocationCache(context.Background(), "location:province", locations)
		if mr.Exists("location:province") {
			t.Fatalf("CacheTTL %v: an entry was written to Redis", ttl)
		}
	}

	svc := NewLocationService(&locationRepoTestDouble{}, Options{Redis: client, CacheTTL: time.Minute})
	svc.setLocationCache(context.Background(), "location:province", locations)
	if !mr.Exists("location:province") {
		t.Fatal("a positive TTL must cache")
	}
	if ttl := mr.TTL("location:province"); ttl <= 0 {
		t.Fatalf("cached entry has no expiry: %v", ttl)
	}
}
