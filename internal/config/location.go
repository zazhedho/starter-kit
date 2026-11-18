package config

import (
	"strings"
	"time"

	"github.com/zazhedho/gokit"
)

const (
	defaultLocationServiceBaseURL = "https://location-service-y7si.onrender.com"
	defaultLocationTimeoutSeconds = 20
	defaultLocationCacheTTL       = 180 * 24 * time.Hour
)

// Location is the location module's setting.
type Location struct {
	ServiceBaseURL, SourceYear string
	ServiceTimeout, CacheTTL   time.Duration
}

func locationFromEnv(l *loader) Location {
	return Location{
		ServiceBaseURL: strings.TrimRight(l.str("LOCATION_SERVICE_BASE_URL", defaultLocationServiceBaseURL), "/"),
		SourceYear:     gokit.GetEnv("LOCATION_SOURCE_YEAR", ""),
		ServiceTimeout: locationTimeout(),
		CacheTTL:       locationCacheTTL(),
	}
}

// locationTimeout reads LOCATION_SERVICE_TIMEOUT_SECONDS as whole seconds; a
// non-positive value means the default.
func locationTimeout() time.Duration {
	sec := gokit.GetEnv("LOCATION_SERVICE_TIMEOUT_SECONDS", defaultLocationTimeoutSeconds)
	if sec <= 0 {
		sec = defaultLocationTimeoutSeconds
	}
	return time.Duration(sec) * time.Second
}

// locationCacheTTL accepts a Go duration, plain seconds or "eod"; a
// non-positive value means the default.
func locationCacheTTL() time.Duration {
	ttl := gokit.GetEnv("LOCATION_CACHE_TTL", defaultLocationCacheTTL)
	if ttl <= 0 {
		return defaultLocationCacheTTL
	}
	return ttl
}

// validateLocation has nothing to check today; the hook exists so a future
// location rule has one place to live.
func (c Config) validateLocation() []string { return nil }
