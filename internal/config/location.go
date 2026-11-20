package config

import (
	"net/url"
	"strings"
	"time"

	"github.com/zazhedho/gokit"
)

const (
	defaultLocationServiceBaseURL = "https://location-service-y7si.onrender.com"
	defaultLocationTimeoutSeconds = 20
	defaultLocationCacheTTL       = 180 * 24 * time.Hour
	maxLocationResponseMB         = 64
)

// Location is the location module's setting.
type Location struct {
	ServiceBaseURL           string
	ServiceTimeout, CacheTTL time.Duration
	// MaxResponseBytes caps one Location Service response body.
	MaxResponseBytes int64
	// RateLimit requests per RateWindow and client IP on the public reads.
	RateLimit  int
	RateWindow time.Duration
}

func locationFromEnv() Location {
	return Location{
		ServiceBaseURL: strings.TrimRight(gokit.GetEnv("LOCATION_SERVICE_BASE_URL", defaultLocationServiceBaseURL), "/"),
		ServiceTimeout: locationTimeout(),
		CacheTTL:       locationCacheTTL(),

		MaxResponseBytes: megabytes("LOCATION_SERVICE_MAX_RESPONSE_MB", 4),
		RateLimit:        gokit.GetEnv("LOCATION_RATE_LIMIT", 60),
		RateWindow:       time.Duration(gokit.GetEnv("LOCATION_RATE_WINDOW_SECONDS", 60)) * time.Second,
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

// validateLocation checks the Location Service URL (http or https with a host,
// and https outside development, because the responses are stored as reference
// data), the response cap and the public read rate limit.
func (c Config) validateLocation() []string {
	l := c.Location
	var problems []string
	u, err := url.Parse(l.ServiceBaseURL)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
		problems = append(problems, "LOCATION_SERVICE_BASE_URL must be an http or https URL with a host")
	case u.Scheme != "https" && !c.isDevelopment():
		problems = append(problems, "LOCATION_SERVICE_BASE_URL must use https unless APP_ENV is development")
	}
	if l.MaxResponseBytes <= 0 || l.MaxResponseBytes > maxLocationResponseMB<<20 {
		problems = append(problems, "LOCATION_SERVICE_MAX_RESPONSE_MB must be between 1 and 64")
	}
	if l.RateLimit <= 0 {
		problems = append(problems, "LOCATION_RATE_LIMIT must be greater than zero")
	}
	if l.RateWindow <= 0 {
		problems = append(problems, "LOCATION_RATE_WINDOW_SECONDS must be greater than zero")
	}
	return problems
}
