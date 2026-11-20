package config

import (
	"fmt"
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

type Location struct {
	ServiceBaseURL           string
	ServiceTimeout, CacheTTL time.Duration
	MaxResponseBytes         int64
	RateLimit                int
	RateWindow               time.Duration
}

func (l Location) String() string {
	return fmt.Sprintf("Location{ServiceBaseURL:%q ServiceTimeout:%s CacheTTL:%s MaxResponseBytes:%d RateLimit:%d RateWindow:%s}",
		withoutUserinfo(l.ServiceBaseURL), l.ServiceTimeout, l.CacheTTL, l.MaxResponseBytes, l.RateLimit, l.RateWindow)
}

func (l Location) GoString() string { return l.String() }

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

func locationTimeout() time.Duration {
	sec := gokit.GetEnv("LOCATION_SERVICE_TIMEOUT_SECONDS", defaultLocationTimeoutSeconds)
	if sec <= 0 {
		sec = defaultLocationTimeoutSeconds
	}
	return time.Duration(sec) * time.Second
}

func locationCacheTTL() time.Duration {
	ttl := gokit.GetEnv("LOCATION_CACHE_TTL", defaultLocationCacheTTL)
	if ttl <= 0 {
		return defaultLocationCacheTTL
	}
	return ttl
}

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
