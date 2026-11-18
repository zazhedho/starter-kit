package location

import "time"

// Options is what the service needs besides its repository. The zero value is
// valid; the constructor fills in defaults.
type Options struct {
	// Cache is the read-through cache; nil installs a cache that always misses.
	Cache Cache
	// NewID returns the identifier of a new sync job; nil means UUIDv7.
	NewID             func() string
	BaseURL           string
	SourceYear        string
	Timeout, CacheTTL time.Duration
}

// defaultHTTPTimeout bounds outbound calls when Options.Timeout is not positive.
const defaultHTTPTimeout = 20 * time.Second
