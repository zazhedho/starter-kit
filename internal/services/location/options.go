package location

import "time"

// Options is what the service needs besides its repository. The zero value is
// valid; the constructor fills in defaults.
type Options struct {
	// Cache is the read-through cache; nil installs a cache that always misses.
	Cache Cache
	// NewID returns the identifier of a new sync job; nil means UUIDv7.
	NewID func() string
	// InstanceID names this process as the owner of its sync jobs; empty means a random UUID.
	InstanceID string
	BaseURL    string
	// MaxResponseBytes caps one Location Service response body; zero or less means 4 MiB.
	MaxResponseBytes  int64
	Timeout, CacheTTL time.Duration

	// The intervals below default when zero or less; tests shorten them.
	HeartbeatInterval time.Duration // how often a running job reports in
	StaleAfter        time.Duration // heartbeat age after which a job is taken over
	ProgressInterval  time.Duration // at most one progress write per interval
	MissTTL           time.Duration // how long an empty upstream answer is remembered
}

const (
	// defaultHTTPTimeout bounds outbound calls when Options.Timeout is not positive.
	defaultHTTPTimeout      = 20 * time.Second
	defaultMaxResponseBytes = int64(4 << 20)
	defaultHeartbeat        = 15 * time.Second
	defaultStaleAfter       = 2 * time.Minute
	defaultProgressInterval = 2 * time.Second
	defaultMissTTL          = time.Minute
)

// orDefault returns v, or def when v is not positive.
func orDefault[T int64 | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}
