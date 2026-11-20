package location

import "time"

type Options struct {
	Cache             Cache
	NewID             func() string
	InstanceID        string
	BaseURL           string
	MaxResponseBytes  int64
	Timeout, CacheTTL time.Duration

	HeartbeatInterval time.Duration
	StaleAfter        time.Duration
	ProgressInterval  time.Duration
	MissTTL           time.Duration
	FailureTTL        time.Duration
}

const (
	defaultHTTPTimeout      = 20 * time.Second
	defaultMaxResponseBytes = int64(4 << 20)
	defaultHeartbeat        = 15 * time.Second
	defaultStaleAfter       = 2 * time.Minute
	defaultProgressInterval = 2 * time.Second
	defaultMissTTL          = time.Minute
	defaultFailureTTL       = 8 * time.Second
)

func orDefault[T int64 | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}
