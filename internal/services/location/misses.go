package location

import (
	"sync"
	"time"
)

// maxMisses bounds the table; keys are existing parent codes, so it is rarely reached.
const maxMisses = 10000

// missCache remembers, per cache key, that the Location Service had nothing to
// offer, so the same empty lookup is not repeated on every request.
type missCache struct {
	mu    sync.Mutex
	until map[string]time.Time
	ttl   time.Duration
}

func newMissCache(ttl time.Duration) *missCache {
	return &missCache{until: make(map[string]time.Time), ttl: ttl}
}

func (m *missCache) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.until[key]
	if ok && time.Now().After(until) {
		delete(m.until, key)
		return false
	}
	return ok
}

func (m *missCache) add(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.until) >= maxMisses {
		now := time.Now()
		for k, until := range m.until {
			if now.After(until) {
				delete(m.until, k)
			}
		}
		if len(m.until) >= maxMisses {
			return
		}
	}
	m.until[key] = time.Now().Add(m.ttl)
}
