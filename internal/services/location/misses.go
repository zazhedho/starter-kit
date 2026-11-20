package location

import (
	"sync"
	"time"
)

const maxMisses = 10000

type missCache struct {
	mu         sync.Mutex
	until      map[string]miss
	ttl        time.Duration
	failureTTL time.Duration
}

type miss struct {
	until  time.Time
	failed bool
}

func newMissCache(ttl, failureTTL time.Duration) *missCache {
	return &missCache{until: make(map[string]miss), ttl: ttl, failureTTL: failureTTL}
}

func (m *missCache) lookup(key string) (failed, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.until[key]
	if ok && time.Now().After(entry.until) {
		delete(m.until, key)
		return false, false
	}
	return entry.failed, ok
}

func (m *missCache) addEmpty(key string) { m.add(key, miss{until: time.Now().Add(m.ttl)}) }

func (m *missCache) addFailure(key string) {
	m.add(key, miss{until: time.Now().Add(m.failureTTL), failed: true})
}

func (m *missCache) add(key string, entry miss) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.until) >= maxMisses {
		now := time.Now()
		for k, e := range m.until {
			if now.After(e.until) {
				delete(m.until, k)
			}
		}
		if len(m.until) >= maxMisses {
			return
		}
	}
	m.until[key] = entry
}
