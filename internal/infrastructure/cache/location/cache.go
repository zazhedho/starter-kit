package locationcache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zazhedho/logus"
	"starter-kit/internal/dto"
	"time"

	"github.com/redis/go-redis/v9"
)

const scanCount = int64(100)

// Cache is the Redis implementation of the location service's cache port. A nil
// client disables it: every Get misses and Set and DeleteKeys do nothing.
type Cache struct {
	client *redis.Client
}

// New wraps client; client may be nil.
func New(client *redis.Client) *Cache {
	return &Cache{client: client}
}

func (c *Cache) Get(ctx context.Context, cacheKey string) ([]dto.Location, bool) {
	if c.client == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cached, err := c.client.Get(ctx, cacheKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("location cache get failed; key=%s; err=%v", cacheKey, err))
		}
		return nil, false
	}

	var locations []dto.Location
	if err := json.Unmarshal([]byte(cached), &locations); err != nil {
		logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("location cache unmarshal failed; key=%s; err=%v", cacheKey, err))
		return nil, false
	}

	return locations, true
}

func (c *Cache) Set(ctx context.Context, cacheKey string, locations []dto.Location, ttl time.Duration) {
	if c.client == nil {
		return
	}

	payload, err := json.Marshal(locations)
	if err != nil {
		logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("location cache marshal failed; key=%s; err=%v", cacheKey, err))
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := c.client.Set(ctx, cacheKey, payload, ttl).Err(); err != nil {
		logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("location cache set failed; key=%s; err=%v", cacheKey, err))
	}
}

func (c *Cache) DeleteKeys(ctx context.Context, pattern string) {
	if c.client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var keys []string
	var cursor uint64
	for {
		foundKeys, nextCursor, err := c.client.Scan(ctx, cursor, pattern+"*", scanCount).Result()
		if err != nil {
			logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("location cache scan failed; pattern=%s; err=%v", pattern, err))
			return
		}
		keys = append(keys, foundKeys...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(keys) == 0 {
		return
	}
	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		logus.WriteLog(logus.LogLevelWarn, fmt.Sprintf("location cache delete failed; pattern=%s; err=%v", pattern, err))
	}
}
