package location

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/logus"

	dtolocation "starter-kit/internal/dto/location"
)

const scanCount = int64(100)

type Cache struct {
	client *redis.Client
}

func New(client *redis.Client) *Cache {
	return &Cache{client: client}
}

func (c *Cache) Get(ctx context.Context, cacheKey string) ([]dtolocation.Location, bool) {
	if c.client == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cached, err := c.client.Get(ctx, cacheKey).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			logus.Logf(logus.LevelWarn, "location: cache get failed; key=%s; err=%v", cacheKey, err)
		}
		return nil, false
	}

	var locations []dtolocation.Location
	if err := json.Unmarshal([]byte(cached), &locations); err != nil {
		logus.Logf(logus.LevelWarn, "location: cache unmarshal failed; key=%s; err=%v", cacheKey, err)
		return nil, false
	}

	return locations, true
}

func (c *Cache) Set(ctx context.Context, cacheKey string, locations []dtolocation.Location, ttl time.Duration) {
	if c.client == nil {
		return
	}

	payload, err := json.Marshal(locations)
	if err != nil {
		logus.Logf(logus.LevelWarn, "location: cache marshal failed; key=%s; err=%v", cacheKey, err)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := c.client.Set(ctx, cacheKey, payload, ttl).Err(); err != nil {
		logus.Logf(logus.LevelWarn, "location: cache set failed; key=%s; err=%v", cacheKey, err)
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
		foundKeys, nextCursor, err := c.client.Scan(ctx, cursor, escapeGlob(pattern)+"*", scanCount).Result()
		if err != nil {
			logus.Logf(logus.LevelWarn, "location: cache scan failed; pattern=%s; err=%v", pattern, err)
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
		logus.Logf(logus.LevelWarn, "location: cache delete failed; pattern=%s; err=%v", pattern, err)
	}
}

func escapeGlob(s string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`, "]", `\]`).Replace(s)
}
