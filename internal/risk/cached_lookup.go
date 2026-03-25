package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type LookupEvent struct {
	Source   string
	Result   string
	Duration time.Duration
}

type LookupObserver interface {
	ObserveLookup(LookupEvent)
}

type LookupObserverFunc func(LookupEvent)

func (f LookupObserverFunc) ObserveLookup(event LookupEvent) {
	f(event)
}

type CachedLookupClient struct {
	client   LookupClient
	redis    redis.Cmdable
	keyFn    func(string) string
	ttl      time.Duration
	observer LookupObserver
}

type cachedLookupEntry struct {
	Status string             `json:"status"`
	Record *FingerprintRecord `json:"record,omitempty"`
}

func NewCachedLookupClient(client LookupClient, redisClient redis.Cmdable, prefix string, ttl time.Duration, observer LookupObserver) *CachedLookupClient {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	trimmedPrefix := strings.Trim(strings.TrimSpace(prefix), ":")
	return &CachedLookupClient{
		client: client,
		redis:  redisClient,
		ttl:    ttl,
		keyFn: func(ja4 string) string {
			if trimmedPrefix == "" {
				return fmt.Sprintf("sybil:lookup:%s", ja4)
			}
			return fmt.Sprintf("%s:lookup:%s", trimmedPrefix, ja4)
		},
		observer: observer,
	}
}

func (c *CachedLookupClient) Lookup(ctx context.Context, ja4 string) (*FingerprintRecord, error) {
	if c == nil || c.client == nil || c.redis == nil {
		if c != nil && c.client != nil {
			return c.client.Lookup(ctx, ja4)
		}
		return nil, nil
	}

	cacheKey := c.keyFn(strings.TrimSpace(ja4))
	cacheStart := time.Now()
	cachedValue, err := c.redis.Get(ctx, cacheKey).Result()
	switch {
	case err == nil:
		c.observe("cache", "hit", time.Since(cacheStart))
		var entry cachedLookupEntry
		if decodeErr := json.Unmarshal([]byte(cachedValue), &entry); decodeErr != nil {
			c.observe("cache", "error", 0)
			break
		}
		if entry.Status == "not_found" {
			return nil, ErrFingerprintNotFound
		}
		if entry.Record == nil {
			return nil, nil
		}
		return entry.Record, nil
	case errors.Is(err, redis.Nil):
		c.observe("cache", "miss", time.Since(cacheStart))
	default:
		c.observe("cache", "error", time.Since(cacheStart))
	}

	originStart := time.Now()
	record, lookupErr := c.client.Lookup(ctx, ja4)
	switch {
	case errors.Is(lookupErr, ErrFingerprintNotFound):
		c.observe("origin", "miss", time.Since(originStart))
		c.writeCache(ctx, cacheKey, cachedLookupEntry{Status: "not_found"})
		return nil, lookupErr
	case lookupErr != nil:
		c.observe("origin", "error", time.Since(originStart))
		return nil, lookupErr
	case record == nil:
		c.observe("origin", "miss", time.Since(originStart))
		c.writeCache(ctx, cacheKey, cachedLookupEntry{Status: "empty"})
		return nil, nil
	default:
		c.observe("origin", "hit", time.Since(originStart))
		c.writeCache(ctx, cacheKey, cachedLookupEntry{Status: "hit", Record: record})
		return record, nil
	}
}

func (c *CachedLookupClient) writeCache(ctx context.Context, key string, entry cachedLookupEntry) {
	if c == nil || c.redis == nil {
		return
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		c.observe("cache", "error", 0)
		return
	}
	if err := c.redis.SetEx(ctx, key, payload, c.ttl).Err(); err != nil {
		c.observe("cache", "error", 0)
		return
	}
	c.observe("cache", "set", 0)
}

func (c *CachedLookupClient) observe(source, result string, duration time.Duration) {
	if c == nil || c.observer == nil {
		return
	}
	c.observer.ObserveLookup(LookupEvent{
		Source:   source,
		Result:   result,
		Duration: duration,
	})
}
