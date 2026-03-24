package redis

import (
	"context"
	"fmt"
	"sync"

	goredis "github.com/redis/go-redis/v9"
)

type Config struct {
	Addr     string
	Password string
	DB       int
}

var (
	mu     sync.RWMutex
	client *goredis.Client
)

func InitRedis(ctx context.Context, cfg Config) (*goredis.Client, error) {
	next := goredis.NewClient(&goredis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	if err := next.Ping(ctx).Err(); err != nil {
		_ = next.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	mu.Lock()
	old := client
	client = next
	mu.Unlock()

	if old != nil {
		_ = old.Close()
	}

	return next, nil
}

func Client() *goredis.Client {
	mu.RLock()
	defer mu.RUnlock()
	return client
}

func Close() error {
	mu.Lock()
	current := client
	client = nil
	mu.Unlock()

	if current == nil {
		return nil
	}
	return current.Close()
}
