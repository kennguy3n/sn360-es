// Package redis hosts the SN360-ES Redis client wrapper. The wrapper
// exposes the small set of primitives we actually use (Get/Set, hash,
// pipelining, basic TTL helpers) so the rest of the codebase does not
// depend directly on go-redis types.
package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Config describes a Redis connection. PoolSize and MinIdleConns
// default to sensible values when zero.
type Config struct {
	// Addr is the host:port of the Redis server. Required.
	Addr string
	// Username (optional, Redis 6+ ACL).
	Username string
	// Password (optional).
	Password string
	// DB is the logical database number (default 0).
	DB int
	// PoolSize is the maximum number of socket connections (default 32).
	PoolSize int
	// MinIdleConns is the minimum number of idle connections (default 4).
	MinIdleConns int
	// DialTimeout for establishing new connections (default 5s).
	DialTimeout time.Duration
	// ReadTimeout for socket reads (default 3s).
	ReadTimeout time.Duration
	// WriteTimeout for socket writes (default 3s).
	WriteTimeout time.Duration
}

func (c Config) defaulted() Config {
	if c.PoolSize == 0 {
		c.PoolSize = 32
	}
	if c.MinIdleConns == 0 {
		c.MinIdleConns = 4
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 3 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 3 * time.Second
	}
	return c
}

// Client wraps *goredis.Client and exposes a narrower API.
type Client struct {
	rdb *goredis.Client
}

// New connects to Redis using cfg and returns a Client. The caller is
// responsible for calling Close.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, errors.New("redis: Addr is required")
	}
	cfg = cfg.defaulted()
	rdb := goredis.NewClient(&goredis.Options{
		Addr:         cfg.Addr,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})
	pingCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// FromRaw wraps an existing *goredis.Client (used by tests).
func FromRaw(rdb *goredis.Client) *Client { return &Client{rdb: rdb} }

// Raw exposes the underlying client for callers that need primitives
// outside this wrapper (e.g. Lua scripts, MULTI/EXEC).
func (c *Client) Raw() *goredis.Client { return c.rdb }

// Close terminates all connections.
func (c *Client) Close() error { return c.rdb.Close() }

// Get fetches a string by key. Returns ("", false, nil) when the key
// does not exist.
func (c *Client) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// Set stores key=value with the given TTL (0 = no expiry).
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

// Del removes one or more keys.
func (c *Client) Del(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

// HGetAll fetches the full hash at key (empty map if missing).
func (c *Client) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.rdb.HGetAll(ctx, key).Result()
}

// HSet sets one or more field/value pairs in the hash at key.
func (c *Client) HSet(ctx context.Context, key string, fields map[string]string) error {
	if len(fields) == 0 {
		return nil
	}
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return c.rdb.HSet(ctx, key, args...).Err()
}

// Expire sets a TTL on key.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.rdb.Expire(ctx, key, ttl).Err()
}

// ScanPrefix iterates keys matching prefix*. fn is called for each batch.
// Iteration stops if fn returns an error.
func (c *Client) ScanPrefix(ctx context.Context, prefix string, batchSize int64, fn func([]string) error) error {
	var cursor uint64
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, prefix+"*", batchSize).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := fn(keys); err != nil {
				return err
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}
