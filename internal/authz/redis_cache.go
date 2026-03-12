package authz

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisDecisionCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRedisDecisionCache(url string, ttl time.Duration) (*RedisDecisionCache, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	client := redis.NewClient(opts)
	return &RedisDecisionCache{client: client, ttl: ttl}, nil
}

func (c *RedisDecisionCache) Get(req DecisionRequest) (DecisionResponse, bool) {
	if c == nil {
		return DecisionResponse{}, false
	}
	key := "dec:" + decisionCacheKey(req)
	if key == "dec:" {
		return DecisionResponse{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return DecisionResponse{}, false
	}
	resp, err := decodeDecisionResponse(data)
	if err != nil {
		return DecisionResponse{}, false
	}
	return resp, true
}

func (c *RedisDecisionCache) Set(req DecisionRequest, resp DecisionResponse) {
	if c == nil {
		return
	}
	key := "dec:" + decisionCacheKey(req)
	if key == "dec:" {
		return
	}
	payload, err := encodeDecisionResponse(resp)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = c.client.Set(ctx, key, payload, c.ttl).Err()
}

func (c *RedisDecisionCache) Clear() {
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var cursor uint64
	for {
		keys, next, err := c.client.Scan(ctx, cursor, "dec:*", 256).Result()
		if err != nil {
			return
		}
		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				return
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

func (c *RedisDecisionCache) Healthy(ctx context.Context) error {
	if c == nil {
		return nil
	}
	return c.client.Ping(ctx).Err()
}
