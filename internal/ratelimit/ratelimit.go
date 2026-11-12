package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrUnavailable = errors.New("rate limiter unavailable")

const tokenScale int64 = 1_000_000

var tokenBucketScript = redis.NewScript(`
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local cost = tonumber(ARGV[5])
local values = redis.call('HMGET', key, 'tokens', 'last_ms')
local tokens = tonumber(values[1])
local last_ms = tonumber(values[2])
if tokens == nil then tokens = capacity end
if last_ms == nil then last_ms = now end
if now > last_ms and refill_per_ms > 0 then
  tokens = math.min(capacity, tokens + ((now - last_ms) * refill_per_ms))
  last_ms = now
end
local allowed = 0
local retry_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  if refill_per_ms > 0 then retry_ms = math.ceil((cost - tokens) / refill_per_ms) else retry_ms = ttl end
end
redis.call('HSET', key, 'tokens', tokens, 'last_ms', last_ms)
redis.call('PEXPIRE', key, ttl)
return {allowed, math.floor(tokens), retry_ms}
`)

type Policy struct {
	Capacity, Refill       int64
	Window, FailurePenalty time.Duration
}

var (
	IPPolicy                = Policy{Capacity: 120, Refill: 240, Window: time.Minute}
	SessionUserPolicy       = Policy{Capacity: 10, Refill: 30, Window: time.Minute}
	ChallengeUserPolicy     = Policy{Capacity: 5, Refill: 15, Window: time.Minute}
	ChallengeDevicePolicy   = Policy{Capacity: 5, Refill: 15, Window: time.Minute}
	AttestationUserPolicy   = Policy{Capacity: 10, Refill: 30, Window: time.Minute}
	AttestationDevicePolicy = Policy{Capacity: 10, Refill: 30, Window: time.Minute}
)

func (p Policy) valid() bool { return p.Capacity > 0 && p.Refill > 0 && p.Window > 0 }
func (p Policy) refillPerMillisecond() int64 {
	return maxInt64(1, (p.Refill*tokenScale)/p.Window.Milliseconds())
}
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type Decision struct {
	Allowed    bool
	Remaining  int64
	RetryAfter time.Duration
}
type Limiter interface {
	Allow(context.Context, string, Policy) (Decision, error)
	Penalize(context.Context, string, time.Duration) error
	Close() error
}
type RedisLimiter struct{ client redis.UniversalClient }

func NewRedis(client redis.UniversalClient) *RedisLimiter { return &RedisLimiter{client: client} }
func (l *RedisLimiter) Allow(ctx context.Context, key string, policy Policy) (Decision, error) {
	if l == nil || l.client == nil || !policy.valid() {
		return Decision{}, ErrUnavailable
	}
	if ttl, err := l.client.PTTL(ctx, key+":blocked").Result(); err == nil && ttl > 0 {
		return Decision{RetryAfter: ttl}, nil
	} else if err != nil && !errors.Is(err, redis.Nil) {
		return Decision{}, err
	}
	result, err := tokenBucketScript.Run(ctx, l.client, []string{key}, policy.Capacity*tokenScale, policy.refillPerMillisecond(), time.Now().UnixMilli(), policy.Window.Milliseconds(), tokenScale).Result()
	if err != nil {
		return Decision{}, err
	}
	values, ok := result.([]interface{})
	if !ok || len(values) != 3 {
		return Decision{}, errors.New("invalid rate limiter response")
	}
	allowed, ok1 := redisInt(values[0])
	remaining, ok2 := redisInt(values[1])
	retry, ok3 := redisInt(values[2])
	if !ok1 || !ok2 || !ok3 {
		return Decision{}, errors.New("invalid rate limiter values")
	}
	return Decision{Allowed: allowed == 1, Remaining: remaining / tokenScale, RetryAfter: time.Duration(retry) * time.Millisecond}, nil
}
func (l *RedisLimiter) Penalize(ctx context.Context, key string, duration time.Duration) error {
	if l == nil || l.client == nil || duration <= 0 {
		return ErrUnavailable
	}
	return l.client.Set(ctx, key+":blocked", "1", duration).Err()
}
func (l *RedisLimiter) Close() error {
	if l == nil || l.client == nil {
		return nil
	}
	return l.client.Close()
}
func redisInt(value interface{}) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

type memoryBucket struct {
	tokens             float64
	last, blockedUntil time.Time
}
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]memoryBucket
}

func NewMemory() *MemoryLimiter { return &MemoryLimiter{buckets: make(map[string]memoryBucket)} }
func (l *MemoryLimiter) Allow(_ context.Context, key string, p Policy) (Decision, error) {
	if l == nil || !p.valid() {
		return Decision{}, ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[key]
	if now.Before(b.blockedUntil) {
		return Decision{RetryAfter: time.Until(b.blockedUntil)}, nil
	}
	if b.last.IsZero() {
		b.tokens = float64(p.Capacity)
		b.last = now
	}
	b.tokens = math.Min(float64(p.Capacity), b.tokens+float64(p.Refill)*now.Sub(b.last).Seconds()/p.Window.Seconds())
	b.last = now
	if b.tokens < 1 {
		retry := time.Duration(math.Ceil((1-b.tokens)*p.Window.Seconds()/float64(p.Refill)) * float64(time.Second))
		l.buckets[key] = b
		return Decision{RetryAfter: retry}, nil
	}
	b.tokens--
	l.buckets[key] = b
	return Decision{Allowed: true, Remaining: int64(b.tokens)}, nil
}
func (l *MemoryLimiter) Penalize(_ context.Context, key string, duration time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	b.blockedUntil = time.Now().Add(duration)
	l.buckets[key] = b
	return nil
}
func (l *MemoryLimiter) Close() error { return nil }

func ClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}
func Key(scope, route, value string) string { return "ota:rl:" + scope + ":" + route + ":" + value }
func HashedKey(scope, route, value string) string {
	sum := sha256.Sum256([]byte(value))
	return Key(scope, route, hex.EncodeToString(sum[:]))
}
func IPKey(route, remoteAddr string) string { return HashedKey("ip", route, ClientIP(remoteAddr)) }
