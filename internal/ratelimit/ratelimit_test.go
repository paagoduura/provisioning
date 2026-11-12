package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimiterEnforcesCapacityAndPenalty(t *testing.T) {
	limiter := NewMemory()
	policy := Policy{Capacity: 2, Refill: 1, Window: time.Minute}
	first, err := limiter.Allow(context.Background(), "key", policy)
	if err != nil || !first.Allowed {
		t.Fatalf("first request: %+v %v", first, err)
	}
	second, err := limiter.Allow(context.Background(), "key", policy)
	if err != nil || !second.Allowed {
		t.Fatalf("second request: %+v %v", second, err)
	}
	third, err := limiter.Allow(context.Background(), "key", policy)
	if err != nil || third.Allowed || third.RetryAfter <= 0 {
		t.Fatalf("third request: %+v %v", third, err)
	}
	if err := limiter.Penalize(context.Background(), "key", time.Second); err != nil {
		t.Fatal(err)
	}
	blocked, err := limiter.Allow(context.Background(), "key", policy)
	if err != nil || blocked.Allowed || blocked.RetryAfter <= 0 {
		t.Fatalf("penalized request: %+v %v", blocked, err)
	}
}

func TestClientIPUsesTransportPeerOnly(t *testing.T) {
	if got := ClientIP("203.0.113.10:443"); got != "203.0.113.10" {
		t.Fatalf("IPv4 = %q", got)
	}
	if got := ClientIP("[2001:db8::10]:443"); got != "2001:db8::10" {
		t.Fatalf("IPv6 = %q", got)
	}
}
