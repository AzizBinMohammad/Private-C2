package middleware

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

func (tb *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64
	burst   float64
}

func NewRateLimiter(ratePerSec, burst float64) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    ratePerSec,
		burst:   burst,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, ok := rl.buckets[key]
	if !ok {
		bucket = &tokenBucket{
			tokens:     rl.burst,
			maxTokens:  rl.burst,
			refillRate: rl.rate,
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
	}
	return bucket.allow()
}

func (rl *RateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, bucket := range rl.buckets {
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, key)
		}
	}
}

func RateLimitUnaryInterceptor(limiter *RateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		key := GetOperatorID(ctx)
		if key == "" {
			key = GetSourceIP(ctx)
		}
		if key == "" {
			key = "anonymous"
		}

		if !limiter.Allow(key) {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

func RateLimitStreamInterceptor(limiter *RateLimiter) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		key := GetOperatorID(ss.Context())
		if key == "" {
			key = GetSourceIP(ss.Context())
		}
		if key == "" {
			key = "anonymous"
		}

		if !limiter.Allow(key) {
			return status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(srv, ss)
	}
}
