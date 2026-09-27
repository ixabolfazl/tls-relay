package dnsresolver

import (
	"sync"
	"time"
)

// tokenBucket implements a per-source-IP token bucket rate limiter.
// If a query arrives and the bucket is empty, it is dropped silently.
type tokenBucket struct {
	tokens    float64
	maxTokens float64
	rate      float64 // tokens per nanosecond
	lastRefil time.Time
	mu        sync.Mutex
}

func newBucket(qps float64, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:    float64(burst),
		maxTokens: float64(burst),
		rate:      qps / 1e9, // tokens per nanosecond
		lastRefil: time.Now(),
	}
}

// Allow returns true if a token can be consumed (i.e. the query is allowed).
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := float64(now.Sub(b.lastRefil))
	b.lastRefil = now

	b.tokens += elapsed * b.rate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// IPRateLimiter maintains a per-IP map of token buckets.
type IPRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	qps     float64
	burst   int
}

// NewIPRateLimiter creates a rate limiter with the given per-IP limits.
func NewIPRateLimiter(qps float64, burst int) *IPRateLimiter {
	rl := &IPRateLimiter{
		buckets: make(map[string]*tokenBucket),
		qps:     qps,
		burst:   burst,
	}
	go rl.sweepOldBuckets()
	return rl
}

// Allow returns true if the given IP's bucket has tokens available.
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	b, ok := rl.buckets[ip]
	if !ok {
		b = newBucket(rl.qps, rl.burst)
		rl.buckets[ip] = b
	}
	rl.mu.Unlock()
	return b.Allow()
}

// sweepOldBuckets periodically removes buckets for IPs that have been idle
// to bound memory usage and prevent leaks from one-off querying clients.
func (rl *IPRateLimiter) sweepOldBuckets() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			b.mu.Lock()
			// Remove bucket if IP has been idle for at least 5 minutes.
			if now.Sub(b.lastRefil) >= 5*time.Minute {
				delete(rl.buckets, ip)
			}
			b.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}
