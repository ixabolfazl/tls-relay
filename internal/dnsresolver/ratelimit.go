package dnsresolver

import (
	"sync"
	"time"
)

const maxIPRateLimiterBuckets = 100000

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

// IPRateLimiter maintains a per-IP map of token buckets bounded to 100,000 buckets.
type IPRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	qps     float64
	burst   int
	stopCh  chan struct{}
}

// NewIPRateLimiter creates a rate limiter with the given per-IP limits.
func NewIPRateLimiter(qps float64, burst int) *IPRateLimiter {
	rl := &IPRateLimiter{
		buckets: make(map[string]*tokenBucket),
		qps:     qps,
		burst:   burst,
		stopCh:  make(chan struct{}),
	}
	go rl.sweepOldBuckets()
	return rl
}

// Close stops the background sweeper goroutine.
func (rl *IPRateLimiter) Close() {
	if rl.stopCh != nil {
		select {
		case <-rl.stopCh:
		default:
			close(rl.stopCh)
		}
	}
}

func (rl *IPRateLimiter) sweepIdleUnderLock(now time.Time, idleThreshold time.Duration) {
	for ip, b := range rl.buckets {
		b.mu.Lock()
		if now.Sub(b.lastRefil) >= idleThreshold {
			delete(rl.buckets, ip)
		}
		b.mu.Unlock()
	}
}

// Allow returns true if the given IP's bucket has tokens available.
// Bounded to 100,000 buckets; performs an immediate idle sweep and arbitrary batch eviction if full.
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	b, ok := rl.buckets[ip]
	if !ok {
		if len(rl.buckets) >= maxIPRateLimiterBuckets {
			// Immediate idle sweep (idle for >= 1 minute)
			now := time.Now()
			rl.sweepIdleUnderLock(now, 1*time.Minute)
			// If still at capacity, evict an arbitrary batch of 1,000
			if len(rl.buckets) >= maxIPRateLimiterBuckets {
				count := 0
				for k := range rl.buckets {
					delete(rl.buckets, k)
					count++
					if count >= 1000 {
						break
					}
				}
			}
		}
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
	for {
		select {
		case <-rl.stopCh:
			return
		case now := <-ticker.C:
			rl.mu.Lock()
			rl.sweepIdleUnderLock(now, 5*time.Minute)
			rl.mu.Unlock()
		}
	}
}
