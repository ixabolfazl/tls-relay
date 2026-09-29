// Package relay/limits tracks global and per-IP concurrent connection counts.
package relay

import (
	"sync"
	"sync/atomic"
)

// LimitTracker tracks global and per-IP connection counts concurrently.
type LimitTracker struct {
	maxGlobal int64
	maxPerIP  int64

	global atomic.Int64

	mu    sync.Mutex
	perIP map[string]int64
}

// NewLimitTracker creates a LimitTracker with the specified limits.
func NewLimitTracker(maxGlobal, maxPerIP int) *LimitTracker {
	return &LimitTracker{
		maxGlobal: int64(maxGlobal),
		maxPerIP:  int64(maxPerIP),
		perIP:     make(map[string]int64),
	}
}

// Acquire tries to claim a slot for the given IP.
// Returns true and a release func on success, or false if any limit is exceeded.
func (lt *LimitTracker) Acquire(ip string) (release func(), ok bool) {
	// Fast path: check global first without locking per-IP map.
	maxGlobal := atomic.LoadInt64(&lt.maxGlobal)
	if lt.global.Load() >= maxGlobal {
		return nil, false
	}

	lt.mu.Lock()
	if lt.perIP[ip] >= lt.maxPerIP {
		lt.mu.Unlock()
		return nil, false
	}
	lt.perIP[ip]++
	lt.mu.Unlock()

	// Increment global AFTER per-IP to avoid double counting on failure.
	if lt.global.Add(1) > maxGlobal {
		// Race: we incremented but global is now over limit; roll back.
		lt.global.Add(-1)
		lt.mu.Lock()
		lt.perIP[ip]--
		if lt.perIP[ip] == 0 {
			delete(lt.perIP, ip)
		}
		lt.mu.Unlock()
		return nil, false
	}

	released := false
	release = func() {
		if released {
			return
		}
		released = true
		lt.global.Add(-1)
		lt.mu.Lock()
		lt.perIP[ip]--
		if lt.perIP[ip] == 0 {
			delete(lt.perIP, ip)
		}
		lt.mu.Unlock()
	}
	return release, true
}

// GlobalCount returns the current number of active connections.
func (lt *LimitTracker) GlobalCount() int64 {
	return lt.global.Load()
}

// MaxGlobal returns the maximum allowed concurrent connections globally.
func (lt *LimitTracker) MaxGlobal() int {
	return int(atomic.LoadInt64(&lt.maxGlobal))
}

// SetMaxGlobal sets the maximum allowed concurrent connections globally.
func (lt *LimitTracker) SetMaxGlobal(limit int) {
	if limit <= 0 {
		return
	}
	atomic.StoreInt64(&lt.maxGlobal, int64(limit))
}

// MaxPerIP returns the maximum allowed concurrent connections per client IP.
func (lt *LimitTracker) MaxPerIP() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return int(lt.maxPerIP)
}

// SetMaxPerIP sets the maximum allowed concurrent connections per client IP.
func (lt *LimitTracker) SetMaxPerIP(limit int) {
	if limit <= 0 {
		return
	}
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.maxPerIP = int64(limit)
}
