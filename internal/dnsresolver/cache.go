package dnsresolver

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxDNSCacheEntries = 20000

// cacheEntry holds a cached DNS response.
type cacheEntry struct {
	msg     []byte    // packed DNS message (response)
	expires time.Time // when this entry should be evicted
}

// DNSCache is a bounded TTL-based in-memory cache keyed by "qname|qtype".
type DNSCache struct {
	mu     sync.Mutex
	items  map[string]*cacheEntry
	stopCh chan struct{}
}

// newDNSCache creates an empty cache.
func newDNSCache() *DNSCache {
	c := &DNSCache{
		items:  make(map[string]*cacheEntry),
		stopCh: make(chan struct{}),
	}
	go c.sweep()
	return c
}

// NewDNSCache creates an empty cache.
func NewDNSCache() *DNSCache {
	return newDNSCache()
}

// Close stops the background cache sweeper goroutine.
func (c *DNSCache) Close() {
	if c.stopCh != nil {
		select {
		case <-c.stopCh:
		default:
			close(c.stopCh)
		}
	}
}

// key builds the cache key (case-insensitive for DNS names).
func cacheKey(name string, qtype uint16) string {
	return strings.ToLower(name) + "|" + strconv.Itoa(int(qtype))
}

// Get returns the cached packed response for the given name+type, or nil if
// not found or expired.
func (c *DNSCache) Get(name string, qtype uint16) []byte {
	k := cacheKey(name, qtype)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[k]
	if !ok {
		return nil
	}
	if time.Now().After(entry.expires) {
		delete(c.items, k)
		return nil
	}
	return entry.msg
}

// Set stores a packed DNS response with the given TTL, bounding memory to max 20,000 entries.
func (c *DNSCache) Set(name string, qtype uint16, msg []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	k := cacheKey(name, qtype)
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= maxDNSCacheEntries {
		now := time.Now()
		// Evict expired entries first
		for key, e := range c.items {
			if now.After(e.expires) {
				delete(c.items, key)
			}
		}
		// If still at or over capacity, evict an arbitrary batch of 1,000
		if len(c.items) >= maxDNSCacheEntries {
			for key := range c.items {
				delete(c.items, key)
				if len(c.items) < maxDNSCacheEntries-1000 {
					break
				}
			}
		}
	}

	c.items[k] = &cacheEntry{msg: msg, expires: time.Now().Add(ttl)}
}

// sweep periodically removes expired entries to bound memory usage.
func (c *DNSCache) sweep() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for k, e := range c.items {
				if now.After(e.expires) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		}
	}
}
