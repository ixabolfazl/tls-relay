package dnsresolver

import (
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	// dnsCheckSuffix is the reserved suffix for DNS probe queries.
	// Must be in dnscheck.tls-relay.invalid. (RFC 2606 .invalid zone).
	dnsCheckSuffix = ".dnscheck.tls-relay.invalid"

	// dnsCheckMaxTokens is the upper bound on simultaneously tracked tokens.
	dnsCheckMaxTokens = 10000

	// dnsCheckTTL is how long an issued token is tracked in the registry.
	dnsCheckTTL = 2 * time.Minute
)

// DNSCheckEntry records the resolver seeing a particular token.
type DNSCheckEntry struct {
	// SeenAt is the time the resolver first observed the query.
	SeenAt time.Time
	// SourceIP is the DNS query source IP (may differ from the HTTP client IP).
	SourceIP string
}

// issuedEntry tracks a token that was issued by the portal but not yet seen by the resolver.
type issuedEntry struct {
	issuedAt time.Time
}

// DNSCheckRegistry is a bounded, TTL-based in-memory registry of DNS check tokens.
// Tokens are issued by the portal and recorded by the resolver when a probe query arrives.
type DNSCheckRegistry struct {
	mu     sync.Mutex
	issued map[string]*issuedEntry // tokens issued but not yet resolved
	seen   map[string]*DNSCheckEntry
	stopCh chan struct{}
}

// NewDNSCheckRegistry creates a registry and starts its background sweeper.
func NewDNSCheckRegistry() *DNSCheckRegistry {
	r := &DNSCheckRegistry{
		issued: make(map[string]*issuedEntry),
		seen:   make(map[string]*DNSCheckEntry),
		stopCh: make(chan struct{}),
	}
	go r.sweep()
	return r
}

// Close stops the background sweeper.
func (r *DNSCheckRegistry) Close() {
	if r.stopCh != nil {
		select {
		case <-r.stopCh:
		default:
			close(r.stopCh)
		}
	}
}

// Issue marks a token as issued (expected to be queried soon).
// It enforces the bounded-size limit by dropping the oldest issued entry when full.
func (r *DNSCheckRegistry) Issue(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Enforce bound
	if len(r.issued)+len(r.seen) >= dnsCheckMaxTokens {
		// Evict oldest issued entry
		var oldest string
		var oldestTime time.Time
		for k, e := range r.issued {
			if oldest == "" || e.issuedAt.Before(oldestTime) {
				oldest = k
				oldestTime = e.issuedAt
			}
		}
		if oldest != "" {
			delete(r.issued, oldest)
		}
	}
	r.issued[token] = &issuedEntry{issuedAt: time.Now()}
}

// IsIssued returns true if a token was issued (whether or not it has been seen yet).
func (r *DNSCheckRegistry) IsIssued(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, inIssued := r.issued[token]
	_, inSeen := r.seen[token]
	return inIssued || inSeen
}

// Record marks a token as seen by the resolver.
// Returns false if the token was never issued or has already expired.
func (r *DNSCheckRegistry) Record(token, sourceIP string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.issued[token]; !ok {
		if _, alreadySeen := r.seen[token]; !alreadySeen {
			return false
		}
		// Already seen: update source IP but keep the original SeenAt.
		r.seen[token].SourceIP = sourceIP
		return true
	}
	delete(r.issued, token)
	r.seen[token] = &DNSCheckEntry{
		SeenAt:   time.Now(),
		SourceIP: sourceIP,
	}
	return true
}

// Lookup returns the seen entry for a token, or (nil, false) if not seen.
func (r *DNSCheckRegistry) Lookup(token string) (*DNSCheckEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.seen[token]
	if !ok {
		return nil, false
	}
	return entry, true
}

// sweep periodically removes expired entries.
func (r *DNSCheckRegistry) sweep() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			for token, e := range r.issued {
				if now.Sub(e.issuedAt) > dnsCheckTTL {
					delete(r.issued, token)
				}
			}
			for token, e := range r.seen {
				if now.Sub(e.SeenAt) > dnsCheckTTL {
					delete(r.seen, token)
				}
			}
			r.mu.Unlock()
		}
	}
}

// isDNSCheckQuery returns the token if qname is a valid DNS check probe,
// otherwise returns ("", false). This is a cheap suffix check on the
// already-lowercased qname — no IDNA or URL parsing on the hot path.
func isDNSCheckQuery(qname string) (token string, ok bool) {
	if !strings.HasSuffix(qname, dnsCheckSuffix) {
		return "", false
	}
	token = strings.TrimSuffix(qname, dnsCheckSuffix)
	// Token must be 16–32 lowercase hex characters.
	if len(token) < 16 || len(token) > 32 {
		return "", false
	}
	if _, err := hex.DecodeString(token); err != nil {
		return "", false
	}
	return token, true
}
