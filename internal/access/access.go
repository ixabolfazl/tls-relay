// Package access provides fast runtime access-control checks for the relay.
// It uses atomic.Pointer snapshots (like the existing rules package) to avoid
// blocking the per-connection hot path.
package access

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// AccessMode controls the system-wide access behaviour.
type AccessMode string

const (
	ModePublic AccessMode = "public"
	ModeUser   AccessMode = "user"
)

// blacklistSnapshot is an immutable snapshot of the global blacklist.
type blacklistSnapshot struct {
	cidrs []*net.IPNet
	ips   []net.IP
}

// userIPSnapshot is an immutable snapshot of all registered user IPs.
type userIPSnapshot struct {
	set map[string]struct{} // normalised IP strings
}

// EvictionHook is called immediately after access rule updates so active connections
// can be closed when permissions change.
type EvictionHook interface {
	EvictNotAllowed(allowedIPs map[string]struct{})
}

// BlacklistEvictionHook can optionally be implemented by EvictionHook to close
// active connections belonging to newly blacklisted IPs immediately.
type BlacklistEvictionHook interface {
	EvictBlacklisted(isBlacklisted func(net.IP) bool)
}

// AccessStore provides thread-safe, lock-free access-control checks.
type AccessStore struct {
	mode         atomic.Pointer[AccessMode]
	blacklist    atomic.Pointer[blacklistSnapshot]
	userIPs      atomic.Pointer[userIPSnapshot]
	evictionHook EvictionHook // optional; called after every SwapUserIPs
}

// NewAccessStore creates an AccessStore with the given mode and empty snapshots.
func NewAccessStore(mode AccessMode) *AccessStore {
	s := &AccessStore{}
	s.mode.Store(&mode)
	s.blacklist.Store(&blacklistSnapshot{})
	s.userIPs.Store(&userIPSnapshot{set: make(map[string]struct{})})
	return s
}

// SetEvictionHook registers a hook that is called with the new allowed-IP set
// after every SwapUserIPs.  Call this once during startup before any traffic
// flows; it is not thread-safe after initialisation.
func (s *AccessStore) SetEvictionHook(h EvictionHook) {
	s.evictionHook = h
}

// SetMode atomically updates the runtime access mode. When switching to ModeUser,
// active connections for unregistered IPs are evicted immediately.
func (s *AccessStore) SetMode(mode AccessMode) {
	s.mode.Store(&mode)
	if mode == ModeUser && s.evictionHook != nil {
		snap := s.userIPs.Load()
		if snap != nil {
			s.evictionHook.EvictNotAllowed(snap.set)
		}
	}
}

// SwapBlacklist atomically replaces the global blacklist. If an eviction hook
// supporting BlacklistEvictionHook is registered, it evicts active connections
// belonging to blacklisted IPs immediately.
func (s *AccessStore) SwapBlacklist(entries []string) error {
	snap, err := buildBlacklistSnapshot(entries)
	if err != nil {
		return err
	}
	s.blacklist.Store(snap)

	if bleh, ok := s.evictionHook.(BlacklistEvictionHook); ok {
		bleh.EvictBlacklisted(s.isBlacklisted)
	}
	return nil
}

// SwapUserIPs atomically replaces the registered user IP set.
// If an EvictionHook has been registered and the system is in ModeUser,
// it is called synchronously with the new allowed set so that connections
// belonging to removed IPs are closed immediately.
func (s *AccessStore) SwapUserIPs(ips []string) {
	set := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		// Normalise to canonical form.
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				set[v4.String()] = struct{}{}
			} else {
				set[parsed.String()] = struct{}{}
			}
		} else {
			// Keep original string if parsing fails.
			set[ip] = struct{}{}
		}
	}
	s.userIPs.Store(&userIPSnapshot{set: set})

	// In ModeUser, notify the eviction hook (e.g. ConnTracker) with the new allowed set so
	// it can immediately close connections for IPs that are no longer permitted.
	// In ModePublic, unregistered users are allowed, so we do not mass-evict them on user IP sync.
	if s.evictionHook != nil && s.Mode() == ModeUser {
		s.evictionHook.EvictNotAllowed(set)
	}
}

// CheckAccess determines whether a client IP is allowed to connect.
//
// Returns (allowed, reason) where reason is non-empty on rejection.
func (s *AccessStore) CheckAccess(ip net.IP) (allowed bool, reason string) {
	if s.isBlacklisted(ip) {
		return false, "blacklisted"
	}

	switch s.Mode() {
	case ModePublic:
		return true, ""
	case ModeUser:
		if s.isRegisteredUser(ip) {
			return true, ""
		}
		return false, "not_registered"
	default:
		return false, "invalid_mode"
	}
}

// IsBlacklisted checks only the global blacklist (used by magic link service).
func (s *AccessStore) IsBlacklisted(ip net.IP) bool {
	return s.isBlacklisted(ip)
}

// Mode returns the current access mode.
func (s *AccessStore) Mode() AccessMode {
	m := s.mode.Load()
	if m == nil {
		return ModeUser
	}
	return *m
}

// BlacklistEntries returns all current blacklist entries as strings.
func (s *AccessStore) BlacklistEntries() []string {
	snap := s.blacklist.Load()
	var out []string
	for _, ip := range snap.ips {
		out = append(out, ip.String())
	}
	for _, cidr := range snap.cidrs {
		out = append(out, cidr.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (s *AccessStore) isBlacklisted(ip net.IP) bool {
	snap := s.blacklist.Load()

	// Normalise to 4-byte for IPv4 comparisons.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	for _, plain := range snap.ips {
		if p := plain.To4(); p != nil {
			if p.Equal(ip) {
				return true
			}
		} else if plain.Equal(ip) {
			return true
		}
	}
	for _, cidr := range snap.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *AccessStore) isRegisteredUser(ip net.IP) bool {
	snap := s.userIPs.Load()
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	_, ok := snap.set[ip.String()]
	return ok
}

func buildBlacklistSnapshot(entries []string) (*blacklistSnapshot, error) {
	snap := &blacklistSnapshot{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Try CIDR first.
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			snap.cidrs = append(snap.cidrs, ipnet)
			continue
		}
		// Try plain IP.
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR entry %q", entry)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		snap.ips = append(snap.ips, ip)
	}
	return snap, nil
}
