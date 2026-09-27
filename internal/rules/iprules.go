package rules

import (
	"fmt"
	"net"
	"sync/atomic"
)

// IPMode controls the access-control behaviour.
type IPMode string

const (
	IPModeBlacklist IPMode = "blacklist"
	IPModeWhitelist IPMode = "whitelist"
)

// ipSnapshot is an immutable snapshot of the IP rule set.
type ipSnapshot struct {
	mode  IPMode
	cidrs []*net.IPNet
	ips   []net.IP // plain (non-CIDR) IPs, stored as 16-byte
}

// IPRuleSet holds the current IP access-control state and exposes a thread-safe
// Allowed check via an atomic.Pointer.
type IPRuleSet struct {
	snapshot atomic.Pointer[ipSnapshot]
}

// NewIPRuleSet creates an empty IPRuleSet in blacklist mode (fully open).
func NewIPRuleSet() *IPRuleSet {
	rs := &IPRuleSet{}
	rs.snapshot.Store(&ipSnapshot{mode: IPModeBlacklist})
	return rs
}

// Swap atomically replaces the IP rule set. mode is "whitelist" or "blacklist",
// entries is a slice of strings, each being either a plain IP or a CIDR range.
func (rs *IPRuleSet) Swap(mode IPMode, entries []string) error {
	snap, err := buildIPSnapshot(mode, entries)
	if err != nil {
		return err
	}
	rs.snapshot.Store(snap)
	return nil
}

func buildIPSnapshot(mode IPMode, entries []string) (*ipSnapshot, error) {
	snap := &ipSnapshot{mode: mode}
	for _, entry := range entries {
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
		snap.ips = append(snap.ips, ip)
	}
	return snap, nil
}

// Allowed returns true if the given IP is permitted to connect.
//
// Blacklist mode: allowed unless the IP matches an entry in the list.
// Whitelist mode: allowed only if the IP matches an entry in the list.
func (rs *IPRuleSet) Allowed(ip net.IP) bool {
	snap := rs.snapshot.Load()
	matched := rs.matches(snap, ip)
	switch snap.mode {
	case IPModeWhitelist:
		return matched
	default: // blacklist
		return !matched
	}
}

// Mode returns the current operating mode.
func (rs *IPRuleSet) Mode() IPMode {
	return rs.snapshot.Load().mode
}

// Entries returns all current entries (plain IPs and CIDRs) as strings.
func (rs *IPRuleSet) Entries() []string {
	snap := rs.snapshot.Load()
	var out []string
	for _, ip := range snap.ips {
		out = append(out, ip.String())
	}
	for _, cidr := range snap.cidrs {
		out = append(out, cidr.String())
	}
	return out
}

func (rs *IPRuleSet) matches(snap *ipSnapshot, ip net.IP) bool {
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
