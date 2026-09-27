// Package rules provides in-memory domain rule lookup and IP access-control
// checking. Both caches are updated atomically via atomic.Pointer swaps so
// the per-connection hot path never blocks on a mutex.
package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

// PortsSpec represents either a list of specific ports or the sentinel "all".
// When All is true, the relay falls back to the global allowed_dest_ports list.
type PortsSpec struct {
	All   bool
	Ports []int
}

// UnmarshalJSON implements json.Unmarshaler. The JSON value is either an array
// of ints or the string "all".
func (ps *PortsSpec) UnmarshalJSON(data []byte) error {
	// Try string first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s != "all" {
			return fmt.Errorf("ports: expected array of ints or the string \"all\", got %q", s)
		}
		ps.All = true
		return nil
	}
	// Try int array.
	var ports []int
	if err := json.Unmarshal(data, &ports); err != nil {
		return fmt.Errorf("ports: expected array of ints or the string \"all\": %w", err)
	}
	ps.Ports = ports
	return nil
}

// MarshalJSON encodes back to either "all" or an int array.
func (ps PortsSpec) MarshalJSON() ([]byte, error) {
	if ps.All {
		return json.Marshal("all")
	}
	if ps.Ports == nil {
		ps.Ports = []int{443} // default
	}
	return json.Marshal(ps.Ports)
}

// DomainRule is the stored configuration for a single domain (or wildcard pattern).
type DomainRule struct {
	GroupName      string    `json:"group_name,omitempty"`
	Ports          PortsSpec `json:"ports"`
	UseEgressProxy string    `json:"use_egress_proxy,omitempty"` // "default", "true", "false"
	Mode           string    `json:"mode,omitempty"`             // "proxy" | "direct" | "block"; default "proxy"
}

// NormalizeMode validates and normalizes a mode string.
// Accepts "proxy", "direct", "block", or "" (normalizes to "proxy").
func NormalizeMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "proxy":
		return "proxy", nil
	case "direct":
		return "direct", nil
	case "block":
		return "block", nil
	}
	return "", fmt.Errorf("invalid mode %q: must be \"proxy\", \"direct\", or \"block\"", s)
}

// domainSnapshot is an immutable snapshot of the full domain rule table.
// Readers get a pointer via atomic.Pointer.Load() and use it without locking.
type domainSnapshot struct {
	// exact holds rules keyed by the exact hostname string.
	exact map[string]DomainRule
	// wildcards holds (suffix, rule) pairs where suffix is e.g. "example.com"
	// for the pattern "*.example.com". Sorted by suffix length descending so
	// the most-specific wildcard wins when multiple could match.
	wildcards []wildcardEntry
}

type wildcardEntry struct {
	// suffix is the domain part after "*.", e.g. "google.com" for "*.google.com"
	suffix string
	rule   DomainRule
}

// RuleStore holds the in-memory domain rules and exposes a thread-safe Lookup.
type RuleStore struct {
	snapshot    atomic.Pointer[domainSnapshot]
	globalPorts []int                  // global allowed_dest_ports from config, for "all" fallback
	policy      atomic.Pointer[string] // "reject" | "allow_default_port"
}

// NewRuleStore creates a RuleStore with an empty initial state.
func NewRuleStore(globalPorts []int, policy string) *RuleStore {
	rs := &RuleStore{
		globalPorts: globalPorts,
	}
	rs.policy.Store(&policy)
	rs.snapshot.Store(&domainSnapshot{
		exact:     make(map[string]DomainRule),
		wildcards: nil,
	})
	return rs
}

// Swap replaces the full rule table atomically. rawRules maps each key (exact
// domain or "*.example.com" pattern) to its JSON-encoded DomainRule.
func (rs *RuleStore) Swap(rawRules map[string]string) error {
	snap, err := buildSnapshot(rawRules)
	if err != nil {
		return err
	}
	rs.snapshot.Store(snap)
	return nil
}

// buildSnapshot parses rawRules into an immutable domainSnapshot.
func buildSnapshot(rawRules map[string]string) (*domainSnapshot, error) {
	snap := &domainSnapshot{
		exact: make(map[string]DomainRule, len(rawRules)),
	}
	for key, val := range rawRules {
		var rule DomainRule
		if err := json.Unmarshal([]byte(val), &rule); err != nil {
			return nil, fmt.Errorf("parsing rule for key %q: %w", key, err)
		}
		// Default ports to [443] when the field is missing (both All=false and Ports=nil).
		if !rule.Ports.All && len(rule.Ports.Ports) == 0 {
			rule.Ports.Ports = []int{443}
		}
		// Default mode to "proxy" when the field is missing.
		if rule.Mode == "" {
			rule.Mode = "proxy"
		}

		if strings.HasPrefix(key, "*.") {
			suffix := key[2:] // strip "*."
			snap.wildcards = append(snap.wildcards, wildcardEntry{suffix: suffix, rule: rule})
		} else {
			snap.exact[key] = rule
		}
	}
	// Sort wildcards by suffix length descending (most specific first).
	sortWildcards(snap.wildcards)
	return snap, nil
}

// sortWildcards sorts wildcardEntry slice by suffix length descending.
func sortWildcards(entries []wildcardEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && len(entries[j].suffix) > len(entries[j-1].suffix); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

// MatchInfo describes the details of a domain rule match.
type MatchInfo struct {
	Matched bool
	Kind    string // "exact" | "wildcard" | "none"
	Rule    string // "" for exact/none, "*.example.com" for wildcard
}

// LookupDetailed checks whether hostname:port is permitted by the domain rules
// in a single atomic snapshot read, returning whether the port is allowed,
// the matched DomainRule, and the match details. This consolidates rule lookup
// to eliminate race conditions during concurrent configuration swaps and avoid
// redundant map/slice scans on the hot path.
func (rs *RuleStore) LookupDetailed(hostname string, port int) (allowed bool, rule DomainRule, info MatchInfo) {
	snap := rs.snapshot.Load()

	// 1. Exact match.
	if r, ok := snap.exact[hostname]; ok {
		return rs.portAllowed(r, port), r, MatchInfo{
			Matched: true,
			Kind:    "exact",
			Rule:    "",
		}
	}

	// 2. Wildcard match.
	for _, wc := range snap.wildcards {
		if matchesWildcard(hostname, wc.suffix) {
			return rs.portAllowed(wc.rule, port), wc.rule, MatchInfo{
				Matched: true,
				Kind:    "wildcard",
				Rule:    "*." + wc.suffix,
			}
		}
	}

	return false, DomainRule{}, MatchInfo{
		Matched: false,
		Kind:    "none",
		Rule:    "",
	}
}

// LookupWithMatchInfo checks whether hostname:port is permitted by the domain rules
// and additionally surfaces match details (Kind and Rule).
func (rs *RuleStore) LookupWithMatchInfo(hostname string, port int) (allowed bool, info MatchInfo) {
	allowed, _, info = rs.LookupDetailed(hostname, port)
	return
}

// Lookup checks whether hostname:port is permitted by the domain rules.
//
// Returns (allowed bool, matched bool).
//   - allowed=true, matched=true  → explicitly allowed by a domain rule.
//   - allowed=false, matched=true → explicitly denied by a domain rule (port not listed).
//   - allowed=false, matched=false → no domain rule found; caller should check policy.
func (rs *RuleStore) Lookup(hostname string, port int) (allowed, matched bool) {
	allowed, _, info := rs.LookupDetailed(hostname, port)
	return allowed, info.Matched
}

// LookupRule checks if a rule matches the hostname and returns it if so.
func (rs *RuleStore) LookupRule(hostname string) (DomainRule, bool) {
	snap := rs.snapshot.Load()

	// 1. Exact match.
	if rule, ok := snap.exact[hostname]; ok {
		return rule, true
	}

	// 2. Wildcard match.
	for _, wc := range snap.wildcards {
		if matchesWildcard(hostname, wc.suffix) {
			return wc.rule, true
		}
	}

	return DomainRule{}, false
}

// portAllowed checks whether port is permitted by the rule.
func (rs *RuleStore) portAllowed(rule DomainRule, port int) bool {
	if rule.Ports.All {
		// Fall back to global allowed_dest_ports.
		for _, p := range rs.globalPorts {
			if p == port {
				return true
			}
		}
		return false
	}
	for _, p := range rule.Ports.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// SetUnknownDomainPolicy updates the unknown domain policy atomically.
func (rs *RuleStore) SetUnknownDomainPolicy(policy string) {
	rs.policy.Store(&policy)
}

// UnknownDomainPolicy returns the current unknown domain policy.
func (rs *RuleStore) UnknownDomainPolicy() string {
	p := rs.policy.Load()
	if p == nil {
		return "allow_default_port"
	}
	return *p
}

// IsPortAllowedByPolicy returns whether the port is allowed when no domain
// rule matched, based on the configured unknown_domain_policy.
func (rs *RuleStore) IsPortAllowedByPolicy(port int) bool {
	if rs.UnknownDomainPolicy() != "allow_default_port" {
		return false
	}
	for _, p := range rs.globalPorts {
		if p == port {
			return true
		}
	}
	return false
}

// matchesWildcard returns true if hostname is a subdomain of suffix (one or
// more label levels), but NOT if hostname == suffix itself.
//
// e.g. matchesWildcard("api.example.com", "example.com") == true
//
//	matchesWildcard("example.com",     "example.com") == false
//	matchesWildcard("evilgoogle.com",  "google.com")  == false
func matchesWildcard(hostname, suffix string) bool {
	// hostname must be longer than suffix (at least "x." + suffix).
	if len(hostname) <= len(suffix)+1 {
		return false
	}
	// The character just before the suffix in hostname must be a dot.
	offset := len(hostname) - len(suffix)
	if hostname[offset-1] != '.' {
		return false
	}
	// The tail of hostname must equal suffix (case-insensitive via ToLower).
	return strings.EqualFold(hostname[offset:], suffix)
}

// AllRules returns a snapshot of all current rules as a map of key → DomainRule.
// This is used by the admin panel API to list rules.
func (rs *RuleStore) AllRules() map[string]DomainRule {
	snap := rs.snapshot.Load()
	out := make(map[string]DomainRule, len(snap.exact)+len(snap.wildcards))
	for k, v := range snap.exact {
		out[k] = v
	}
	for _, wc := range snap.wildcards {
		out["*."+wc.suffix] = wc.rule
	}
	return out
}

// PortsSpecFromJSON parses the raw JSON ports field stored in the database.
func PortsSpecFromJSON(raw string) (PortsSpec, error) {
	var ps PortsSpec
	if err := json.Unmarshal([]byte(raw), &ps); err != nil {
		return PortsSpec{}, err
	}
	return ps, nil
}

// MarshalDomainRule encodes a DomainRule to JSON for storage in the database.
func MarshalDomainRule(rule DomainRule) (string, error) {
	b, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParsePorts parses a string like "443,8443", "[443]", "\"all\"", or "all" into a PortsSpec.
// Used when the panel submits a ports value as a string.
func ParsePorts(s string) (PortsSpec, error) {
	s = strings.TrimSpace(s)
	// Remove escaped quotes or surrounding quotes/brackets repeatedly if nested
	for {
		orig := s
		s = strings.Trim(s, `"' \`)
		if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			s = strings.TrimSpace(s[1 : len(s)-1])
		}
		if s == orig {
			break
		}
	}
	if strings.EqualFold(s, "all") {
		return PortsSpec{All: true}, nil
	}
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"' \`)
		if p == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n <= 0 || n > 65535 {
			return PortsSpec{}, fmt.Errorf("invalid port %q", p)
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return PortsSpec{}, fmt.Errorf("at least one port is required")
	}
	return PortsSpec{Ports: ports}, nil
}

// IPCheckAllowed validates a single client IP string against the IP rule set.
// It is a convenience wrapper used in tests and by the relay connection handler.
func IPCheckAllowed(rs *IPRuleSet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return rs.Allowed(ip)
}
