// Package settings provides shared validation and formatting for system and panel settings.
package settings

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// ValidateAccessMode validates that the access mode is either "public" or "user".
func ValidateAccessMode(val string) (string, error) {
	return config.ValidateAccessMode(val)
}

// ValidateUnknownDomainPolicy validates the unknown domain policy.
func ValidateUnknownDomainPolicy(val, fallback string) (string, error) {
	return config.ValidateUnknownDomainPolicy(val, fallback)
}

// ValidatePanelPath validates and normalizes a panel URL path prefix.
func ValidatePanelPath(p string) (string, error) {
	return config.ValidatePanelPath(p)
}

// ValidateTimezone validates that the given timezone can be loaded by time.LoadLocation.
func ValidateTimezone(tz string) (string, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "", fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	return tz, nil
}

// ParseDurationWithDays parses duration strings supporting days (e.g. 7d, 24h, 1h).
func ParseDurationWithDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") || strings.HasSuffix(s, "D") {
		numStr := s[:len(s)-1]
		days, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days format %q: %w", s, err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if dur <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return dur, nil
}

// FormatDurationClean formats a duration into a human-readable string (e.g. 7d, 24h, 30m).
func FormatDurationClean(d time.Duration) string {
	if d <= 0 {
		return "24h"
	}
	if d%(24*time.Hour) == 0 && d >= 24*time.Hour {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// ValidateRetention validates request log retention and returns the canonical formatted string.
func ValidateRetention(s string) (string, time.Duration, error) {
	dur, err := ParseDurationWithDays(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid retention duration %q (e.g. 1h, 12h, 24h, 7d): %w", s, err)
	}
	return FormatDurationClean(dur), dur, nil
}

// ValidatePortsList parses a comma-separated list of ports or a JSON array of port numbers,
// validates that each port is between 1 and 65535, and returns the slice of ports and its JSON encoding.
func ValidatePortsList(raw string) ([]int, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", fmt.Errorf("ports list cannot be empty")
	}

	var ports []int
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		if err := json.Unmarshal([]byte(raw), &ports); err != nil {
			return nil, "", fmt.Errorf("invalid json ports array: %w", err)
		}
	} else {
		parts := strings.Split(raw, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			num, err := strconv.Atoi(p)
			if err != nil {
				return nil, "", fmt.Errorf("invalid port number %q: %w", p, err)
			}
			ports = append(ports, num)
		}
	}

	if len(ports) == 0 {
		return nil, "", fmt.Errorf("ports list cannot be empty")
	}

	seen := make(map[int]bool)
	var unique []int
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			return nil, "", fmt.Errorf("invalid port %d: must be between 1 and 65535", p)
		}
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	jsonBytes, err := json.Marshal(unique)
	if err != nil {
		return nil, "", err
	}
	return unique, string(jsonBytes), nil
}

// ValidateEgressAddr validates and normalizes an upstream SOCKS5 proxy address.
// Strips socks5:// or socks5h:// prefix, rejects http:// or https://, and requires net.SplitHostPort success.
func ValidateEgressAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", nil
	}
	addrLower := strings.ToLower(addr)
	if strings.HasPrefix(addrLower, "http://") || strings.HasPrefix(addrLower, "https://") {
		return "", fmt.Errorf("only SOCKS5 host:port is supported")
	}
	if strings.HasPrefix(addrLower, "socks5://") {
		addr = addr[len("socks5://"):]
	} else if strings.HasPrefix(addrLower, "socks5h://") {
		addr = addr[len("socks5h://"):]
	}
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("invalid proxy address (must be host:port): %s", raw)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", fmt.Errorf("invalid port in proxy address: %s", port)
	}
	return addr, nil
}

// ValidateBool parses boolean strings ("true", "1", "yes", "false", "0", "no").
func ValidateBool(raw string) (string, bool, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "true", "1", "yes", "on", "enabled":
		return "true", true, nil
	case "false", "0", "no", "off", "disabled":
		return "false", false, nil
	default:
		return "", false, fmt.Errorf("invalid boolean value %q (expected true or false)", raw)
	}
}

// ValidatePositiveInt parses and validates a positive integer string (> 0).
func ValidatePositiveInt(raw string, name string) (int, error) {
	raw = strings.TrimSpace(raw)
	val, err := strconv.Atoi(raw)
	if err != nil || val <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", name, raw)
	}
	return val, nil
}

// ValidateSetting validates a key-value pair for database persistence.
// Returns the canonicalized string value suitable for storing in SQLite.
func ValidateSetting(key, val string) (string, error) {
	key = strings.TrimSpace(key)
	switch key {
	case "access_mode":
		return ValidateAccessMode(val)
	case "unknown_domain_policy":
		return ValidateUnknownDomainPolicy(val, "")
	case "panel_path":
		return ValidatePanelPath(val)
	case "timezone":
		return ValidateTimezone(val)
	case "server_domain":
		d := strings.TrimSpace(val)
		if d == "" {
			return "", nil
		}
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		return d, nil
	case "request_logs_enabled":
		canon, _, err := ValidateBool(val)
		return canon, err
	case "request_logs_retention":
		canon, _, err := ValidateRetention(val)
		return canon, err
	case "max_connections_per_ip":
		n, err := ValidatePositiveInt(val, key)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(n), nil
	case "dns_unauthorized_passthrough_enabled":
		canon, _, err := ValidateBool(val)
		return canon, err
	case "allowed_dest_ports", "listen_ports", "listen_http_ports":
		_, canonJSON, err := ValidatePortsList(val)
		return canonJSON, err
	case "dns_upstream_addr":
		_, canon, err := ValidateUpstreamList(val)
		return canon, err
	case "lookup_enabled", "lookup_require_registered", "update_check_enabled":
		canon, _, err := ValidateBool(val)
		return canon, err
	case "http_front_max_conns_per_ip", "http_front_max_global_conns":
		n, err := ValidatePositiveInt(val, key)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(n), nil
	case "egress_proxy_enabled":
		canon, _, err := ValidateBool(val)
		return canon, err
	case "egress_proxy_addr":
		return ValidateEgressAddr(val)
	case "egress_proxy_user":
		return strings.TrimSpace(val), nil
	case "egress_proxy_password":
		return val, nil
	default:
		return "", fmt.Errorf("unknown setting key %q", key)
	}
}

// ValidateUpstreamList parses a comma-separated list of host:port or a JSON array of strings,
// defaults bare IPs/hostnames to port 53, deduplicates entries preserving order,
// validates that each entry has a valid host and port between 1 and 65535,
// and enforces between 1 and 5 upstream servers.
// Returns the slice of upstream addresses and the canonical comma-separated string.
func ValidateUpstreamList(raw string) ([]string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", fmt.Errorf("upstream list cannot be empty")
	}

	var rawEntries []string
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		var jsonList []string
		if err := json.Unmarshal([]byte(raw), &jsonList); err == nil {
			rawEntries = jsonList
		} else {
			rawEntries = []string{raw}
		}
	} else {
		parts := strings.Split(raw, ",")
		for _, p := range parts {
			rawEntries = append(rawEntries, p)
		}
	}

	var list []string
	seen := make(map[string]bool)

	for _, entry := range rawEntries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		canon, err := normalizeUpstreamEntry(entry)
		if err != nil {
			return nil, "", err
		}

		if !seen[canon] {
			seen[canon] = true
			list = append(list, canon)
		}
	}

	if len(list) == 0 {
		return nil, "", fmt.Errorf("upstream list cannot be empty")
	}
	if len(list) > 5 {
		return nil, "", fmt.Errorf("too many upstream servers: maximum 5, got %d", len(list))
	}

	return list, strings.Join(list, ","), nil
}

func isAllDigitsAndDots(s string) bool {
	if s == "" {
		return false
	}
	hasDot := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			hasDot = true
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return hasDot
}

func isValidHostnameLabel(label string) bool {
	return rules.IsValidHostnameLabel(label)
}

func isValidHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if !isValidHostnameLabel(label) {
			return false
		}
	}
	return true
}

func normalizeUpstreamEntry(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", fmt.Errorf("upstream entry cannot be empty")
	}

	host, portStr, err := net.SplitHostPort(entry)
	if err == nil {
		port, pErr := strconv.Atoi(portStr)
		if pErr != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid port in upstream address %q: must be between 1 and 65535", entry)
		}
		if isAllDigitsAndDots(host) {
			ip := net.ParseIP(host)
			if ip == nil || ip.To4() == nil {
				return "", fmt.Errorf("invalid IPv4 address %q in upstream address %q", host, entry)
			}
			return fmt.Sprintf("%s:%d", ip.String(), port), nil
		}
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() == nil {
				return fmt.Sprintf("[%s]:%d", ip.String(), port), nil
			}
			return fmt.Sprintf("%s:%d", ip.String(), port), nil
		}
		if isValidHostname(host) {
			return fmt.Sprintf("%s:%d", strings.ToLower(host), port), nil
		}
		return "", fmt.Errorf("invalid host %q in upstream address %q", host, entry)
	}

	// SplitHostPort failed. Check if port was omitted.
	unbracketed := entry
	if strings.HasPrefix(unbracketed, "[") && strings.HasSuffix(unbracketed, "]") {
		unbracketed = unbracketed[1 : len(unbracketed)-1]
	}

	if isAllDigitsAndDots(unbracketed) {
		ip := net.ParseIP(unbracketed)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid IPv4 address %q in upstream address %q", entry, entry)
		}
		return fmt.Sprintf("%s:53", ip.String()), nil
	}

	if ip := net.ParseIP(unbracketed); ip != nil {
		if ip.To4() == nil {
			return fmt.Sprintf("[%s]:53", ip.String()), nil
		}
		return fmt.Sprintf("%s:53", ip.String()), nil
	}

	if isValidHostname(entry) {
		return fmt.Sprintf("%s:53", strings.ToLower(entry)), nil
	}

	return "", fmt.Errorf("invalid upstream address %q: %w", entry, err)
}
