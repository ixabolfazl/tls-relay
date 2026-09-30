// normalize.go — smart domain input parsing for the admin panel write path.
//
// PERFORMANCE CONTRACT: NormalizeDomainInput is called ONLY from admin-panel
// write handlers (handleAddDomain, handleUpdateDomain, bulk-add, import).
// It must NEVER be called from the TLS relay connection path, the DNS resolver
// query path, or RuleStore.Lookup / LookupRule / IsConfigured. Domains are
// stored pre-normalized at write time; read/match time never re-normalizes.
package rules

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeDomainInput parses a single raw domain token (which may be a full
// URL, a host:port, a bare hostname, or a *.wildcard) and returns the
// canonical bare hostname that should be stored as a domain rule.
//
// Parsing rules applied in order:
//  1. Trim whitespace; reject if empty.
//  2. Preserve a leading "*." wildcard prefix; reject bare "*" without dot.
//  3. Strip URL scheme (https://, http://, wss://, ws://, ftp://, bare //).
//  4. Strip userinfo (user:pass@).
//  5. Reject bracketed IPv6 hosts ([::1], [2001:db8::1]:443).
//  6. Strip path, query string, and fragment.
//  7. Strip port suffix from non-IP hostname (host:port → host).
//     Bare IPv6 literals (multiple colons) are rejected here.
//  8. Lowercase; trim trailing FQDN dot.
//  9. Reject bare IPv4 and IPv6 addresses.
//
// 10. Reject stray "*" characters in the hostname part.
// 11. Convert non-ASCII labels to punycode via golang.org/x/net/idna.
// 12. Validate hostname label syntax.
// 13. Re-attach wildcard prefix and return.
func NormalizeDomainInput(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty domain")
	}

	// -----------------------------------------------------------------------
	// 1. Strip URL scheme.
	// -----------------------------------------------------------------------
	if strings.HasPrefix(s, "//") {
		// Bare protocol-relative URL.
		s = s[2:]
	} else {
		// Case-insensitive scheme match; strip by the known scheme length.
		sLower := strings.ToLower(s)
		for _, scheme := range []string{"https://", "http://", "wss://", "ws://", "ftp://"} {
			if strings.HasPrefix(sLower, scheme) {
				s = s[len(scheme):]
				break
			}
		}
	}

	// -----------------------------------------------------------------------
	// 2. Handle wildcard prefix.
	// -----------------------------------------------------------------------
	hasWildcard := false
	if strings.HasPrefix(s, "*.") {
		hasWildcard = true
		s = s[2:] // strip "*." — we re-attach it at the end
	} else if len(s) > 0 && s[0] == '*' {
		// "*" present but not followed by "." — invalid syntax.
		return "", fmt.Errorf("invalid wildcard syntax: '*' must be followed by '.' (e.g. '*.example.com')")
	}

	// -----------------------------------------------------------------------
	// 3. Strip userinfo (user:pass@ or user@).
	// -----------------------------------------------------------------------
	if atIdx := strings.Index(s, "@"); atIdx >= 0 {
		// Only strip if "@" appears before the first path separator.
		slashIdx := strings.Index(s, "/")
		if slashIdx < 0 || atIdx < slashIdx {
			s = s[atIdx+1:]
		}
	}

	// -----------------------------------------------------------------------
	// 4. Reject bracketed IPv6 hosts — before any other processing.
	// -----------------------------------------------------------------------
	if len(s) > 0 && s[0] == '[' {
		return "", fmt.Errorf("IP addresses are not valid SNI domains")
	}

	// -----------------------------------------------------------------------
	// 5. Strip path, query string, and fragment.
	//    Find the earliest of '/', '?', '#' and truncate there.
	// -----------------------------------------------------------------------
	cutAt := len(s)
	for _, sep := range []byte{'/', '?', '#'} {
		if idx := strings.IndexByte(s, sep); idx >= 0 && idx < cutAt {
			cutAt = idx
		}
	}
	s = s[:cutAt]

	// -----------------------------------------------------------------------
	// 6. Strip port; detect bare IPv6.
	// -----------------------------------------------------------------------
	colonCount := strings.Count(s, ":")
	switch {
	case colonCount > 1:
		// Multiple colons → bare IPv6 literal (e.g. "::1", "2001:db8::1").
		return "", fmt.Errorf("IP addresses are not valid SNI domains")
	case colonCount == 1:
		// Possible host:port — split and take the host portion.
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			// Could not split — check whether the whole thing is an IP.
			if net.ParseIP(s) != nil {
				return "", fmt.Errorf("IP addresses are not valid SNI domains")
			}
			return "", fmt.Errorf("malformed host:port %q: %w", s, err)
		}
		// host must not itself be a bracketed IPv6 (SplitHostPort strips brackets).
		if net.ParseIP(host) != nil && strings.Contains(host, ":") {
			return "", fmt.Errorf("IP addresses are not valid SNI domains")
		}
		s = host
	}

	// -----------------------------------------------------------------------
	// 7. Lowercase + trim trailing FQDN dot.
	// -----------------------------------------------------------------------
	s = strings.ToLower(strings.TrimSuffix(s, "."))

	// -----------------------------------------------------------------------
	// 8. Reject bare IP addresses (IPv4 or IPv6).
	// -----------------------------------------------------------------------
	if net.ParseIP(s) != nil {
		return "", fmt.Errorf("IP addresses are not valid SNI domains")
	}

	// -----------------------------------------------------------------------
	// 9. Reject stray '*' in the hostname portion (e.g. "example.*.com",
	//    "foo*.example.com", "*.*.example.com" after its outer *. was stripped).
	// -----------------------------------------------------------------------
	if strings.Contains(s, "*") {
		if hasWildcard {
			return "", fmt.Errorf("invalid wildcard syntax: only a single leading '*.' is allowed (e.g. '*.example.com')")
		}
		return "", fmt.Errorf("invalid wildcard syntax: '*' may only appear as a leading '*.' prefix")
	}

	// -----------------------------------------------------------------------
	// 10. Reject empty host (e.g. scheme-only "https://" → stripped to "").
	// -----------------------------------------------------------------------
	if s == "" {
		if hasWildcard {
			return "", fmt.Errorf("invalid hostname syntax: empty domain after wildcard prefix")
		}
		return "", fmt.Errorf("empty domain after normalization")
	}

	// -----------------------------------------------------------------------
	// 11. IDN / punycode conversion for non-ASCII hostnames.
	//     Applied to the hostname portion only (without the "*." prefix).
	// -----------------------------------------------------------------------
	if !isASCIIString(s) {
		converted, err := idna.Lookup.ToASCII(s)
		if err != nil {
			return "", fmt.Errorf("invalid internationalized domain name %q: %w", s, err)
		}
		s = converted
	}

	// -----------------------------------------------------------------------
	// 12. Validate each hostname label.
	// -----------------------------------------------------------------------
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !isValidHostnameLabel(label) {
			return "", fmt.Errorf("invalid hostname syntax: label %q is not a valid DNS label", label)
		}
	}

	// -----------------------------------------------------------------------
	// 13. Re-attach wildcard prefix.
	// -----------------------------------------------------------------------
	if hasWildcard {
		return "*." + s, nil
	}
	return s, nil
}

// isASCIIString returns true if every byte of s is a 7-bit ASCII character.
func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// IsValidHostnameLabel returns true if label is a syntactically valid DNS
// hostname label: 1–63 characters, consisting of [a-zA-Z0-9] and hyphens,
// with no leading or trailing hyphen. This also accepts punycode labels
// (xn--…) since they satisfy the same character constraints.
func IsValidHostnameLabel(label string) bool {
	n := len(label)
	if n == 0 || n > 63 {
		return false
	}
	for i := 0; i < n; i++ {
		c := label[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		isHyphen := c == '-'
		if !isAlphaNum && !isHyphen {
			return false
		}
		// Hyphens may not appear at the first or last position.
		if isHyphen && (i == 0 || i == n-1) {
			return false
		}
	}
	return true
}

func isValidHostnameLabel(label string) bool {
	return IsValidHostnameLabel(label)
}
