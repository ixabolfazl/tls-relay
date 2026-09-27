package panel

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	hostnameLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
)

// NormalizeAndValidateServerDomain cleans up a raw domain or host string
// (removing schemes, paths, trailing slashes, etc.) and validates that it forms
// a syntactically valid domain name, hostname, or IP address.
// An empty or whitespace-only string is considered valid and returned as "" (clearing the setting).
func NormalizeAndValidateServerDomain(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}

	// If a scheme is included, parse via url.Parse to extract Host
	candidate := trimmed
	if strings.Contains(candidate, "://") || strings.HasPrefix(candidate, "//") {
		if strings.HasPrefix(candidate, "//") {
			candidate = "http:" + candidate
		}
		u, err := url.Parse(candidate)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("invalid domain or URL %q", trimmed)
		}
		candidate = u.Host
	} else {
		// Strip any trailing path, query, or fragment if user entered e.g. example.com/path
		if idx := strings.IndexAny(candidate, "/?#"); idx != -1 {
			candidate = candidate[:idx]
		}
	}

	candidate = strings.TrimSpace(candidate)
	candidate = strings.Trim(candidate, "/")
	candidate = strings.ToLower(candidate)

	if candidate == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	// Separate host and port if present
	var host, portStr string
	if strings.Contains(candidate, ":") && !strings.HasPrefix(candidate, "[") && strings.Count(candidate, ":") == 1 {
		var err error
		host, portStr, err = net.SplitHostPort(candidate)
		if err != nil {
			return "", fmt.Errorf("invalid host:port format in %q", trimmed)
		}
	} else if strings.HasPrefix(candidate, "[") && strings.Contains(candidate, "]:") {
		var err error
		host, portStr, err = net.SplitHostPort(candidate)
		if err != nil {
			return "", fmt.Errorf("invalid IPv6 host:port format in %q", trimmed)
		}
	} else {
		host = candidate
	}

	// Validate port if provided
	if portStr != "" {
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum < 1 || portNum > 65535 {
			return "", fmt.Errorf("invalid port number %q in domain", portStr)
		}
		// If port is standard HTTP (80), omit it
		if portNum == 80 {
			portStr = ""
		}
	}

	// Strip IPv6 brackets for IP checking
	cleanHost := strings.Trim(host, "[]")

	// Check if cleanHost is a valid IP
	if ip := net.ParseIP(cleanHost); ip != nil {
		if portStr != "" {
			if strings.Contains(cleanHost, ":") {
				return fmt.Sprintf("[%s]:%s", cleanHost, portStr), nil
			}
			return fmt.Sprintf("%s:%s", cleanHost, portStr), nil
		}
		return cleanHost, nil
	}

	// Validate domain / hostname syntax (RFC 1123)
	cleanHost = strings.TrimSuffix(cleanHost, ".")
	if len(cleanHost) == 0 || len(cleanHost) > 253 {
		return "", fmt.Errorf("domain length must be between 1 and 253 characters")
	}

	labels := strings.Split(cleanHost, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return "", fmt.Errorf("domain contains empty label or consecutive dots in %q", trimmed)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("domain label %q exceeds 63 characters", label)
		}
		if !hostnameLabelRegex.MatchString(label) {
			return "", fmt.Errorf("domain label %q contains invalid characters (must be alphanumeric and hyphens, not starting/ending with hyphen)", label)
		}
	}

	if portStr != "" {
		return fmt.Sprintf("%s:%s", cleanHost, portStr), nil
	}
	return cleanHost, nil
}
