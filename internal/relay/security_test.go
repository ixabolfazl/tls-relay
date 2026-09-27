package relay

import (
	"net"
	"testing"
)

func TestSecurityChecker_IsBlocked(t *testing.T) {
	// 1. sc configured with blockPrivate = true
	sc, err := NewSecurityChecker(true, false, nil)
	if err != nil {
		t.Fatalf("failed to create security checker: %v", err)
	}

	cases := []struct {
		ip      string
		blocked bool
		reason  string
	}{
		// Loopback
		{"127.0.0.1", true, "loopback"},
		{"::1", true, "loopback"},
		// Private (RFC 1918)
		{"10.0.0.1", true, "private"},
		{"172.16.0.1", true, "private"},
		{"192.168.1.1", true, "private"},
		// Link local
		{"169.254.1.1", true, "link_local"},
		{"fe80::1", true, "link_local"},
		// Unspecified
		{"0.0.0.0", true, "unspecified"},
		{"::", true, "unspecified"},
		// Multicast
		{"224.0.0.1", true, "link_local"}, // Link-local multicast, matched first
		{"ff02::1", true, "link_local"},   // Link-local multicast, matched first
		// CGNAT (100.64.0.0/10)
		{"100.64.0.1", true, "cgnat"},
		{"100.127.255.255", true, "cgnat"},
		{"100.128.0.1", false, ""}, // outside CGNAT range
		// IPv4-mapped IPv6
		{"::ffff:127.0.0.1", true, "loopback"},
		{"::ffff:10.0.0.1", true, "private"},
		{"::ffff:192.168.1.1", true, "private"},
		{"::ffff:1.1.1.1", false, ""},
		// Public (should not be blocked)
		{"1.1.1.1", false, ""},
		{"8.8.8.8", false, ""},
		{"2606:4700:4700::1111", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			parsedIP := net.ParseIP(tc.ip)
			if parsedIP == nil {
				t.Fatalf("failed to parse IP: %s", tc.ip)
			}
			gotReason := sc.isBlocked(parsedIP)
			gotBlocked := gotReason != ""
			if gotBlocked != tc.blocked {
				t.Errorf("isBlocked(%s): blocked=%v, want %v", tc.ip, gotBlocked, tc.blocked)
			}
			if gotReason != tc.reason {
				t.Errorf("isBlocked(%s): reason=%q, want %q", tc.ip, gotReason, tc.reason)
			}
		})
	}
}

func TestSecurityChecker_ExtraCIDRs(t *testing.T) {
	sc, err := NewSecurityChecker(false, false, []string{"192.0.2.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("failed to create security checker: %v", err)
	}

	cases := []struct {
		ip      string
		blocked bool
		reason  string
	}{
		{"192.0.2.1", true, "extra_blocked_cidr(192.0.2.0/24)"},
		{"192.0.2.254", true, "extra_blocked_cidr(192.0.2.0/24)"},
		{"192.0.3.1", false, ""},
		{"2001:db8::1", true, "extra_blocked_cidr(2001:db8::/32)"},
		{"2001:db9::1", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			parsedIP := net.ParseIP(tc.ip)
			gotReason := sc.isBlocked(parsedIP)
			gotBlocked := gotReason != ""
			if gotBlocked != tc.blocked {
				t.Errorf("isBlocked(%s): blocked=%v, want %v", tc.ip, gotBlocked, tc.blocked)
			}
			if gotReason != tc.reason {
				t.Errorf("isBlocked(%s): reason=%q, want %q", tc.ip, gotReason, tc.reason)
			}
		})
	}
}

func TestSecurityChecker_BlockOwn(t *testing.T) {
	sc, err := NewSecurityChecker(false, true, nil)
	if err != nil {
		t.Fatalf("failed to create security checker: %v", err)
	}

	// Manually seed ownIPs map to test blocking behavior deterministically
	testIP := "198.51.100.5"
	sc.ownIPs[testIP] = struct{}{}

	parsedIP := net.ParseIP(testIP)
	gotReason := sc.isBlocked(parsedIP)
	if gotReason != "own_ip" {
		t.Errorf("expected %s to be blocked as own_ip, got reason %q", testIP, gotReason)
	}

	mappedIP := net.ParseIP("::ffff:" + testIP)
	if sc.isBlocked(mappedIP) != "own_ip" {
		t.Errorf("expected mapped IP %s to be blocked as own_ip, got %q", mappedIP, sc.isBlocked(mappedIP))
	}

	otherIP := net.ParseIP("198.51.100.6")
	if sc.isBlocked(otherIP) != "" {
		t.Errorf("expected %s not to be blocked", otherIP)
	}
}
