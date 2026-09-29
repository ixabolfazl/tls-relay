// Package relay/security provides SSRF protection and port allow-list checks.
package relay

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// PortAllowList is a thread-safe set of destination ports that the relay is
// permitted to forward to.
type PortAllowList struct {
	mu    sync.RWMutex
	ports map[int]struct{}
	list  []int
}

// NewPortAllowList constructs an allow-list from a slice of port numbers.
func NewPortAllowList(ports []int) *PortAllowList {
	pal := &PortAllowList{}
	pal.SetPorts(ports)
	return pal
}

// Allowed returns true if the port is in the allow-list.
func (pal *PortAllowList) Allowed(port int) bool {
	if pal == nil {
		return false
	}
	pal.mu.RLock()
	defer pal.mu.RUnlock()
	_, ok := pal.ports[port]
	return ok
}

// SetPorts updates the allowed ports dynamically at runtime.
func (pal *PortAllowList) SetPorts(ports []int) {
	if pal == nil {
		return
	}
	m := make(map[int]struct{}, len(ports))
	list := make([]int, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			if _, exists := m[p]; !exists {
				m[p] = struct{}{}
				list = append(list, p)
			}
		}
	}
	pal.mu.Lock()
	pal.ports = m
	pal.list = list
	pal.mu.Unlock()
}

// Ports returns a copy of the currently allowed destination ports.
func (pal *PortAllowList) Ports() []int {
	if pal == nil {
		return nil
	}
	pal.mu.RLock()
	defer pal.mu.RUnlock()
	out := make([]int, len(pal.list))
	copy(out, pal.list)
	return out
}

// -----------------------------------------------------------------------
// SSRF / internal-network guard
// -----------------------------------------------------------------------

// SecurityChecker holds the configuration for IP-level validation.
type SecurityChecker struct {
	mu           sync.RWMutex
	blockPrivate bool
	blockOwn     bool
	extraCIDRs   []*net.IPNet
	ownIPs       map[string]struct{}

	// CGNAT: 100.64.0.0/10
	cgnat *net.IPNet
}

var blockedPrivateCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",
		"192.0.0.0/24",
		"198.18.0.0/15",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	var res []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		res = append(res, n)
	}
	return res
}()

// NewSecurityChecker builds a SecurityChecker.
//
// blockPrivate: reject RFC-1918 / loopback / link-local / etc.
// blockOwn:     reject connections to the machine's own IPs.
// extraCIDRs:   additional CIDR strings to reject.
func NewSecurityChecker(blockPrivate, blockOwn bool, extraCIDRs []string) (*SecurityChecker, error) {
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")

	sc := &SecurityChecker{
		blockPrivate: blockPrivate,
		blockOwn:     blockOwn,
		cgnat:        cgnat,
		ownIPs:       make(map[string]struct{}),
	}

	for _, cidr := range extraCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid extra_blocked_cidr %q: %w", cidr, err)
		}
		sc.extraCIDRs = append(sc.extraCIDRs, ipNet)
	}

	if blockOwn {
		if err := sc.loadOwnIPs(); err != nil {
			// Non-fatal: log and continue.
			slog.Warn("failed to enumerate own IPs; own-IP blocking may be incomplete", "error", err)
		}
	}

	return sc, nil
}

// AddOwnIPs adds explicit IP addresses to the ownIPs blocklist.
func (sc *SecurityChecker) AddOwnIPs(ips ...string) {
	if sc == nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, s := range ips {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			sc.ownIPs[ip.String()] = struct{}{}
		}
	}
}

// loadOwnIPs enumerates all local interface addresses and stores them.
func (sc *SecurityChecker) loadOwnIPs() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					ip = v4
				}
				sc.ownIPs[ip.String()] = struct{}{}
			}
		}
	}
	return nil
}

// isBlocked returns a non-empty reason string if the IP should be rejected.
func (sc *SecurityChecker) isBlocked(ip net.IP) string {
	// Canonicalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to 4-byte form
	// so string comparison, loopback/private checks, and CIDRs match consistently.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if sc.blockPrivate {
		if ip.IsLoopback() {
			return "loopback"
		}
		if ip.IsPrivate() {
			return "private"
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return "link_local"
		}
		if ip.IsUnspecified() {
			return "unspecified"
		}
		if ip.IsMulticast() {
			return "multicast"
		}
		if sc.cgnat != nil && sc.cgnat.Contains(ip) {
			return "cgnat"
		}
		for _, cidr := range blockedPrivateCIDRs {
			if cidr.Contains(ip) {
				return "private"
			}
		}

		// Check 6to4 and NAT64 embedded IPv4 addresses.
		if ip.To4() == nil && len(ip) == net.IPv6len {
			// 6to4: 2002::/16 - bytes 2..5 contain embedded IPv4.
			if ip[0] == 0x20 && ip[1] == 0x02 {
				embedded := net.IPv4(ip[2], ip[3], ip[4], ip[5])
				if r := sc.isBlocked(embedded); r != "" {
					return "6to4_blocked"
				}
			}

			// NAT64 Well-Known Prefix: 64:ff9b::/96 - bytes 12..15 contain embedded IPv4.
			if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
				ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
				ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
				embedded := net.IPv4(ip[12], ip[13], ip[14], ip[15])
				if r := sc.isBlocked(embedded); r != "" {
					return "nat64_blocked"
				}
			}
		}
	}

	for _, cidr := range sc.extraCIDRs {
		if cidr.Contains(ip) {
			return fmt.Sprintf("extra_blocked_cidr(%s)", cidr.String())
		}
	}

	if sc.blockOwn {
		sc.mu.RLock()
		_, owned := sc.ownIPs[ip.String()]
		sc.mu.RUnlock()
		if owned {
			return "own_ip"
		}
	}
	return ""
}

// ResolveAndValidate resolves hostname to IP addresses, validates each one,
// and returns the first safe IP to dial (as a string) plus an error if all are
// blocked or DNS fails.
//
// To defend against DNS rebinding: we resolve once, validate all returned IPs,
// and return the specific validated IP so the caller dials by IP (not hostname).
func (sc *SecurityChecker) ResolveAndValidate(hostname string) (ip net.IP, reason string, err error) {
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, "", fmt.Errorf("DNS lookup for %q failed: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return nil, "", fmt.Errorf("DNS lookup for %q returned no addresses", hostname)
	}

	// Validate every resolved IP; collect first safe IP.
	var firstSafe net.IP
	for _, addr := range addrs {
		parsedIP := net.ParseIP(addr)
		if parsedIP == nil {
			continue
		}
		// Normalise to 16-byte form for consistent comparison.
		if v4 := parsedIP.To4(); v4 != nil {
			parsedIP = v4
		}
		if r := sc.isBlocked(parsedIP); r != "" {
			// At least one resolved IP is blocked — reject the whole connection.
			// This is intentionally strict: if ANY resolved IP is dangerous we
			// refuse to connect to avoid attacks via split-horizon DNS.
			return nil, r, nil
		}
		if firstSafe == nil {
			firstSafe = parsedIP
		}
	}

	if firstSafe == nil {
		return nil, "no_valid_ip", nil
	}

	// Final check on the specific IP we will actually dial (belt-and-suspenders
	// defence against TOCTOU if the net package re-resolves internally — it
	// does not when we dial by IP, but we validate again just in case).
	if r := sc.isBlocked(firstSafe); r != "" {
		return nil, r, nil
	}

	return firstSafe, "", nil
}

// AddrForIP formats the dial address string from an IP and port, correctly
// handling IPv6 addresses.
func AddrForIP(ip net.IP, port int) string {
	a, _ := netip.AddrFromSlice(ip)
	a = a.Unmap()
	if a.Is6() {
		return fmt.Sprintf("[%s]:%d", a, port)
	}
	return fmt.Sprintf("%s:%d", a, port)
}
