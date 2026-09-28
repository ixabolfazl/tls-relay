package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/ixabolfazl/tls-relay/internal/config"
)

// EgressDialer manages outbound dialing, either directly or through a SOCKS5 proxy.
type EgressDialer struct {
	mu         sync.RWMutex
	enabled    bool
	addr       string
	user       string
	password   string
	socksProxy proxy.Dialer
}

// NewEgressDialer initializes an EgressDialer based on the provided configuration.
func NewEgressDialer(cfg config.EgressProxyConfig) (*EgressDialer, error) {
	ed := &EgressDialer{}
	if err := ed.UpdateConfig(cfg); err != nil {
		return nil, err
	}
	return ed, nil
}

// UpdateConfig updates the egress dialer configuration dynamically at runtime.
func (e *EgressDialer) UpdateConfig(cfg config.EgressProxyConfig) error {
	if cfg.Enabled && cfg.Addr == "" {
		return fmt.Errorf("egress proxy is enabled but address is empty")
	}

	var socksDialer proxy.Dialer
	var err error
	if cfg.Addr != "" {
		var auth *proxy.Auth
		if cfg.User != "" && cfg.Password != "" {
			auth = &proxy.Auth{
				User:     cfg.User,
				Password: cfg.Password,
			}
		}
		socksDialer, err = proxy.SOCKS5("tcp", cfg.Addr, auth, proxy.Direct)
		if err != nil {
			return fmt.Errorf("building SOCKS5 dialer for %s: %w", cfg.Addr, err)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = cfg.Enabled
	e.addr = cfg.Addr
	e.user = cfg.User
	e.password = cfg.Password
	e.socksProxy = socksDialer
	return nil
}

// Config returns a copy of the current configuration.
func (e *EgressDialer) Config() config.EgressProxyConfig {
	if e == nil {
		return config.EgressProxyConfig{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return config.EgressProxyConfig{
		Enabled:  e.enabled,
		Addr:     e.addr,
		User:     e.user,
		Password: e.password,
	}
}

// SetEnabled toggles egress proxying on or off.
func (e *EgressDialer) SetEnabled(enabled bool) error {
	if e == nil {
		return fmt.Errorf("egress dialer is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if enabled && e.addr == "" {
		return fmt.Errorf("cannot enable egress proxy without configuring proxy address")
	}
	e.enabled = enabled
	return nil
}

// TestConnection dials the proxy to verify connectivity and returns the measured latency.
func (e *EgressDialer) TestConnection(ctx context.Context, testTarget string) (time.Duration, error) {
	if e == nil {
		return 0, fmt.Errorf("egress dialer is nil")
	}
	e.mu.RLock()
	dialer := e.socksProxy
	addr := e.addr
	e.mu.RUnlock()

	if dialer == nil {
		return 0, fmt.Errorf("SOCKS5 proxy dialer is not configured (address is empty)")
	}

	if testTarget == "" {
		testTarget = "1.1.1.1:53"
	}

	start := time.Now()
	var conn net.Conn
	var err error

	if cd, ok := dialer.(proxy.ContextDialer); ok {
		conn, err = cd.DialContext(ctx, "tcp", testTarget)
	} else {
		conn, err = dialer.Dial("tcp", testTarget)
	}

	if err != nil {
		return 0, fmt.Errorf("proxy connection to %s failed: %w", addr, err)
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// DialContext connects to the target address, routing through the SOCKS5 proxy if enabled,
// or dialing directly if disabled.
func (e *EgressDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return e.DialContextWithOverride(ctx, network, addr, "default")
}

// DialContextWithOverride connects to the target address using SOCKS5 or direct dial, based on the rule's override.
func (e *EgressDialer) DialContextWithOverride(ctx context.Context, network, addr string, ruleUseProxy string) (net.Conn, error) {
	if e == nil {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	e.mu.RLock()
	useProxy := e.enabled
	dialer := e.socksProxy
	e.mu.RUnlock()

	if ruleUseProxy == "true" {
		useProxy = true
	} else if ruleUseProxy == "false" {
		useProxy = false
	}

	if useProxy {
		if dialer == nil {
			return nil, fmt.Errorf("SOCKS5 proxy dialer is not configured (EGRESS_PROXY_ADDR is empty)")
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return dialer.Dial(network, addr)
	}

	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// ResolveMode returns "proxy" or "direct" based on global status and the rule's override.
func (e *EgressDialer) ResolveMode(ruleUseProxy string) string {
	if e == nil {
		return "direct"
	}
	e.mu.RLock()
	useProxy := e.enabled
	e.mu.RUnlock()

	if ruleUseProxy == "true" {
		useProxy = true
	} else if ruleUseProxy == "false" {
		useProxy = false
	}
	if useProxy {
		return "proxy"
	}
	return "direct"
}

// Mode returns "proxy" if egress proxying is enabled, or "direct" if disabled.
func (e *EgressDialer) Mode() string {
	if e != nil && e.Enabled() {
		return "proxy"
	}
	return "direct"
}

// Enabled returns true if egress proxying is enabled.
func (e *EgressDialer) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}
