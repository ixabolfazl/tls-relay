package relay

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"

	"github.com/ixabolfazl/tls-relay/internal/config"
)

// EgressDialer manages outbound dialing, either directly or through a SOCKS5 proxy.
type EgressDialer struct {
	enabled    bool
	socksProxy proxy.Dialer
}

// NewEgressDialer initializes an EgressDialer based on the provided configuration.
func NewEgressDialer(cfg config.EgressProxyConfig) (*EgressDialer, error) {
	if cfg.Enabled && cfg.Addr == "" {
		return nil, fmt.Errorf("egress proxy is enabled but address is empty")
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
			return nil, fmt.Errorf("building SOCKS5 dialer for %s: %w", cfg.Addr, err)
		}
	}

	return &EgressDialer{
		enabled:    cfg.Enabled,
		socksProxy: socksDialer,
	}, nil
}

// DialContext connects to the target address, routing through the SOCKS5 proxy if enabled,
// or dialing directly if disabled.
func (e *EgressDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return e.DialContextWithOverride(ctx, network, addr, "default")
}

// DialContextWithOverride connects to the target address using SOCKS5 or direct dial, based on the rule's override.
func (e *EgressDialer) DialContextWithOverride(ctx context.Context, network, addr string, ruleUseProxy string) (net.Conn, error) {
	useProxy := e.enabled
	if ruleUseProxy == "true" {
		useProxy = true
	} else if ruleUseProxy == "false" {
		useProxy = false
	}

	if useProxy {
		if e == nil || e.socksProxy == nil {
			return nil, fmt.Errorf("SOCKS5 proxy dialer is not configured (EGRESS_PROXY_ADDR is empty)")
		}
		if cd, ok := e.socksProxy.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return e.socksProxy.Dial(network, addr)
	}

	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// ResolveMode returns "proxy" or "direct" based on global status and the rule's override.
func (e *EgressDialer) ResolveMode(ruleUseProxy string) string {
	useProxy := e.enabled
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
	if e != nil && e.enabled {
		return "proxy"
	}
	return "direct"
}

// Enabled returns true if egress proxying is enabled.
func (e *EgressDialer) Enabled() bool {
	return e != nil && e.enabled
}
