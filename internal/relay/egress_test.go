package relay_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/relay"
)

// mockSocks5Server implements a minimal in-memory SOCKS5 server for unit testing.
type mockSocks5Server struct {
	listener     net.Listener
	mu           sync.Mutex
	destinations []string
	user         string
	password     string
}

func newMockSocks5Server(user, password string) (*mockSocks5Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &mockSocks5Server{
		listener: ln,
		user:     user,
		password: password,
	}
	go s.serve()
	return s, nil
}

func (s *mockSocks5Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *mockSocks5Server) Close() {
	_ = s.listener.Close()
}

func (s *mockSocks5Server) Destinations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := make([]string, len(s.destinations))
	copy(res, s.destinations)
	return res
}

func (s *mockSocks5Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *mockSocks5Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 256)
	// Read SOCKS5 greeting: VER NMETHODS METHODS
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	expectedAuth := s.user != "" && s.password != ""
	if expectedAuth {
		// Server selects auth method 0x02 (Username/Password)
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// Subnegotiation: VER ULEN UNAME PLEN PASSWD
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return
		}
		ulen := int(buf[1])
		uname := make([]byte, ulen)
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		plen := int(buf[0])
		passwd := make([]byte, plen)
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}

		if string(uname) != s.user || string(passwd) != s.password {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		// Server selects auth method 0x00 (No Authentication)
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	// Read SOCKS5 request header: VER CMD RSV ATYP
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // VER=5, CMD=1 (CONNECT)
		return
	}

	atyp := buf[3]
	var destHost string
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		destHost = net.IP(ipBuf).String()
	case 0x03: // Domain name
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		domainBuf := make([]byte, dlen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		destHost = string(domainBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		destHost = net.IP(ipBuf).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := (int(portBuf[0]) << 8) | int(portBuf[1])

	target := fmt.Sprintf("%s:%d", destHost, port)
	s.mu.Lock()
	s.destinations = append(s.destinations, target)
	s.mu.Unlock()

	// Send success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return
	}

	// Echo data
	io.Copy(conn, conn)
}

func TestEgressDialer_Disabled(t *testing.T) {
	cfg := config.EgressProxyConfig{
		Enabled: false,
	}
	ed, err := relay.NewEgressDialer(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating egress dialer: %v", err)
	}

	if ed.Enabled() {
		t.Error("expected egress dialer to be disabled")
	}
	if ed.Mode() != "direct" {
		t.Errorf("expected mode 'direct', got %q", ed.Mode())
	}
}

func TestEgressDialer_EnabledWithSocks5Mock(t *testing.T) {
	mockServer, err := newMockSocks5Server("testuser", "testpass")
	if err != nil {
		t.Fatalf("failed to start mock SOCKS5 server: %v", err)
	}
	defer mockServer.Close()

	cfg := config.EgressProxyConfig{
		Enabled:  true,
		Addr:     mockServer.Addr(),
		User:     "testuser",
		Password: "testpass",
	}

	ed, err := relay.NewEgressDialer(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating egress dialer: %v", err)
	}

	if !ed.Enabled() {
		t.Error("expected egress dialer to be enabled")
	}
	if ed.Mode() != "proxy" {
		t.Errorf("expected mode 'proxy', got %q", ed.Mode())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targetIP := "93.184.216.34:443"
	conn, err := ed.DialContext(ctx, "tcp", targetIP)
	if err != nil {
		t.Fatalf("DialContext failed through SOCKS5 proxy: %v", err)
	}
	_ = conn.Close()

	dests := mockServer.Destinations()
	if len(dests) != 1 {
		t.Fatalf("expected 1 destination received by mock server, got %d", len(dests))
	}
	if dests[0] != targetIP {
		t.Errorf("expected destination %q, got %q", targetIP, dests[0])
	}
}

func TestEgressDialer_NoAuth(t *testing.T) {
	mockServer, err := newMockSocks5Server("", "")
	if err != nil {
		t.Fatalf("failed to start mock SOCKS5 server: %v", err)
	}
	defer mockServer.Close()

	cfg := config.EgressProxyConfig{
		Enabled: true,
		Addr:    mockServer.Addr(),
	}

	ed, err := relay.NewEgressDialer(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating egress dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targetIP := "198.51.100.1:8443"
	conn, err := ed.DialContext(ctx, "tcp", targetIP)
	if err != nil {
		t.Fatalf("DialContext failed through SOCKS5 proxy without auth: %v", err)
	}
	_ = conn.Close()

	dests := mockServer.Destinations()
	if len(dests) != 1 || dests[0] != targetIP {
		t.Errorf("expected destination %q, got %v", targetIP, dests)
	}
}

func TestEgressDialer_RequiresAddrWhenEnabled(t *testing.T) {
	cfg := config.EgressProxyConfig{
		Enabled: true,
		Addr:    "",
	}
	_, err := relay.NewEgressDialer(cfg)
	if err == nil {
		t.Error("expected error when EGRESS_PROXY_ADDR is empty and proxying is enabled")
	}
}

func TestEgressDialer_ProxyFailureDoesNotFallback(t *testing.T) {
	cfg := config.EgressProxyConfig{
		Enabled: true,
		Addr:    "127.0.0.1:59999", // Unreachable port
	}
	ed, err := relay.NewEgressDialer(cfg)
	if err != nil {
		t.Fatalf("failed to create egress dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = ed.DialContext(ctx, "tcp", "93.184.216.34:443")
	if err == nil {
		t.Error("expected dial error when SOCKS5 proxy is unreachable, got nil")
	}
}

func TestEgressDialer_DecisionTableOverrides(t *testing.T) {
	mockServer, err := newMockSocks5Server("", "")
	if err != nil {
		t.Fatalf("failed to start mock SOCKS5 server: %v", err)
	}
	defer mockServer.Close()

	cases := []struct {
		globalEnabled  bool
		ruleOverride   string
		expectedMode   string
		shouldUseSocks bool
	}{
		// Global disabled: always direct, even if rule says "true".
		{false, "false", "direct", false},
		{false, "default", "direct", false},
		{false, "true", "direct", false}, // global switch wins
		// Global enabled: per-rule override applies; default/empty -> proxy.
		{true, "false", "direct", false},
		{true, "default", "proxy", true},
		{true, "true", "proxy", true},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("Global_%v_Rule_%s", tc.globalEnabled, tc.ruleOverride), func(t *testing.T) {
			cfg := config.EgressProxyConfig{
				Enabled: tc.globalEnabled,
				Addr:    mockServer.Addr(),
			}
			ed, err := relay.NewEgressDialer(cfg)
			if err != nil {
				t.Fatalf("unexpected error creating egress dialer: %v", err)
			}

			mode := ed.ResolveMode(tc.ruleOverride)
			if mode != tc.expectedMode {
				t.Errorf("expected mode %q, got %q", tc.expectedMode, mode)
			}

			// Perform a dial
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// Start a local echo listener to target if it dials directly
			var directListener net.Listener
			targetAddr := "127.0.0.1:0"
			var directErr error
			if !tc.shouldUseSocks {
				directListener, directErr = net.Listen("tcp", "127.0.0.1:0")
				if directErr != nil {
					t.Fatalf("failed to start local direct listener: %v", directErr)
				}
				defer directListener.Close()
				targetAddr = directListener.Addr().String()

				go func() {
					c, acceptErr := directListener.Accept()
					if acceptErr == nil {
						c.Close()
					}
				}()
			} else {
				// Use dummy target address for SOCKS5 mock server
				targetAddr = "93.184.216.34:443"
			}

			conn, dialErr := ed.DialContextWithOverride(ctx, "tcp", targetAddr, tc.ruleOverride)
			if dialErr != nil {
				t.Fatalf("dial failed: %v", dialErr)
			}
			conn.Close()
		})
	}
}
