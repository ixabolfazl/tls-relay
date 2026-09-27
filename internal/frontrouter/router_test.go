package frontrouter_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/frontrouter"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

func setupTestConfig(panelPort int) *config.Config {
	return &config.Config{
		Listen: config.ListenConfig{
			Addr:      "127.0.0.1",
			Ports:     []int{443},
			HTTPPorts: []int{panelPort},
		},
		Panel: config.PanelConfig{
			Addr: fmt.Sprintf("127.0.0.1:%d", panelPort),
			Path: "/admin",
		},
		AllowedDestPorts:    []int{panelPort, 80, 8080},
		UnknownDomainPolicy: "allow_default_port",
		AccessMode:          "public",
		Timeouts: config.TimeoutConfig{
			ClientHello:           config.Duration{Duration: 2 * time.Second},
			HTTPHeader:            config.Duration{Duration: 2 * time.Second},
			Idle:                  config.Duration{Duration: 5 * time.Second},
			MaxConnectionDuration: config.Duration{Duration: 0},
			TCPKeepalive:          config.Duration{Duration: 0},
		},
		Limits: config.LimitConfig{
			MaxGlobalConnections: 100,
			MaxConnectionsPerIP:  10,
		},
	}
}

func TestFrontRouter_RoutingMatrix(t *testing.T) {
	// 1. Mock Panel Handler
	panelCalled := false
	panelHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panelCalled = true
		if r.URL.Path == "/api/login" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("panel-ok"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// 2. Mock Destination Relay Backend on 127.0.0.1:0 (ephemeral port)
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen failed: %v", err)
	}
	defer backendLn.Close()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				req, err := http.ReadRequest(r)
				if err != nil {
					return
				}
				body := "relay:" + req.Host
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	// 3. Start FrontRouter on real listener
	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("router listen failed: %v", err)
	}
	defer routerLn.Close()

	_, routerPortStr, _ := net.SplitHostPort(routerLn.Addr().String())
	var routerPort int
	fmt.Sscanf(routerPortStr, "%d", &routerPort)

	cfg := setupTestConfig(routerPort)
	ruleStore := rules.NewRuleStore([]int{routerPort}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)

	rulesMap := map[string]string{
		"127.0.0.1":     fmt.Sprintf(`{"mode":"proxy","ports":[%d]}`, routerPort),
		"blocked.local": `{"mode":"block","ports":[80]}`,
		"direct.local":  `{"mode":"direct","ports":[80]}`,
		"badport.local": `{"mode":"proxy","ports":[9999]}`,
	}
	if err := ruleStore.Swap(rulesMap); err != nil {
		t.Fatalf("ruleStore.Swap failed: %v", err)
	}

	router, err := frontrouter.New(cfg, panelHandler, ruleStore, accessStore, security, limits, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("frontrouter.New failed: %v", err)
	}

	// Override outbound dialer to route relay traffic to backendLn
	router.SetCustomDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, backendLn.Addr().String())
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = router.ServeListener(ctx, routerLn, nil)
	}()

	time.Sleep(50 * time.Millisecond)

	// Case 1: Unmatched Host -> Panel Handler receives request
	t.Run("Unmatched Host -> Panel", func(t *testing.T) {
		panelCalled = false
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		reqStr := "GET /api/login HTTP/1.1\r\nHost: panel.local\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("reading response failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "panel-ok" {
			t.Errorf("expected 'panel-ok', got %q", string(body))
		}
		if !panelCalled {
			t.Errorf("expected panel to be invoked for unmatched domain")
		}
	})

	// Case 2: Matched Host + proxy mode -> Relayed to backend
	t.Run("Matched Proxy Host -> HTTP Relay", func(t *testing.T) {
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		reqStr := "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("reading response failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "relay:127.0.0.1" {
			t.Errorf("expected 'relay:127.0.0.1', got %q", string(body))
		}
	})

	// Case 3: Matched Host + block mode -> Rejected (panel NOT invoked)
	t.Run("Matched Block Host -> Rejected", func(t *testing.T) {
		panelCalled = false
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		reqStr := "GET / HTTP/1.1\r\nHost: blocked.local\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		if n > 0 {
			t.Errorf("expected closed connection, got %q", string(buf[:n]))
		}
		if panelCalled {
			t.Errorf("panel should NOT be invoked for blocked domain")
		}
	})

	// Case 4: Matched Host + direct mode -> Rejected (panel NOT invoked)
	t.Run("Matched Direct Host -> Rejected", func(t *testing.T) {
		panelCalled = false
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		reqStr := "GET / HTTP/1.1\r\nHost: direct.local\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		if n > 0 {
			t.Errorf("expected closed connection, got %q", string(buf[:n]))
		}
		if panelCalled {
			t.Errorf("panel should NOT be invoked for direct domain")
		}
	})

	// Case 5: Non-HTTP input -> Rejected
	t.Run("Non-HTTP Garbage -> Rejected", func(t *testing.T) {
		panelCalled = false
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("\x16\x03\x01\x00\x05garbage"))

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		if n > 0 {
			t.Errorf("expected closed connection, got %q", string(buf[:n]))
		}
		if panelCalled {
			t.Errorf("panel should NOT be invoked for non-HTTP input")
		}
	})

	// Case 6: Matched Proxy Host + disallowed port -> Rejected
	t.Run("Matched Proxy Host + Disallowed Port -> Rejected", func(t *testing.T) {
		panelCalled = false
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		reqStr := "GET / HTTP/1.1\r\nHost: badport.local\r\n\r\n"
		_, _ = conn.Write([]byte(reqStr))

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 100)
		n, _ := conn.Read(buf)
		if n > 0 {
			t.Errorf("expected closed connection, got %q", string(buf[:n]))
		}
		if panelCalled {
			t.Errorf("panel should NOT be invoked for matched domain with disallowed port")
		}
	})

	// Case 7: IP Access Registration & Blacklist Controls
	t.Run("IP Access Registration & Blacklist Control Flow", func(t *testing.T) {
		// Change access mode to User (whitelist only)
		accessStore.SetMode(access.ModeUser)
		defer accessStore.SetMode(access.ModePublic) // Restore after test

		// Subcase 7a: Unregistered IP accessing unmatched host (Panel/Landing page) -> ALLOWED
		t.Run("Unregistered IP -> Panel Allowed", func(t *testing.T) {
			panelCalled = false
			conn, err := net.Dial("tcp", routerLn.Addr().String())
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()

			reqStr := "GET /api/login HTTP/1.1\r\nHost: panel.local\r\n\r\n"
			_, _ = conn.Write([]byte(reqStr))

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("reading response failed: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "panel-ok" {
				t.Errorf("expected 'panel-ok', got %q", string(body))
			}
			if !panelCalled {
				t.Errorf("expected panel to be invoked for unregistered IP on panel URL")
			}
		})

		// Subcase 7b: Unregistered IP accessing matched proxy host (Relay Traffic) -> REJECTED
		t.Run("Unregistered IP -> Relay Rejected", func(t *testing.T) {
			conn, err := net.Dial("tcp", routerLn.Addr().String())
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()

			reqStr := "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
			_, _ = conn.Write([]byte(reqStr))

			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 100)
			n, _ := conn.Read(buf)
			if n > 0 {
				t.Errorf("expected closed connection, got %q", string(buf[:n]))
			}
		})

		// Subcase 7c: Blacklisted IP accessing unmatched host -> REJECTED IMMEDIATELY
		t.Run("Blacklisted IP -> Rejected Immediately", func(t *testing.T) {
			_ = accessStore.SwapBlacklist([]string{"127.0.0.1"})
			defer func() { _ = accessStore.SwapBlacklist([]string{}) }()

			panelCalled = false
			conn, err := net.Dial("tcp", routerLn.Addr().String())
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()

			reqStr := "GET /api/login HTTP/1.1\r\nHost: panel.local\r\n\r\n"
			_, _ = conn.Write([]byte(reqStr))

			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 100)
			n, _ := conn.Read(buf)
			if n > 0 {
				t.Errorf("expected closed connection, got %q", string(buf[:n]))
			}
			if panelCalled {
				t.Errorf("panel should NOT be invoked for blacklisted IP")
			}
		})
	})
}
