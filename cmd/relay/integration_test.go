package main_test

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
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/portal"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

func TestEndToEnd_FrontRouterPanelAndRelay(t *testing.T) {
	// 1. Start mock destination backend HTTP server
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
				body := "mock-backend-response-for:" + req.Host
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	// 2. Start merged Front Router on 127.0.0.1:0
	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("router listen failed: %v", err)
	}
	defer routerLn.Close()

	_, portStr, _ := net.SplitHostPort(routerLn.Addr().String())
	var routerPort int
	fmt.Sscanf(portStr, "%d", &routerPort)

	cfg := &config.Config{
		Listen: config.ListenConfig{
			Addr:      "127.0.0.1",
			Ports:     []int{443},
			HTTPPorts: []int{routerPort},
		},
		Panel: config.PanelConfig{
			Addr: fmt.Sprintf("127.0.0.1:%d", routerPort),
			Path: "/",
		},
		AllowedDestPorts:    []int{routerPort, 80},
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

	ruleStore := rules.NewRuleStore([]int{routerPort}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)
	checker, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	connTracker := relay.NewConnTracker()

	// Build Panel & Portal Server
	panelSrv, err := panel.New(cfg.Panel.Addr, cfg.Panel.Path, ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("panel.New failed: %v", err)
	}

	portalSrv := portal.New(cfg.Panel.Addr, nil, accessStore, nil)
	panelSrv.SetPortalServer(portalSrv)

	// Configure Domain Rule for 127.0.0.1 -> mode: proxy
	rulesMap := map[string]string{
		"127.0.0.1": fmt.Sprintf(`{"mode":"proxy","ports":[%d]}`, routerPort),
	}
	if err := ruleStore.Swap(rulesMap); err != nil {
		t.Fatalf("ruleStore.Swap failed: %v", err)
	}

	router, err := frontrouter.New(cfg, panelSrv, ruleStore, accessStore, checker, limits, nil, connTracker, nil, nil, nil)
	if err != nil {
		t.Fatalf("frontrouter.New failed: %v", err)
	}

	// Override router dialer to connect to backendLn
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

	// -----------------------------------------------------------------------
	// Part A: Send request for panel path (GET /api/login) on unmatched host
	// -----------------------------------------------------------------------
	t.Run("Panel Fallback", func(t *testing.T) {
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial router failed: %v", err)
		}
		defer conn.Close()

		// Request for unmatched host panel.local
		_, _ = conn.Write([]byte("POST /api/login HTTP/1.1\r\nHost: panel.local\r\nContent-Length: 0\r\n\r\n"))

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response from panel failed: %v", err)
		}

		// Panel returns 400 Bad Request for empty login payload
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected panel HTTP 400 status, got %d", resp.StatusCode)
		}
	})

	// -----------------------------------------------------------------------
	// Part B: Send request for proxy-mode domain rule (Host: 127.0.0.1)
	// -----------------------------------------------------------------------
	t.Run("HTTP Relay Path", func(t *testing.T) {
		conn, err := net.Dial("tcp", routerLn.Addr().String())
		if err != nil {
			t.Fatalf("dial router failed: %v", err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))

		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response from HTTP relay failed: %v", err)
		}

		body, _ := io.ReadAll(resp.Body)
		expectedBody := "mock-backend-response-for:127.0.0.1"
		if string(body) != expectedBody {
			t.Errorf("expected relay body %q, got %q", expectedBody, string(body))
		}
	})
}
