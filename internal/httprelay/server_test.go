package httprelay_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/httprelay"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

type mockConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return m.Conn.RemoteAddr()
}

func setupTestConfig() *config.Config {
	return &config.Config{
		Listen: config.ListenConfig{
			Addr:      "127.0.0.1",
			Ports:     []int{443},
			HTTPPorts: []int{80},
		},
		AllowedDestPorts:    []int{80, 8080, 443},
		UnknownDomainPolicy: "allow_default_port",
		AccessMode:          "public",
		Timeouts: config.TimeoutConfig{
			ClientHello:           config.Duration{Duration: 5 * time.Second},
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

func TestHTTPRelay_Success(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen failed: %v", err)
	}
	defer backendLn.Close()

	_, backendPortStr, _ := net.SplitHostPort(backendLn.Addr().String())
	var backendPort int
	fmt.Sscanf(backendPortStr, "%d", &backendPort)

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
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello %s", req.Host)
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{backendPort, 80})
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	ruleStore := rules.NewRuleStore([]int{backendPort, 80}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)

	ruleJSON := fmt.Sprintf(`{"mode":"proxy","ports":[%d]}`, backendPort)
	if err := ruleStore.Swap(map[string]string{"127.0.0.1": ruleJSON}); err != nil {
		t.Fatalf("Swap rules failed: %v", err)
	}

	srv := httprelay.NewServer(cfg, backendPort, allowList, security, limits, ruleStore, accessStore, nil, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	peekedReq := []byte("GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Go-test\r\n\r\n")

	go srv.HandleConn(ctx, wrappedServerConn, peekedReq, "127.0.0.1")

	respBuf := make([]byte, 1024)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("reading response failed: %v", err)
	}

	respStr := string(respBuf[:n])
	if respStr == "" {
		t.Errorf("expected response from backend, got empty string")
	}
}

func TestHTTPRelay_BlockMode(t *testing.T) {
	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{80})
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	ruleStore := rules.NewRuleStore([]int{80}, "reject")
	accessStore := access.NewAccessStore(access.ModePublic)

	_ = ruleStore.Swap(map[string]string{
		"blocked.com": `{"mode":"block","ports":[80]}`,
	})

	srv := httprelay.NewServer(cfg, 80, allowList, security, limits, ruleStore, accessStore, nil, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	peekedReq := []byte("GET / HTTP/1.1\r\nHost: blocked.com\r\n\r\n")
	done := make(chan struct{})
	go func() {
		srv.HandleConn(ctx, wrappedServerConn, peekedReq, "blocked.com")
		close(done)
	}()

	select {
	case <-done:
		// Connection closed promptly
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return promptly for blocked domain")
	}
}

func TestHTTPRelay_DirectMode(t *testing.T) {
	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{80})
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	ruleStore := rules.NewRuleStore([]int{80}, "reject")
	accessStore := access.NewAccessStore(access.ModePublic)

	_ = ruleStore.Swap(map[string]string{
		"direct.com": `{"mode":"direct","ports":[80]}`,
	})

	srv := httprelay.NewServer(cfg, 80, allowList, security, limits, ruleStore, accessStore, nil, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	peekedReq := []byte("GET / HTTP/1.1\r\nHost: direct.com\r\n\r\n")
	done := make(chan struct{})
	go func() {
		srv.HandleConn(ctx, wrappedServerConn, peekedReq, "direct.com")
		close(done)
	}()

	select {
	case <-done:
		// Connection closed promptly
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return promptly for direct domain")
	}
}

func TestHTTPRelay_IPBlocked(t *testing.T) {
	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{80})
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	ruleStore := rules.NewRuleStore([]int{80}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)
	_ = accessStore.SwapBlacklist([]string{"10.0.0.5"})

	srv := httprelay.NewServer(cfg, 80, allowList, security, limits, ruleStore, accessStore, nil, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "10.0.0.5:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	peekedReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	done := make(chan struct{})
	go func() {
		srv.HandleConn(ctx, wrappedServerConn, peekedReq, "example.com")
		close(done)
	}()

	select {
	case <-done:
		// Connection rejected by IP access check
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return promptly for blocked IP")
	}
}

func TestHTTPRelay_LimitExceeded(t *testing.T) {
	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{80})
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(1, 1) // Max 1 conn per IP
	ruleStore := rules.NewRuleStore([]int{80}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)

	// Acquire 1 slot manually so limit is reached
	release, ok := limits.Acquire("127.0.0.1")
	if !ok {
		t.Fatal("failed to acquire initial slot")
	}
	defer release()

	srv := httprelay.NewServer(cfg, 80, allowList, security, limits, ruleStore, accessStore, nil, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	peekedReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	done := make(chan struct{})
	go func() {
		srv.HandleConn(ctx, wrappedServerConn, peekedReq, "example.com")
		close(done)
	}()

	select {
	case <-done:
		// Connection rejected by LimitTracker
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return promptly when connection limit exceeded")
	}
}

func TestHTTPRelay_SSRFBlocked(t *testing.T) {
	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{80})
	// Security checker set to block private IPs
	security, _ := relay.NewSecurityChecker(true, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	ruleStore := rules.NewRuleStore([]int{80}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)

	srv := httprelay.NewServer(cfg, 80, allowList, security, limits, ruleStore, accessStore, nil, nil)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 127.0.0.1 is loopback/private, SecurityChecker with BlockPrivateIPs=true will block it
	peekedReq := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	done := make(chan struct{})
	go func() {
		srv.HandleConn(ctx, wrappedServerConn, peekedReq, "127.0.0.1")
		close(done)
	}()

	select {
	case <-done:
		// Connection rejected by SecurityChecker
	case <-time.After(2 * time.Second):
		t.Fatal("HandleConn did not return promptly for SSRF-blocked target")
	}
}

func TestHTTPRelay_EgressSOCKS5Reuse(t *testing.T) {
	cfg := setupTestConfig()
	allowList := relay.NewPortAllowList([]int{80})
	security, _ := relay.NewSecurityChecker(false, false, nil)
	limits := relay.NewLimitTracker(100, 10)
	ruleStore := rules.NewRuleStore([]int{80}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModePublic)

	egressDialer, err := relay.NewEgressDialer(config.EgressProxyConfig{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("failed to create egress dialer: %v", err)
	}

	srv := httprelay.NewServer(cfg, 80, allowList, security, limits, ruleStore, accessStore, egressDialer, nil)

	dialCalled := false
	srv.SetCustomDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCalled = true
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			buf := make([]byte, 1024)
			_, _ = server.Read(buf)
			_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}()
		return client, nil
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	remoteAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	wrappedServerConn := &mockConn{Conn: serverConn, remoteAddr: remoteAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	peekedReq := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	go srv.HandleConn(ctx, wrappedServerConn, peekedReq, "127.0.0.1")

	buf := make([]byte, 1024)
	n, _ := clientConn.Read(buf)
	if !dialCalled {
		t.Errorf("expected custom dialer to be called")
	}
	if n == 0 {
		t.Errorf("expected non-empty response")
	}
}

func TestTryHTTPSRedirect_MethodAndTargetSanitizing(t *testing.T) {
	ruleStore := rules.NewRuleStore([]int{443}, "reject")
	if err := ruleStore.Swap(map[string]string{
		"example.com":   `{"mode":"proxy","ports":[443]}`,
		"noproxy.com":   `{"mode":"direct","ports":[443]}`,
		"noport443.com": `{"mode":"proxy","ports":[8080]}`,
	}); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	tests := []struct {
		name         string
		host         string
		peeked       string
		expectRedir  bool
		expectCode   string
		expectTarget string
	}{
		{
			name:         "GET method with valid path",
			host:         "example.com",
			peeked:       "GET /hello/world?foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectRedir:  true,
			expectCode:   "301",
			expectTarget: "/hello/world?foo=bar",
		},
		{
			name:         "HEAD method with valid path",
			host:         "example.com",
			peeked:       "HEAD /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectRedir:  true,
			expectCode:   "301",
			expectTarget: "/test",
		},
		{
			name:         "POST method with valid path",
			host:         "example.com",
			peeked:       "POST /api/submit HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectRedir:  true,
			expectCode:   "308",
			expectTarget: "/api/submit",
		},
		{
			name:         "PUT method with valid path",
			host:         "example.com",
			peeked:       "PUT /api/update HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectRedir:  true,
			expectCode:   "308",
			expectTarget: "/api/update",
		},
		{
			name:         "Target with CRLF falls back to slash",
			host:         "example.com",
			peeked:       "GET /bad\r\ntarget HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectRedir:  true,
			expectCode:   "301",
			expectTarget: "/",
		},
		{
			name:         "Target without leading slash falls back to slash",
			host:         "example.com",
			peeked:       "GET http://example.com/foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectRedir:  true,
			expectCode:   "301",
			expectTarget: "/",
		},
		{
			name:        "Domain without port 443 -> No redirect",
			host:        "noport443.com",
			peeked:      "GET /test HTTP/1.1\r\nHost: noport443.com\r\n\r\n",
			expectRedir: false,
		},
		{
			name:        "Direct mode domain -> No redirect",
			host:        "noproxy.com",
			peeked:      "GET /test HTTP/1.1\r\nHost: noproxy.com\r\n\r\n",
			expectRedir: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()

			done := make(chan struct{})
			var redirected bool
			go func() {
				redirected = httprelay.TryHTTPSRedirect(server, []byte(tc.peeked), tc.host, ruleStore)
				close(done)
			}()

			if !tc.expectRedir {
				<-done
				if redirected {
					t.Errorf("expected no redirect for %s", tc.name)
				}
				return
			}

			buf := make([]byte, 1024)
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			n, err := client.Read(buf)
			if err != nil {
				t.Fatalf("read failed: %v", err)
			}
			<-done
			if !redirected {
				t.Fatalf("expected redirect to be true")
			}

			respStr := string(buf[:n])
			if !strings.Contains(respStr, "HTTP/1.1 "+tc.expectCode) {
				t.Errorf("expected status %s, got response:\n%s", tc.expectCode, respStr)
			}
			expectedLocation := fmt.Sprintf("Location: https://%s%s", tc.host, tc.expectTarget)
			if !strings.Contains(respStr, expectedLocation) {
				t.Errorf("expected %q, got response:\n%s", expectedLocation, respStr)
			}
		})
	}
}
