package relay_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

type mockLogStore struct {
	mu     sync.Mutex
	events []requestlog.Event
}

func (m *mockLogStore) InsertRequestLogs(ctx context.Context, logs []requestlog.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, logs...)
	return nil
}

func (m *mockLogStore) DeleteExpiredRequestLogs(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

func (m *mockLogStore) ClearAllRequestLogs(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
	return nil
}

func (m *mockLogStore) GetEvents() []requestlog.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]requestlog.Event, len(m.events))
	copy(res, m.events)
	return res
}

func append16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func makeClientHello(hostname string) []byte {
	var exts []byte
	if hostname != "" {
		name := []byte(hostname)
		snEntry := make([]byte, 0, 3+len(name))
		snEntry = append(snEntry, 0x00)
		snEntry = append16(snEntry, uint16(len(name)))
		snEntry = append(snEntry, name...)

		snList := append16(nil, uint16(len(snEntry)))
		snList = append(snList, snEntry...)

		ext := append16(nil, 0x0000)
		ext = append16(ext, uint16(len(snList)))
		ext = append(ext, snList...)
		exts = ext
	}

	extBlock := append16(nil, uint16(len(exts)))
	extBlock = append(extBlock, exts...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append16(body, 2)
	body = append16(body, 0x0035)
	body = append(body, 0x01, 0x00)
	body = append(body, extBlock...)

	hsLen := len(body)
	hs := []byte{
		0x01,
		byte(hsLen >> 16),
		byte(hsLen >> 8),
		byte(hsLen),
	}
	hs = append(hs, body...)

	rec := []byte{
		0x16,
		0x03, 0x01,
		byte(len(hs) >> 8),
		byte(len(hs)),
	}
	rec = append(rec, hs...)
	return rec
}

func TestServer_SNINormalizationAndValidation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var relayPort int
	fmt.Sscanf(portStr, "%d", &relayPort)

	cfg := &config.Config{
		AllowedDestPorts:    []int{relayPort, 443},
		UnknownDomainPolicy: "reject",
		AccessMode:          "public",
		Timeouts: config.TimeoutConfig{
			ClientHello:           config.Duration{Duration: 2 * time.Second},
			Idle:                  config.Duration{Duration: 2 * time.Second},
			MaxConnectionDuration: config.Duration{Duration: 0},
			TCPKeepalive:          config.Duration{Duration: 0},
		},
		Limits: config.LimitConfig{
			MaxGlobalConnections: 100,
			MaxConnectionsPerIP:  10,
		},
	}

	ruleStore := rules.NewRuleStore([]int{relayPort, 443}, "reject")
	_ = ruleStore.Swap(map[string]string{
		"blocked1.com":   `{"ports":[443],"mode":"block"}`,
		"blocked2.com":   `{"ports":[443],"mode":"block"}`,
		"*.wildcard.com": `{"ports":[443],"mode":"block"}`,
		"allowed.com":    `{"ports":[443],"mode":"proxy"}`,
	})

	accessStore := access.NewAccessStore(access.ModePublic)
	checker, err := relay.NewSecurityChecker(false, false, nil)
	if err != nil {
		t.Fatalf("security checker: %v", err)
	}
	limits := relay.NewLimitTracker(100, 10)
	connTracker := relay.NewConnTracker()

	srv := relay.NewServer(cfg, relayPort, relay.NewPortAllowList([]int{relayPort, 443}), checker, limits, ruleStore, accessStore, nil, connTracker)

	mockStore := &mockLogStore{}
	logger := requestlog.New(mockStore, time.Hour, true)
	loggerCtx, cancelLogger := context.WithCancel(context.Background())
	defer cancelLogger()
	logger.Start(loggerCtx)
	srv.SetLogger(logger)

	srvCtx, cancelSrv := context.WithCancel(context.Background())
	defer cancelSrv()

	go func() {
		_ = srv.Serve(srvCtx, ln, nil)
	}()

	tests := []struct {
		name           string
		rawSNI         string
		expectedStatus string
		expectedDomain string
	}{
		{
			name:           "Uppercase exact blocked domain normalized to lowercase",
			rawSNI:         "BLOCKED1.COM",
			expectedStatus: "rejected_domain_blocked",
			expectedDomain: "blocked1.com",
		},
		{
			name:           "Trailing dot on exact blocked domain trimmed",
			rawSNI:         "blocked2.com.",
			expectedStatus: "rejected_domain_blocked",
			expectedDomain: "blocked2.com",
		},
		{
			name:           "Uppercase and trailing dot on wildcard domain",
			rawSNI:         "SUB.wildcard.com.",
			expectedStatus: "rejected_domain_blocked",
			expectedDomain: "sub.wildcard.com",
		},
		{
			name:           "Bad SNI containing space",
			rawSNI:         "bad space.com",
			expectedStatus: "rejected_bad_sni",
			expectedDomain: "bad space.com",
		},
		{
			name:           "Bad SNI containing control character",
			rawSNI:         "bad\x01ctrl.com",
			expectedStatus: "rejected_bad_sni",
			expectedDomain: "bad\x01ctrl.com",
		},
		{
			name:           "Bad SNI containing slash",
			rawSNI:         "bad/slash.com",
			expectedStatus: "rejected_bad_sni",
			expectedDomain: "bad/slash.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.ClearAllRequestLogs(context.Background())

			conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()

			hello := makeClientHello(tt.rawSNI)
			if _, err := conn.Write(hello); err != nil {
				t.Fatalf("write ClientHello failed: %v", err)
			}

			// The connection should be closed by server immediately upon rejection
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 128)
			_, rerr := conn.Read(buf)
			if rerr == nil {
				t.Errorf("expected connection to be closed, but read succeeded")
			}

			// Wait up to 2s for logger event to be processed
			var foundEvent requestlog.Event
			var found bool
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				events := mockStore.GetEvents()
				for i := len(events) - 1; i >= 0; i-- {
					ev := events[i]
					if ev.Status == tt.expectedStatus && ev.Domain == tt.expectedDomain {
						foundEvent = ev
						found = true
						break
					}
				}
				if found {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}

			if !found {
				t.Fatalf("expected log event status %q domain %q, got events: %+v", tt.expectedStatus, tt.expectedDomain, mockStore.GetEvents())
			}
			if foundEvent.Domain != tt.expectedDomain {
				t.Errorf("expected logged domain %q, got %q", tt.expectedDomain, foundEvent.Domain)
			}
		})
	}
}
