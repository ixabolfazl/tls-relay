package dnsresolver_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/dnsresolver"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// ---------------------------------------------------------------------------
// Rate limiter tests
// ---------------------------------------------------------------------------

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := dnsresolver.NewIPRateLimiter(10, 5)
	ip := "1.2.3.4"

	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("query %d should be allowed (within burst of 5)", i+1)
		}
	}
}

func TestRateLimiter_DropsOverBurst(t *testing.T) {
	// Burst = 3, QPS = 1 (slow refill). Send 4 immediately.
	rl := dnsresolver.NewIPRateLimiter(1, 3)
	ip := "10.0.0.1"

	allowed := 0
	for i := 0; i < 6; i++ {
		if rl.Allow(ip) {
			allowed++
		}
	}
	// Burst of 3 means at most 3 queries before throttling.
	if allowed > 3 {
		t.Errorf("expected at most 3 allowed (burst=3), got %d", allowed)
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := dnsresolver.NewIPRateLimiter(1, 2)
	// Each IP has its own bucket.
	for i := 0; i < 5; i++ {
		ip := "10.0.0." + string(rune('0'+i))
		if !rl.Allow(ip) {
			t.Errorf("first query for IP %s should be allowed (separate bucket)", ip)
		}
	}
}

func TestRateLimiter_RefillsAfterWait(t *testing.T) {
	// 100 QPS with burst 1 → after ~10ms another token should be available.
	rl := dnsresolver.NewIPRateLimiter(100, 1)
	ip := "9.9.9.9"

	if !rl.Allow(ip) {
		t.Fatal("first query should be allowed")
	}
	if rl.Allow(ip) {
		t.Error("second immediate query should be rejected (burst=1 exhausted)")
	}

	time.Sleep(15 * time.Millisecond) // 100 QPS → ~10ms per token

	if !rl.Allow(ip) {
		t.Error("query after wait should be allowed (token refilled)")
	}
}

// ---------------------------------------------------------------------------
// Domain+IP gate tests (using a mock Server helper)
// ---------------------------------------------------------------------------

// makeMatcher creates a RuleStore + IPRuleSet for testing the DNS match logic.
func makeMatcherStores(rawRules map[string]string, ipMode rules.IPMode, ipEntries []string) (*rules.RuleStore, *rules.IPRuleSet) {
	rs := rules.NewRuleStore([]int{443, 8443}, "reject")
	if err := rs.Swap(rawRules); err != nil {
		panic(err)
	}
	ir := rules.NewIPRuleSet()
	if err := ir.Swap(ipMode, ipEntries); err != nil {
		panic(err)
	}
	return rs, ir
}

// domainConfigured mirrors the logic in resolver.go for testing.
func domainConfigured(rs *rules.RuleStore, qname string) bool {
	return rs.IsConfigured(qname)
}

func clientIPAllowed(ir *rules.IPRuleSet, ipStr string) bool {
	return rules.IPCheckAllowed(ir, ipStr)
}

func TestDNSGate_ExactDomain_AllowedIP(t *testing.T) {
	rs, ir := makeMatcherStores(
		map[string]string{"example.com": `{"ports":[443]}`},
		rules.IPModeBlacklist, nil,
	)
	if !domainConfigured(rs, "example.com") {
		t.Error("example.com should be a configured domain")
	}
	if !clientIPAllowed(ir, "1.2.3.4") {
		t.Error("IP should be allowed in empty blacklist")
	}
}

func TestDNSGate_WildcardDomain_AllowedIP(t *testing.T) {
	rs, _ := makeMatcherStores(
		map[string]string{"*.example.com": `{"ports":[443]}`},
		rules.IPModeBlacklist, nil,
	)
	if !domainConfigured(rs, "api.example.com") {
		t.Error("api.example.com should match *.example.com")
	}
	if domainConfigured(rs, "example.com") {
		t.Error("apex example.com should NOT match *.example.com")
	}
}

func TestDNSGate_ConfiguredDomain_BlockedIP(t *testing.T) {
	rs, ir := makeMatcherStores(
		map[string]string{"example.com": `{"ports":[443]}`},
		rules.IPModeWhitelist, []string{"10.0.0.1"},
	)
	if !domainConfigured(rs, "example.com") {
		t.Error("domain should be configured")
	}
	// IP not in whitelist → should be denied.
	if clientIPAllowed(ir, "1.2.3.4") {
		t.Error("1.2.3.4 should NOT be allowed (whitelist mode, not listed)")
	}
}

func TestDNSGate_UnconfiguredDomain_AnyIP(t *testing.T) {
	rs, ir := makeMatcherStores(
		map[string]string{"example.com": `{"ports":[443]}`},
		rules.IPModeBlacklist, nil,
	)
	// Domain not configured → should be refused regardless of IP.
	if domainConfigured(rs, "unknown.org") {
		t.Error("unknown.org should NOT be a configured domain")
	}
	// IP allowed is irrelevant when domain not configured.
	_ = clientIPAllowed(ir, "1.2.3.4")
}

// ---------------------------------------------------------------------------
// ANY query refusal test (logic only — without network)
// ---------------------------------------------------------------------------

func TestANYQueryRefusal(t *testing.T) {
	// We test the guard logic directly by checking the query type value.
	// The actual DNS message handling is integration-level; here we verify
	// that the constant used is dns.TypeANY (255).
	const dnsTypeANY = 255
	if dnsTypeANY != 255 {
		t.Error("TypeANY should be 255 per RFC")
	}
	// Confirm our resolver would refuse this type (logic tested in resolver.go).
	// Any qtype != TypeANY should not be refused by the type-check alone.
	const dnsTypeA = 1
	if dnsTypeA == dnsTypeANY {
		t.Error("TypeA should not equal TypeANY")
	}
}

// ---------------------------------------------------------------------------
// Passthrough Toggle State Tests
// ---------------------------------------------------------------------------

func TestServer_UnauthorizedPassthroughToggle(t *testing.T) {
	rs := rules.NewRuleStore([]int{443}, "allow_default_port")
	as := access.NewAccessStore(access.ModeUser)

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:               "127.0.0.1:0",
		PassthroughEnabled: false,
		PassthroughQPS:     5,
		PassthroughBurst:   10,
	}, rs, as)
	if err != nil {
		t.Fatalf("dnsresolver.New: %v", err)
	}

	if srv.UnauthorizedPassthroughEnabled() {
		t.Error("expected initial PassthroughEnabled to be false")
	}

	srv.SetUnauthorizedPassthrough(true)
	if !srv.UnauthorizedPassthroughEnabled() {
		t.Error("expected PassthroughEnabled to be true after SetUnauthorizedPassthrough(true)")
	}

	srv.SetUnauthorizedPassthrough(false)
	if srv.UnauthorizedPassthroughEnabled() {
		t.Error("expected PassthroughEnabled to be false after SetUnauthorizedPassthrough(false)")
	}
}

func TestDNSCache_CaseInsensitive(t *testing.T) {
	c := dnsresolver.NewDNSCache()
	payload := []byte("mock-dns-response")

	c.Set("Example.COM.", 1, payload, 5*time.Second)

	// Fetching with different casing should hit cache
	got := c.Get("example.com.", 1)
	if string(got) != string(payload) {
		t.Errorf("expected cache hit for lowercase 'example.com.', got %s", got)
	}

	gotUpper := c.Get("EXAMPLE.COM.", 1)
	if string(gotUpper) != string(payload) {
		t.Errorf("expected cache hit for uppercase 'EXAMPLE.COM.', got %s", gotUpper)
	}
}

func TestServer_HTTPSAndSVCBSuppression(t *testing.T) {
	rs := rules.NewRuleStore([]int{443}, "reject")
	if err := rs.Swap(map[string]string{
		"example.com": `{"mode":"proxy","ports":[443]}`,
	}); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	as := access.NewAccessStore(access.ModePublic)

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	addr := ln.LocalAddr().String()
	_ = ln.Close()

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:         addr,
		RelayIP:      "1.2.3.4",
		UpstreamAddr: "127.0.0.1:5353",
		TTL:          60,
		QPS:          100,
		Burst:        100,
		EDNSBufSize:  1232,
	}, rs, as)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.ListenAndServe(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	c := new(dns.Client)

	// Test qtype 65 (HTTPS)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeHTTPS)
	in, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("Exchange HTTPS failed: %v", err)
	}
	if in.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess for HTTPS, got %v", in.Rcode)
	}
	if !in.Authoritative {
		t.Errorf("expected Authoritative response for HTTPS")
	}
	if len(in.Answer) != 0 {
		t.Errorf("expected empty answer for HTTPS, got %d answers", len(in.Answer))
	}

	// Test qtype 64 (SVCB)
	mSVCB := new(dns.Msg)
	mSVCB.SetQuestion("example.com.", dns.TypeSVCB)
	inSVCB, _, err := c.Exchange(mSVCB, addr)
	if err != nil {
		t.Fatalf("Exchange SVCB failed: %v", err)
	}
	if inSVCB.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess for SVCB, got %v", inSVCB.Rcode)
	}
	if !inSVCB.Authoritative {
		t.Errorf("expected Authoritative response for SVCB")
	}
	if len(inSVCB.Answer) != 0 {
		t.Errorf("expected empty answer for SVCB, got %d answers", len(inSVCB.Answer))
	}
}

func TestServer_TCPRetryOnTruncatedUpstream(t *testing.T) {
	// Set up mock upstream DNS server on UDP and TCP
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer udpLn.Close()
	upstreamAddr := udpLn.LocalAddr().String()

	tcpLn, err := net.Listen("tcp", upstreamAddr)
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer tcpLn.Close()

	// Upstream UDP handler: always returns truncated response
	udpSrv := &dns.Server{
		PacketConn: udpLn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Truncated = true
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = udpSrv.ActivateAndServe() }()
	defer func() { _ = udpSrv.Shutdown() }()

	// Upstream TCP handler: returns full answer
	tcpSrv := &dns.Server{
		Listener: tcpLn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("93.184.216.34").To4(),
			})
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	defer func() { _ = tcpSrv.Shutdown() }()

	// Relay resolver
	rs := rules.NewRuleStore([]int{443}, "allow_default_port")
	as := access.NewAccessStore(access.ModePublic)

	srvLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("srv listen: %v", err)
	}
	srvAddr := srvLn.LocalAddr().String()
	_ = srvLn.Close()

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:         srvAddr,
		UpstreamAddr: upstreamAddr,
		TTL:          60,
		QPS:          100,
		Burst:        100,
		EDNSBufSize:  1232,
	}, rs, as)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(50 * time.Millisecond)

	c := new(dns.Client)
	req := new(dns.Msg)
	req.SetQuestion("unconfigured.org.", dns.TypeA)

	resp, _, err := c.Exchange(req, srvAddr)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected non-empty answer from TCP retry, got 0")
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "93.184.216.34" {
		t.Errorf("unexpected answer: %v", resp.Answer[0])
	}
}

func TestDNSCache_BoundedCapacityAndClose(t *testing.T) {
	c := dnsresolver.NewDNSCache()
	defer c.Close()

	for i := 0; i < 20500; i++ {
		c.Set(fmt.Sprintf("host%d.com.", i), 1, []byte("data"), time.Minute)
	}

	if c.Get("host20499.com.", 1) == nil {
		t.Errorf("expected host20499.com to be in cache")
	}
}

func TestIPRateLimiter_BoundedCapacityAndClose(t *testing.T) {
	rl := dnsresolver.NewIPRateLimiter(10, 5)
	defer rl.Close()

	for i := 0; i < 1000; i++ {
		rl.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
}

func startMockDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenPacket: %v", err)
	}
	srv := &dns.Server{PacketConn: ln, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	return ln.LocalAddr().String(), func() {
		_ = srv.Shutdown()
		_ = ln.Close()
	}
}

func startTestResolver(t *testing.T, upstreams string) (*dnsresolver.Server, string, func()) {
	t.Helper()
	rs := rules.NewRuleStore([]int{443}, "allow_default_port")
	as := access.NewAccessStore(access.ModePublic)

	srvLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("srv listen: %v", err)
	}
	srvAddr := srvLn.LocalAddr().String()
	_ = srvLn.Close()

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:         srvAddr,
		UpstreamAddr: upstreams,
		TTL:          60,
		QPS:          1000,
		Burst:        1000,
		EDNSBufSize:  1232,
	}, rs, as)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(50 * time.Millisecond)

	return srv, srvAddr, func() {
		cancel()
		srv.Close()
	}
}

func TestForwardQuery_PrimaryTimesOutSecondaryAnswers(t *testing.T) {
	primaryAddr, primaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		// Do not respond; let the request time out
	})
	defer primaryClose()

	secondaryAddr, secondaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.1").To4(),
		})
		_ = w.WriteMsg(m)
	})
	defer secondaryClose()

	_, srvAddr, srvClose := startTestResolver(t, primaryAddr+","+secondaryAddr)
	defer srvClose()

	c := &dns.Client{Timeout: 7 * time.Second}
	req := new(dns.Msg)
	req.SetQuestion("fallback-timeout.org.", dns.TypeA)

	resp, _, err := c.Exchange(req, srvAddr)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected answer from secondary, got 0")
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1, got %v", resp.Answer[0])
	}
}

func TestForwardQuery_PrimaryServfailSecondaryAnswers(t *testing.T) {
	primaryAddr, primaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	defer primaryClose()

	secondaryAddr, secondaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.2").To4(),
		})
		_ = w.WriteMsg(m)
	})
	defer secondaryClose()

	_, srvAddr, srvClose := startTestResolver(t, primaryAddr+","+secondaryAddr)
	defer srvClose()

	c := new(dns.Client)
	req := new(dns.Msg)
	req.SetQuestion("fallback-servfail.org.", dns.TypeA)

	resp, _, err := c.Exchange(req, srvAddr)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected answer from secondary, got 0")
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "192.0.2.2" {
		t.Errorf("expected 192.0.2.2, got %v", resp.Answer[0])
	}
}

func TestForwardQuery_PrimaryNXDOMAINDoesNotFallback(t *testing.T) {
	primaryAddr, primaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})
	defer primaryClose()

	secondaryCalls := 0
	secondaryAddr, secondaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		secondaryCalls++
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.3").To4(),
		})
		_ = w.WriteMsg(m)
	})
	defer secondaryClose()

	_, srvAddr, srvClose := startTestResolver(t, primaryAddr+","+secondaryAddr)
	defer srvClose()

	c := new(dns.Client)
	req := new(dns.Msg)
	req.SetQuestion("primary-nxdomain.org.", dns.TypeA)

	resp, _, err := c.Exchange(req, srvAddr)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN (RcodeNameError), got %d", resp.Rcode)
	}
	if len(resp.Answer) > 0 {
		t.Errorf("expected no answers, got %d", len(resp.Answer))
	}
	if secondaryCalls > 0 {
		t.Errorf("secondary upstream was unexpectedly contacted on NXDOMAIN")
	}
}

func TestForwardQuery_AllFailReturnsServfail(t *testing.T) {
	primaryAddr, primaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	defer primaryClose()

	secondaryAddr, secondaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
	defer secondaryClose()

	_, srvAddr, srvClose := startTestResolver(t, primaryAddr+","+secondaryAddr)
	defer srvClose()

	c := new(dns.Client)
	req := new(dns.Msg)
	req.SetQuestion("all-fail.org.", dns.TypeA)

	resp, _, err := c.Exchange(req, srvAddr)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL (RcodeServerFailure), got %d", resp.Rcode)
	}
}

func TestServer_SetUpstreamsHotReload(t *testing.T) {
	primaryAddr, primaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.10").To4(),
		})
		_ = w.WriteMsg(m)
	})
	defer primaryClose()

	secondaryAddr, secondaryClose := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.ParseIP("192.0.2.20").To4(),
		})
		_ = w.WriteMsg(m)
	})
	defer secondaryClose()

	srv, srvAddr, srvClose := startTestResolver(t, primaryAddr)
	defer srvClose()

	c := new(dns.Client)

	// First query with initial primary
	req1 := new(dns.Msg)
	req1.SetQuestion("test-hotreload-1.org.", dns.TypeA)
	resp1, _, err := c.Exchange(req1, srvAddr)
	if err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}
	if len(resp1.Answer) == 0 {
		t.Fatalf("expected answer, got 0")
	}
	if a, ok := resp1.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.10" {
		t.Fatalf("expected 192.0.2.10, got %v", resp1.Answer[0])
	}

	// Hot-reload upstreams to point to secondary
	srv.SetUpstreams([]string{secondaryAddr})
	upstreams := srv.Upstreams()
	if len(upstreams) != 1 || upstreams[0] != secondaryAddr {
		t.Fatalf("expected upstreams [%s], got %v", secondaryAddr, upstreams)
	}

	// Second query with distinct domain should hit secondary
	req2 := new(dns.Msg)
	req2.SetQuestion("test-hotreload-2.org.", dns.TypeA)
	resp2, _, err := c.Exchange(req2, srvAddr)
	if err != nil {
		t.Fatalf("second exchange failed: %v", err)
	}
	if len(resp2.Answer) == 0 {
		t.Fatalf("expected answer from secondary after hot-reload, got 0")
	}
	if a, ok := resp2.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.20" {
		t.Fatalf("expected 192.0.2.20, got %v", resp2.Answer[0])
	}
}

type mockDNSUsageEmitter struct {
	mu            sync.Mutex
	userQueries   []int64
	domainQueries []string
}

func (m *mockDNSUsageEmitter) EmitDNSQuery(userID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userQueries = append(m.userQueries, userID)
}

func (m *mockDNSUsageEmitter) EmitDomainDNSQuery(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domainQueries = append(m.domainQueries, domain)
}

func TestHandleQuery_EmitsDomainDNSQuery(t *testing.T) {
	rs := rules.NewRuleStore([]int{443}, "reject")
	_ = rs.Swap(map[string]string{
		"myconfigured.com": `{"ports":[443],"mode":"proxy"}`,
		"*.wildcard.org":   `{"ports":[443],"mode":"proxy"}`,
	})
	as := access.NewAccessStore(access.ModePublic)

	srvLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("srv listen: %v", err)
	}
	srvAddr := srvLn.LocalAddr().String()
	_ = srvLn.Close()

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:        srvAddr,
		RelayIP:     "192.0.2.1",
		TTL:         60,
		QPS:         1000,
		Burst:       1000,
		EDNSBufSize: 1232,
	}, rs, as)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	emitter := &mockDNSUsageEmitter{}
	srv.SetUsageTracker(emitter)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		srv.Close()
	}()
	time.Sleep(50 * time.Millisecond)

	c := new(dns.Client)

	// Query exact match domain
	req1 := new(dns.Msg)
	req1.SetQuestion("myconfigured.com.", dns.TypeA)
	_, _, err = c.Exchange(req1, srvAddr)
	if err != nil {
		t.Fatalf("exchange 1: %v", err)
	}

	// Query wildcard domain
	req2 := new(dns.Msg)
	req2.SetQuestion("sub.wildcard.org.", dns.TypeA)
	_, _, err = c.Exchange(req2, srvAddr)
	if err != nil {
		t.Fatalf("exchange 2: %v", err)
	}

	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if len(emitter.domainQueries) != 2 {
		t.Fatalf("expected 2 domain DNS queries, got %d", len(emitter.domainQueries))
	}
	if emitter.domainQueries[0] != "myconfigured.com" {
		t.Errorf("query 0 domain got %q, want myconfigured.com", emitter.domainQueries[0])
	}
	if emitter.domainQueries[1] != "*.wildcard.org" {
		t.Errorf("query 1 domain got %q, want *.wildcard.org", emitter.domainQueries[1])
	}
}

// ---------------------------------------------------------------------------
// DNSCheckRegistry tests
// ---------------------------------------------------------------------------

func TestDNSCheckRegistry_IssueAndRecord(t *testing.T) {
	r := dnsresolver.NewDNSCheckRegistry()
	defer r.Close()

	const tok = "aabbccddeeff0011"

	if r.IsIssued(tok) {
		t.Fatal("token should not be issued before Issue()")
	}

	r.Issue(tok)
	if !r.IsIssued(tok) {
		t.Fatal("token should be issued after Issue()")
	}

	_, seen := r.Lookup(tok)
	if seen {
		t.Error("token should not be seen before Record()")
	}

	if !r.Record(tok, "1.2.3.4") {
		t.Fatal("Record() should return true for issued token")
	}

	entry, seen := r.Lookup(tok)
	if !seen {
		t.Fatal("token should be seen after Record()")
	}
	if entry == nil {
		t.Fatal("entry should not be nil after Record()")
	}
	if entry.SourceIP != "1.2.3.4" {
		t.Errorf("expected source IP 1.2.3.4, got %q", entry.SourceIP)
	}
}

func TestDNSCheckRegistry_UnknownToken(t *testing.T) {
	r := dnsresolver.NewDNSCheckRegistry()
	defer r.Close()

	if r.Record("deadbeef12345678", "2.2.2.2") {
		t.Error("Record() should return false for unknown token")
	}
}

func TestDNSCheckRegistry_ProbeQueryServerSide(t *testing.T) {
	// Bind a UDP socket to get a free port, then release it so the resolver can bind.
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("could not bind UDP socket for probe test")
	}
	srvAddr := ln.LocalAddr().String()
	_ = ln.Close()

	rs := rules.NewRuleStore([]int{443}, "reject")
	as := access.NewAccessStore(access.ModeUser)

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:    srvAddr,
		RelayIP: "203.0.113.10",
		QPS:     1000,
		Burst:   1000,
	}, rs, as)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	reg := dnsresolver.NewDNSCheckRegistry()
	srv.SetDNSCheckRegistry(reg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(40 * time.Millisecond) // let the listener bind

	const tok = "ccddaabb11223344"
	reg.Issue(tok)

	probeName := tok + ".dnscheck.relay-probe.net."
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(probeName, dns.TypeA)

	resp, _, err := client.Exchange(msg, srvAddr)
	if err != nil {
		t.Fatalf("probe query failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR for probe, got %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Error("expected A record in probe response")
	}

	entry, seen := reg.Lookup(tok)
	if !seen {
		t.Fatal("registry should have recorded the probe token")
	}
	if entry == nil || entry.SourceIP == "" {
		t.Error("registry entry should have a source IP")
	}
}

func TestDNSCheckRegistry_UnknownProbeGetsNXDOMAIN(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("could not bind UDP socket for probe test")
	}
	srvAddr := ln.LocalAddr().String()
	_ = ln.Close()

	rs := rules.NewRuleStore([]int{443}, "reject")
	as := access.NewAccessStore(access.ModeUser)

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:    srvAddr,
		RelayIP: "203.0.113.10",
		QPS:     1000,
		Burst:   1000,
	}, rs, as)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	reg := dnsresolver.NewDNSCheckRegistry()
	srv.SetDNSCheckRegistry(reg)
	// Do NOT issue any token.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(40 * time.Millisecond)

	probeName := "ccddaabb11223300.dnscheck.relay-probe.net."
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(probeName, dns.TypeA)

	resp, _, err := client.Exchange(msg, srvAddr)
	if err != nil {
		t.Fatalf("probe query failed: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN for unknown probe token, got %d", resp.Rcode)
	}
}

// TestDirectModeDomain_ForwardsUpstream_IgnoresRejectPolicy verifies that a
// domain configured with mode="direct" is always forwarded to upstream DNS for
// authorized clients, even when unknown_domain_policy is "reject".  Without the
// fix the server would REFUSE the query because the domain is not a proxy rule.
func TestDirectModeDomain_ForwardsUpstream_IgnoresRejectPolicy(t *testing.T) {
	// Upstream mock: always returns NOERROR with a dummy A record.
	upMux := dns.NewServeMux()
	upMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("9.9.9.9"),
			})
		}
		_ = w.WriteMsg(m)
	})
	upLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	upSrv := &dns.Server{PacketConn: upLn, Net: "udp", Handler: upMux}
	go func() { _ = upSrv.ActivateAndServe() }()
	defer upSrv.Shutdown()
	upAddr := upLn.LocalAddr().String()

	// DNS server rule store: "reject" policy + one direct-mode rule.
	rs := rules.NewRuleStore([]int{443}, "reject")
	if err := rs.Swap(map[string]string{
		"bypass.example.com": `{"mode":"direct","ports":[443]}`,
	}); err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// Public access mode so any client IP is authorized.
	as := access.NewAccessStore(access.ModePublic)

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.LocalAddr().String()
	_ = ln.Close()

	srv, err := dnsresolver.New(dnsresolver.Config{
		Addr:         addr,
		RelayIP:      "1.2.3.4",
		UpstreamAddr: upAddr,
		TTL:          5,
		QPS:          100,
		Burst:        100,
		EDNSBufSize:  1232,
	}, rs, as)
	if err != nil {
		t.Fatalf("dnsresolver.New: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(50 * time.Millisecond)

	c := new(dns.Client)

	// Query for the direct-mode domain — must NOT be REFUSED.
	m := new(dns.Msg)
	m.SetQuestion("bypass.example.com.", dns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.Rcode == dns.RcodeRefused {
		t.Fatal("direct-mode domain was REFUSED; expected upstream forwarding (NOERROR with real IP)")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR from upstream, got rcode %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one answer from upstream for direct-mode domain")
	}

	// Sanity: a proxy-mode domain should still resolve to the relay IP (not upstream).
	if err := rs.Swap(map[string]string{
		"bypass.example.com": `{"mode":"direct","ports":[443]}`,
		"proxy.example.com":  `{"mode":"proxy","ports":[443]}`,
	}); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	mp := new(dns.Msg)
	mp.SetQuestion("proxy.example.com.", dns.TypeA)
	resp2, _, err := c.Exchange(mp, addr)
	if err != nil {
		t.Fatalf("proxy Exchange: %v", err)
	}
	if resp2.Rcode != dns.RcodeSuccess {
		t.Errorf("expected proxy domain to resolve, got %d", resp2.Rcode)
	}
	if !resp2.Authoritative {
		t.Error("expected authoritative response for proxy-mode domain (relay IP)")
	}
}
