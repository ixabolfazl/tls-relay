// Package dnsresolver implements a custom DNS server that:
//   - Rate-limits by source IP (token bucket, silent drop on over-limit).
//   - Refuses ANY queries (amplification prevention).
//   - Caps EDNS0 UDP buffer size.
//   - Responds with the relay's own IP for configured domains from allowed client IPs.
//   - Forwards all other queries to an upstream resolver, caching responses.
package dnsresolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/reqstats"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// UserLookup is an interface to query user info for a client IP.
type UserLookup interface {
	LookupUser(ip string) (userID int64, username string, ok bool)
}

// UserDNSUsageEmitter is an interface to emit per-user and per-domain DNS query events.
type UserDNSUsageEmitter interface {
	EmitDNSQuery(userID int64)
	EmitDomainDNSQuery(domain string)
}

// Config holds the DNS resolver configuration.
type Config struct {
	Addr               string  // e.g. "0.0.0.0:53"
	RelayIP            string  // authoritative A record answer
	UpstreamAddr       string  // e.g. "1.1.1.1:53"
	TTL                uint32  // TTL for authoritative answers (seconds)
	QPS                float64 // per-IP rate limit queries/sec
	Burst              int     // per-IP burst size
	EDNSBufSize        uint16  // cap advertised EDNS0 UDP buffer
	PassthroughEnabled bool
	PassthroughQPS     float64
	PassthroughBurst   int
}

// Server is the custom DNS resolver.
type Server struct {
	cfg                Config
	ruleStore          *rules.RuleStore
	accessStore        *access.AccessStore
	limiter            *IPRateLimiter
	passthroughEnabled atomic.Bool
	passthroughLimiter *IPRateLimiter
	cache              *DNSCache
	relayIP            net.IP
	upstreams          atomic.Pointer[[]string]
	upstream           *dns.Client
	logger             *requestlog.Logger
	userLookup         UserLookup
	stats              *reqstats.Collector
	usageTracker       UserDNSUsageEmitter
	sampled            *sampledLogger
	checkRegistry      *DNSCheckRegistry
}

// SetUpstreams dynamically updates the list of upstream DNS servers.
func (s *Server) SetUpstreams(addrs []string) {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	s.upstreams.Store(&cp)
}

// Upstreams returns a copy of the active upstream DNS servers.
func (s *Server) Upstreams() []string {
	ptr := s.upstreams.Load()
	if ptr == nil || len(*ptr) == 0 {
		return nil
	}
	cp := make([]string, len(*ptr))
	copy(cp, *ptr)
	return cp
}

// SetDNSCheckRegistry registers the DNS check token registry for probe queries.
func (s *Server) SetDNSCheckRegistry(r *DNSCheckRegistry) {
	s.checkRegistry = r
}

// DNSCheckRegistry returns the active check registry (may be nil).
func (s *Server) DNSCheckRegistry() *DNSCheckRegistry {
	return s.checkRegistry
}

// Close stops background caches and sweepers.
func (s *Server) Close() {
	if s.cache != nil {
		s.cache.Close()
	}
	if s.limiter != nil {
		s.limiter.Close()
	}
	if s.passthroughLimiter != nil {
		s.passthroughLimiter.Close()
	}
	if s.sampled != nil {
		s.sampled.Close()
	}
}

// SetUnauthorizedPassthrough enables or disables DNS resolution for unregistered IPs on unconfigured domains.
func (s *Server) SetUnauthorizedPassthrough(enabled bool) {
	s.passthroughEnabled.Store(enabled)
}

// UnauthorizedPassthroughEnabled returns whether DNS passthrough for unregistered IPs is currently enabled.
func (s *Server) UnauthorizedPassthroughEnabled() bool {
	return s.passthroughEnabled.Load()
}

// SetLogger sets the async request logger and user lookup interface.
func (s *Server) SetLogger(l *requestlog.Logger, lookup UserLookup) {
	s.logger = l
	s.userLookup = lookup
}

// SetStatsCollector sets the request stats collector.
func (s *Server) SetStatsCollector(c *reqstats.Collector) {
	s.stats = c
}

// SetUsageTracker sets the user DNS usage emitter.
func (s *Server) SetUsageTracker(ut UserDNSUsageEmitter) {
	s.usageTracker = ut
}

func (s *Server) emitLog(clientIP, domain, status string) {
	if s.logger == nil || !s.logger.IsEnabled() {
		return
	}

	username := "Unknown"
	var userID int64

	if s.userLookup != nil {
		if uid, uname, ok := s.userLookup.LookupUser(clientIP); ok {
			userID = uid
			if uname != "" {
				username = uname
			}
		}
	}

	s.logger.Emit(requestlog.Event{
		UserID:      userID,
		Username:    username,
		ClientIP:    clientIP,
		RequestType: requestlog.TypeDNS,
		Domain:      domain,
		Port:        53,
		Status:      status,
		Timestamp:   time.Now(),
	})
}

// New creates a Server.
func New(cfg Config, rs *rules.RuleStore, as *access.AccessStore) (*Server, error) {
	var relayIP net.IP
	if cfg.RelayIP != "" {
		parsed := net.ParseIP(cfg.RelayIP)
		if parsed == nil {
			return nil, fmt.Errorf("dns.relay_ip %q is not a valid IP address", cfg.RelayIP)
		}
		relayIP = parsed.To4()
		if relayIP == nil {
			return nil, fmt.Errorf("dns.relay_ip %q is not a valid IPv4 address", cfg.RelayIP)
		}
	}

	ptQPS := cfg.PassthroughQPS
	if ptQPS <= 0 {
		ptQPS = 5
	}
	ptBurst := cfg.PassthroughBurst
	if ptBurst <= 0 {
		ptBurst = 10
	}

	srv := &Server{
		cfg:                cfg,
		ruleStore:          rs,
		accessStore:        as,
		limiter:            NewIPRateLimiter(cfg.QPS, cfg.Burst),
		passthroughLimiter: NewIPRateLimiter(ptQPS, ptBurst),
		cache:              newDNSCache(),
		relayIP:            relayIP,
		upstream:           &dns.Client{Timeout: 5 * time.Second},
		sampled:            newSampledLogger(),
	}
	var initialUpstreams []string
	for _, u := range strings.Split(cfg.UpstreamAddr, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			initialUpstreams = append(initialUpstreams, u)
		}
	}
	srv.upstreams.Store(&initialUpstreams)
	srv.passthroughEnabled.Store(cfg.PassthroughEnabled)
	return srv, nil
}

// ListenAndServe starts UDP and TCP listeners and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	defer s.Close()
	errCh := make(chan error, 2)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleQuery)

	udpServer := &dns.Server{
		Addr:    s.cfg.Addr,
		Net:     "udp",
		Handler: mux,
	}
	tcpServer := &dns.Server{
		Addr:    s.cfg.Addr,
		Net:     "tcp",
		Handler: mux,
	}

	go func() {
		slog.Info("dns resolver listening (UDP)", "addr", s.cfg.Addr)
		if err := udpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("dns udp: %w", err)
		}
	}()
	go func() {
		slog.Info("dns resolver listening (TCP)", "addr", s.cfg.Addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("dns tcp: %w", err)
		}
	}()

	// Wait for context cancellation or early listener failure.
	var serveErr error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		serveErr = err
	}

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	return serveErr
}

// handleQuery is the main query handler.
func (s *Server) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	clientAddr := w.RemoteAddr()
	clientIP := extractDNSIP(clientAddr)

	// ------------------------------------------------------------------
	// Step 1: Per-source-IP rate limit. Drop silently if over limit.
	// ------------------------------------------------------------------
	if !s.limiter.Allow(clientIP) {
		s.sampled.Log("rate_limited", func() {
			slog.Warn("dns query rate-limited", "client_ip", clientIP)
		})
		return
	}

	if len(req.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeFormatError
		s.writeMsg(w, req, resp)
		return
	}

	q := req.Question[0]

	// ------------------------------------------------------------------
	// Step 2: Refuse ANY queries (amplification prevention).
	// ------------------------------------------------------------------
	if q.Qtype == dns.TypeANY {
		s.sampled.Log("refused_any", func() {
			slog.Warn("dns query refused: ANY query type", "client_ip", clientIP, "qname", q.Name)
		})
		resp := refusedMsg(req)
		s.writeMsg(w, req, resp)
		return
	}

	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	qtypeStr := dns.TypeToString[q.Qtype]

	slog.Debug("dns query received",
		slog.String("client_ip", clientIP),
		slog.String("qname", qname),
		slog.String("qtype", qtypeStr),
	)

	// ------------------------------------------------------------------
	// Step 2b: DNS status check probe (dnscheck.relay-probe.net subdomain).
	// Handled regardless of access mode, but still after the rate limit.
	// Does NOT log request, does NOT emit usage stats.
	// ------------------------------------------------------------------
	if s.checkRegistry != nil && s.relayIP != nil {
		if token, isProbe := isDNSCheckQuery(qname); isProbe {
			if s.checkRegistry.IsIssued(token) {
				_ = s.checkRegistry.Record(token, clientIP)
				slog.Debug("dns check probe recorded",
					slog.String("token", token),
					slog.String("client_ip", clientIP),
				)
				// Answer A with the relay IP (authoritative, TTL 0).
				if q.Qtype == dns.TypeA {
					resp := new(dns.Msg)
					resp.SetReply(req)
					resp.Authoritative = true
					resp.RecursionAvailable = false
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: s.relayIP,
					})
					s.writeMsg(w, req, resp)
					return
				}
				// All other types: empty NOERROR.
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Authoritative = true
				s.writeMsg(w, req, resp)
				return
			}
			// Unknown or expired token: NXDOMAIN, not forwarded upstream.
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			s.writeMsg(w, req, resp)
			return
		}
	} else if s.checkRegistry != nil && strings.HasSuffix(qname, dnsCheckSuffix) {
		// relay_ip not configured: refuse probe silently with NXDOMAIN.
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeNameError
		resp.Authoritative = true
		s.writeMsg(w, req, resp)
		return
	}

	// Emit per-user DNS usage count if client IP belongs to a registered user.
	if s.userLookup != nil && s.usageTracker != nil {
		if uid, _, ok := s.userLookup.LookupUser(clientIP); ok && uid > 0 {
			s.usageTracker.EmitDNSQuery(uid)
		}
	}

	// ------------------------------------------------------------------
	// Step 3: Evaluate domain rule mode & IP authorization status.
	// ------------------------------------------------------------------
	var (
		matchedRule rules.DomainRule
		ruleMatched bool
	)
	if s.ruleStore != nil {
		matchedRule, ruleMatched = s.ruleStore.LookupRule(qname)
	}

	// Mode check: "block" mode MUST be refused for both authorized and unauthorized IPs.
	if ruleMatched && matchedRule.Mode == "block" {
		if s.stats != nil {
			s.stats.Emit("DNS", "blocked")
		}
		s.sampled.Log("refused_block", func() {
			slog.Warn("dns query refused: domain rule is in block mode",
				slog.String("client_ip", clientIP),
				slog.String("qname", qname),
			)
		})
		s.emitLog(clientIP, qname, "rejected_domain_blocked")
		resp := refusedMsg(req)
		s.writeMsg(w, req, resp)
		return
	}

	isIPAllowed := s.clientIPAllowed(clientIP)
	isDomainConfigured := ruleMatched && (matchedRule.Mode == "proxy" || matchedRule.Mode == "")

	// Branch 1: Client IP is authorized (registered user or public mode)
	if isIPAllowed {
		if s.stats != nil {
			s.stats.Emit("DNS", "authorized")
		}
		if isDomainConfigured {
			if s.usageTracker != nil {
				domainKey := matchedRule.Domain
				if domainKey == "" {
					domainKey = qname
				}
				s.usageTracker.EmitDomainDNSQuery(domainKey)
			}
			// Domain IS configured -> authoritative relay response
			if s.relayIP == nil {
				slog.Error("dns query matched domain rule but RELAY_IP is not configured in env/config",
					slog.String("client_ip", clientIP),
					slog.String("qname", qname),
				)
				s.emitLog(clientIP, qname, "error_no_relay_ip")
				resp := serverFailureMsg(req)
				s.writeMsg(w, req, resp)
				return
			}

			if q.Qtype == dns.TypeHTTPS || q.Qtype == dns.TypeSVCB || q.Qtype == 65 || q.Qtype == 64 {
				slog.Info("dns query answered with empty authoritative answer for HTTPS/SVCB",
					slog.String("client_ip", clientIP),
					slog.String("qname", qname),
					slog.String("qtype", qtypeStr),
				)
				s.emitLog(clientIP, qname, "resolved_empty")
				resp := s.buildAuthoritativeResponse(req, q, qname)
				s.writeMsg(w, req, resp)
				return
			}

			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
				slog.Info("dns query resolved with relay IP",
					slog.String("client_ip", clientIP),
					slog.String("qname", qname),
					slog.String("qtype", qtypeStr),
					slog.String("relay_ip", s.relayIP.String()),
				)
				s.emitLog(clientIP, qname, "resolved")
				resp := s.buildAuthoritativeResponse(req, q, qname)
				s.writeMsg(w, req, resp)
				return
			}

			// For non-A/AAAA/HTTPS/SVCB queries on configured domains (e.g. TXT, MX), forward to upstream.
			s.emitLog(clientIP, qname, "forwarded")
			s.forwardQuery(w, req, q)
			return
		}

		// Domain is configured in rules with mode="direct", OR domain is NOT in rules (unconfigured):
		// For authorized clients, the DNS resolver resolves the domain's real IP via upstream DNS
		// so the client connects directly. The unknown_domain_policy setting applies exclusively
		// to TLS/HTTP relay proxying (refusing TCP/TLS connections for unlisted hostnames), never
		// to authorized DNS resolution.
		slog.Info("dns query forwarded to upstream for authorized client",
			slog.String("client_ip", clientIP),
			slog.String("qname", qname),
		)
		s.emitLog(clientIP, qname, "forwarded")
		s.forwardQuery(w, req, q)
		return
	}

	// Branch 2: Client IP is NOT authorized
	// (a) If the domain is a configured relay domain rule, ALWAYS refuse unauthorized IPs.
	if isDomainConfigured {
		if s.stats != nil {
			s.stats.Emit("DNS", "unauthorized_rejected")
		}
		s.sampled.Log("unauthorized_configured", func() {
			slog.Warn("dns query rejected: unauthorized IP attempted to query configured domain",
				slog.String("client_ip", clientIP),
				slog.String("qname", qname),
			)
		})
		s.emitLog(clientIP, qname, "rejected_client_ip")
		resp := refusedMsg(req)
		s.writeMsg(w, req, resp)
		return
	}

	// (b) Domain is NOT a relay rule -> check if DNS passthrough is enabled.
	if s.passthroughEnabled.Load() {
		if s.stats != nil {
			s.stats.Emit("DNS", "unauthorized_passthrough")
		}
		// Enforce dedicated stricter rate limiter for passthrough queries
		if s.passthroughLimiter != nil && !s.passthroughLimiter.Allow(clientIP) {
			s.sampled.Log("passthrough_rate_limited", func() {
				slog.Warn("dns passthrough query rate-limited", "client_ip", clientIP, "qname", qname)
			})
			return
		}

		slog.Info("dns passthrough query forwarded to upstream for unauthorized IP",
			slog.String("client_ip", clientIP),
			slog.String("qname", qname),
		)
		s.emitLog(clientIP, qname, "forwarded_unauthorized")
		s.forwardQuery(w, req, q)
		return
	}

	// Passthrough is disabled -> refuse unauthorized query
	if s.stats != nil {
		s.stats.Emit("DNS", "unauthorized_rejected")
	}
	s.sampled.Log("unauthorized_rejected", func() {
		slog.Warn("dns query rejected: unauthorized IP",
			slog.String("client_ip", clientIP),
			slog.String("qname", qname),
		)
	})
	s.emitLog(clientIP, qname, "rejected_client_ip")
	resp := refusedMsg(req)
	s.writeMsg(w, req, resp)
}

// clientIPAllowed checks if the querying client IP is allowed by the access rules.
func (s *Server) clientIPAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	allowed, _ := s.accessStore.CheckAccess(ip)
	return allowed
}

func (s *Server) buildAuthoritativeResponse(req *dns.Msg, q dns.Question, qname string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	if q.Qtype == dns.TypeA {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    s.cfg.TTL,
			},
			A: s.relayIP,
		}
		resp.Answer = append(resp.Answer, rr)
	}
	// For AAAA, HTTPS, SVCB: return NOERROR with empty answer.
	return resp
}

func (s *Server) forwardQuery(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	// Check cache first.
	if cached := s.cache.Get(q.Name, q.Qtype); cached != nil {
		cachedMsg := new(dns.Msg)
		if err := cachedMsg.Unpack(cached); err == nil {
			cachedMsg.Id = req.Id
			s.writeMsg(w, req, cachedMsg)
			return
		}
	}

	upstreams := s.Upstreams()
	if len(upstreams) == 0 {
		slog.Warn("dns forward query failed: no upstream resolvers configured", "name", q.Name)
		fail := serverFailureMsg(req)
		s.writeMsg(w, req, fail)
		return
	}

	deadline := time.Now().Add(8 * time.Second)
	var failures []string

	for _, addr := range upstreams {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			failures = append(failures, "total timeout exceeded")
			break
		}

		attemptTimeout := 5 * time.Second
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}

		client := &dns.Client{Net: "udp", Timeout: attemptTimeout}
		resp, _, err := client.Exchange(req, addr)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s (UDP): %v", addr, err))
			continue
		}
		if resp == nil {
			failures = append(failures, fmt.Sprintf("%s: nil response", addr))
			continue
		}

		// When the upstream UDP answer has TC set, retry over TCP before answering
		if resp.Truncated {
			remainingTCP := time.Until(deadline)
			if remainingTCP <= 0 {
				failures = append(failures, fmt.Sprintf("%s (TCP): total timeout exceeded", addr))
				break
			}
			tcpTimeout := 5 * time.Second
			if remainingTCP < tcpTimeout {
				tcpTimeout = remainingTCP
			}
			tcpClient := &dns.Client{Net: "tcp", Timeout: tcpTimeout}
			tcpResp, _, tcpErr := tcpClient.Exchange(req, addr)
			if tcpErr != nil {
				failures = append(failures, fmt.Sprintf("%s (TCP): %v", addr, tcpErr))
				continue
			}
			if tcpResp == nil {
				failures = append(failures, fmt.Sprintf("%s (TCP): nil response", addr))
				continue
			}
			resp = tcpResp
		}

		// Fall back to next upstream on SERVFAIL.
		// Stop on any other rcode (NOERROR, NXDOMAIN, NOTIMP, REFUSED, etc.).
		if resp.Rcode == dns.RcodeServerFailure {
			failures = append(failures, fmt.Sprintf("%s: SERVFAIL", addr))
			continue
		}

		// Success or other valid authoritative rcode (like NXDOMAIN).
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			minTTL := resp.Answer[0].Header().Ttl
			for _, rr := range resp.Answer {
				if rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
			if packed, err := resp.Pack(); err == nil {
				s.cache.Set(q.Name, q.Qtype, packed, time.Duration(minTTL)*time.Second)
			}
		}

		s.writeMsg(w, req, resp)
		return
	}

	// All upstreams failed
	slog.Warn("dns forward query failed on all upstreams",
		"name", q.Name,
		"failures", strings.Join(failures, "; "),
	)
	fail := serverFailureMsg(req)
	s.writeMsg(w, req, fail)
}

func (s *Server) writeMsg(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) {
	if w == nil || resp == nil {
		return
	}
	capEDNS(resp, s.cfg.EDNSBufSize)

	// For UDP, resp.Truncate(min(clientEDNSSize or 512, cfg.EDNSBufSize)) (sets TC when needed)
	isUDP := false
	if rAddr := w.RemoteAddr(); rAddr != nil {
		netName := strings.ToLower(rAddr.Network())
		if strings.HasPrefix(netName, "udp") {
			isUDP = true
		}
	}

	if isUDP && req != nil {
		clientBuf := 512
		if opt := req.IsEdns0(); opt != nil && opt.UDPSize() > 0 {
			clientBuf = int(opt.UDPSize())
		}
		maxBuf := clientBuf
		if s.cfg.EDNSBufSize > 0 && int(s.cfg.EDNSBufSize) < maxBuf {
			maxBuf = int(s.cfg.EDNSBufSize)
		}
		resp.Truncate(maxBuf)
	}

	_ = w.WriteMsg(resp)
}

type sampleEntry struct {
	lastLogged time.Time
	count      int
}

type sampledLogger struct {
	mu      sync.Mutex
	entries map[string]*sampleEntry
	stopCh  chan struct{}
}

func newSampledLogger() *sampledLogger {
	sl := &sampledLogger{
		entries: make(map[string]*sampleEntry),
		stopCh:  make(chan struct{}),
	}
	go sl.flusher()
	return sl
}

func (sl *sampledLogger) Close() {
	if sl.stopCh != nil {
		select {
		case <-sl.stopCh:
		default:
			close(sl.stopCh)
		}
	}
}

func (sl *sampledLogger) flusher() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sl.stopCh:
			return
		case now := <-ticker.C:
			sl.mu.Lock()
			for reason, entry := range sl.entries {
				if entry.count > 0 && now.Sub(entry.lastLogged) >= 10*time.Second {
					slog.Warn("dns query drops/refusals sampled", "reason", reason, "count", entry.count)
					entry.count = 0
					entry.lastLogged = now
				}
			}
			sl.mu.Unlock()
		}
	}
}

func (sl *sampledLogger) Log(reason string, logFirst func()) {
	now := time.Now()
	sl.mu.Lock()
	defer sl.mu.Unlock()

	entry, exists := sl.entries[reason]
	if !exists || now.Sub(entry.lastLogged) >= 10*time.Second {
		if exists && entry.count > 0 {
			slog.Warn("dns query drops/refusals sampled", "reason", reason, "count", entry.count)
		}
		sl.entries[reason] = &sampleEntry{lastLogged: now, count: 0}
		logFirst()
		return
	}
	entry.count++
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func refusedMsg(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeRefused
	return resp
}

func serverFailureMsg(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeServerFailure
	return resp
}

func capEDNS(msg *dns.Msg, maxBuf uint16) {
	opt := msg.IsEdns0()
	if opt != nil && opt.UDPSize() > maxBuf {
		opt.SetUDPSize(maxBuf)
	}
}

func extractDNSIP(addr net.Addr) string {
	var raw string
	switch a := addr.(type) {
	case *net.UDPAddr:
		raw = a.IP.String()
	case *net.TCPAddr:
		raw = a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			raw = addr.String()
		} else {
			raw = host
		}
	}
	raw = strings.TrimSpace(raw)
	if parsed := net.ParseIP(raw); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return raw
}
