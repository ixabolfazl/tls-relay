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

// UserDNSUsageEmitter is an interface to emit per-user DNS query events.
type UserDNSUsageEmitter interface {
	EmitDNSQuery(userID int64)
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
	upstream           *dns.Client
	logger             *requestlog.Logger
	userLookup         UserLookup
	stats              *reqstats.Collector
	usageTracker       UserDNSUsageEmitter
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
	}
	srv.passthroughEnabled.Store(cfg.PassthroughEnabled)
	return srv, nil
}

// ListenAndServe starts UDP and TCP listeners and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
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
		slog.Warn("dns query rate-limited", "client_ip", clientIP)
		return
	}

	if len(req.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}

	q := req.Question[0]

	// ------------------------------------------------------------------
	// Step 2: Refuse ANY queries (amplification prevention).
	// ------------------------------------------------------------------
	if q.Qtype == dns.TypeANY {
		slog.Warn("dns query refused: ANY query type", "client_ip", clientIP, "qname", q.Name)
		resp := refusedMsg(req)
		capEDNS(resp, s.cfg.EDNSBufSize)
		_ = w.WriteMsg(resp)
		return
	}

	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	qtypeStr := dns.TypeToString[q.Qtype]

	slog.Info("dns query received",
		slog.String("client_ip", clientIP),
		slog.String("qname", qname),
		slog.String("qtype", qtypeStr),
	)

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
		slog.Warn("dns query refused: domain rule is in block mode",
			slog.String("client_ip", clientIP),
			slog.String("qname", qname),
		)
		s.emitLog(clientIP, qname, "rejected_domain_blocked")
		resp := refusedMsg(req)
		capEDNS(resp, s.cfg.EDNSBufSize)
		_ = w.WriteMsg(resp)
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
			// Domain IS configured -> authoritative relay response
			if s.relayIP == nil {
				slog.Error("dns query matched domain rule but RELAY_IP is not configured in env/config",
					slog.String("client_ip", clientIP),
					slog.String("qname", qname),
				)
				s.emitLog(clientIP, qname, "error_no_relay_ip")
				resp := serverFailureMsg(req)
				capEDNS(resp, s.cfg.EDNSBufSize)
				_ = w.WriteMsg(resp)
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
				capEDNS(resp, s.cfg.EDNSBufSize)
				_ = w.WriteMsg(resp)
				return
			}

			// For non-A/AAAA queries on configured domains (e.g. TXT, MX), forward to upstream.
			s.emitLog(clientIP, qname, "forwarded")
			s.forwardQuery(w, req, q)
			return
		}

		// Domain is NOT in rules -> check unknown_domain_policy
		if s.ruleStore != nil && s.ruleStore.UnknownDomainPolicy() == "allow_default_port" {
			slog.Info("dns query forwarded to upstream (unconfigured domain, allow_default_port policy)",
				slog.String("client_ip", clientIP),
				slog.String("qname", qname),
			)
			s.emitLog(clientIP, qname, "forwarded")
			s.forwardQuery(w, req, q)
			return
		}

		slog.Warn("dns query rejected: domain not configured in rules and policy is reject",
			slog.String("client_ip", clientIP),
			slog.String("qname", qname),
		)
		s.emitLog(clientIP, qname, "rejected_domain")
		resp := refusedMsg(req)
		capEDNS(resp, s.cfg.EDNSBufSize)
		_ = w.WriteMsg(resp)
		return
	}

	// Branch 2: Client IP is NOT authorized
	// (a) If the domain is a configured relay domain rule, ALWAYS refuse unauthorized IPs.
	if isDomainConfigured {
		if s.stats != nil {
			s.stats.Emit("DNS", "unauthorized_rejected")
		}
		slog.Warn("dns query rejected: unauthorized IP attempted to query configured domain",
			slog.String("client_ip", clientIP),
			slog.String("qname", qname),
		)
		s.emitLog(clientIP, qname, "rejected_client_ip")
		resp := refusedMsg(req)
		capEDNS(resp, s.cfg.EDNSBufSize)
		_ = w.WriteMsg(resp)
		return
	}

	// (b) Domain is NOT a relay rule -> check if DNS passthrough is enabled.
	if s.passthroughEnabled.Load() {
		if s.stats != nil {
			s.stats.Emit("DNS", "unauthorized_passthrough")
		}
		// Enforce dedicated stricter rate limiter for passthrough queries
		if s.passthroughLimiter != nil && !s.passthroughLimiter.Allow(clientIP) {
			slog.Warn("dns passthrough query rate-limited", "client_ip", clientIP, "qname", qname)
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
	s.emitLog(clientIP, qname, "rejected_client_ip")
	resp := refusedMsg(req)
	capEDNS(resp, s.cfg.EDNSBufSize)
	_ = w.WriteMsg(resp)
}

// domainConfiguredForRelay checks whether qname matches a configured domain rule
// that is set to "proxy" mode. Rules in "direct" or "block" mode return false
// so they are not redirected to the relay IP.
func (s *Server) domainConfiguredForRelay(qname string) bool {
	if s.ruleStore == nil {
		return false
	}
	rule, matched := s.ruleStore.LookupRule(qname)
	if !matched {
		return false
	}
	return rule.Mode == "proxy" || rule.Mode == ""
}

// domainConfigured checks whether qname matches any configured domain rule
// (exact or wildcard), regardless of port. Used to decide whether the relay
// should redirect DNS queries to its own IP.
func (s *Server) domainConfigured(qname string) bool {
	return s.ruleStore.IsConfigured(qname)
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
	// For AAAA, return NOERROR with empty answer (no IPv6 relay IP).
	return resp
}

func (s *Server) forwardQuery(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	// Check cache first.
	if cached := s.cache.Get(q.Name, q.Qtype); cached != nil {
		cachedMsg := new(dns.Msg)
		if err := cachedMsg.Unpack(cached); err == nil {
			cachedMsg.Id = req.Id
			capEDNS(cachedMsg, s.cfg.EDNSBufSize)
			_ = w.WriteMsg(cachedMsg)
			return
		}
	}

	// Forward to upstream.
	resp, _, err := s.upstream.Exchange(req, s.cfg.UpstreamAddr)
	if err != nil {
		slog.Warn("dns upstream query failed", "name", q.Name, "error", err)
		// Return SERVFAIL.
		fail := serverFailureMsg(req)
		capEDNS(fail, s.cfg.EDNSBufSize)
		_ = w.WriteMsg(fail)
		return
	}

	// Cache the response (use minimum TTL from answer section).
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

	capEDNS(resp, s.cfg.EDNSBufSize)
	_ = w.WriteMsg(resp)
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
