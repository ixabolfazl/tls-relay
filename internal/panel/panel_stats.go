package panel

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var totalDomains, totalUsers, totalBlacklist int
	var totalRequestLogs int64

	if s.sqlStore != nil {
		if rules, err := s.sqlStore.ListDomainRules(ctx); err == nil {
			totalDomains = len(rules)
		}
		if users, err := s.sqlStore.ListUsers(ctx); err == nil {
			totalUsers = len(users)
		}
		if bl, err := s.sqlStore.ListBlacklist(ctx); err == nil {
			totalBlacklist = len(bl)
		}
		if count, err := s.sqlStore.CountRequestLogsCached(ctx); err == nil {
			totalRequestLogs = count
		}
	} else if s.ruleStore != nil {
		rules := s.ruleStore.AllRules()
		totalDomains = len(rules)
	}

	activeConns := 0
	onlineUsers := 0
	s.mu.RLock()
	ct := s.connTracker
	s.mu.RUnlock()
	if ct != nil {
		stats := ct.GetPresenceStats()
		activeConns = stats.ActiveConnections
		onlineUsers = stats.TotalOnline
	}

	uptimeSec := int(time.Since(s.startTime).Seconds())

	var dnsTotals, tlsTotals, httpTotals map[string]int64
	var totalGlobalBytes, totalUserDNS int64
	var tlsSent, tlsRecv int64
	var httpSent, httpRecv int64
	if s.sqlStore != nil {
		sinceDate := parseUsageRange(r)
		dnsTotals, _ = s.sqlStore.GetRequestStatsTotals(ctx, "DNS", sinceDate)
		tlsTotals, _ = s.sqlStore.GetRequestStatsTotals(ctx, "TLS", sinceDate)
		httpTotals, _ = s.sqlStore.GetRequestStatsTotals(ctx, "HTTP", sinceDate)
		globalSent, globalRecv, _ := s.sqlStore.GetGlobalUsageTotals(ctx, sinceDate)
		totalGlobalBytes = globalSent + globalRecv
		totalUserDNS, _ = s.sqlStore.GetGlobalDNSQueriesTotal(ctx, sinceDate)

		tlsSent, tlsRecv, _ = s.sqlStore.GetProtocolUsageTotals(ctx, "TLS", sinceDate)
		httpSent, httpRecv, _ = s.sqlStore.GetProtocolUsageTotals(ctx, "HTTP", sinceDate)
	}

	tlsBytes := tlsSent + tlsRecv
	httpBytes := httpSent + httpRecv

	// If protocol_usage_daily has no records yet (e.g. legacy data before protocol tracking),
	// fallback proportionally based on request counts or attribute to TLS.
	if tlsBytes == 0 && httpBytes == 0 && totalGlobalBytes > 0 {
		tlsBytes = totalGlobalBytes
		httpBytes = 0
	}

	jsonOK(w, map[string]interface{}{
		"active_connections":                    activeConns,
		"online_users":                          onlineUsers,
		"total_domain_rules":                    totalDomains,
		"total_users":                           totalUsers,
		"total_blacklist":                       totalBlacklist,
		"total_request_logs":                    totalRequestLogs,
		"uptime_seconds":                        uptimeSec,
		"dns_requests_total":                    dnsTotals["total"],
		"dns_requests_authorized":               dnsTotals["authorized"],
		"dns_requests_unauthorized_passthrough": dnsTotals["unauthorized_passthrough"],
		"dns_requests_unauthorized_rejected":    dnsTotals["unauthorized_rejected"],
		"dns_requests_blocked":                  dnsTotals["blocked"],
		"user_dns_queries_total":                totalUserDNS,
		"tls_requests_total":                    tlsTotals["total"],
		"tls_requests_registered":               tlsTotals["registered"],
		"tls_requests_unregistered":             tlsTotals["unregistered"],
		"tls_bytes_sent":                        tlsSent,
		"tls_bytes_received":                    tlsRecv,
		"tls_bytes_total":                       tlsBytes,
		"http_requests_total":                   httpTotals["total"],
		"http_requests_registered":              httpTotals["registered"],
		"http_requests_unregistered":            httpTotals["unregistered"],
		"http_bytes_sent":                       httpSent,
		"http_bytes_received":                   httpRecv,
		"http_bytes_total":                      httpBytes,
		"global_bytes_total":                    totalGlobalBytes,
	})
}

func (s *Server) handleGetPresence(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ct := s.connTracker
	s.mu.RUnlock()

	if ct == nil {
		jsonOK(w, map[string]interface{}{
			"total_online":       0,
			"total_offline":      0,
			"total_users":        0,
			"active_connections": 0,
			"users":              []interface{}{},
		})
		return
	}

	stats := ct.GetPresenceStats()
	jsonOK(w, stats)
}

func (s *Server) handleGetRequestStatsDaily(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonOK(w, map[string]interface{}{"days": []sqlitestore.RequestStatDayRow{}})
		return
	}
	reqType := strings.ToUpper(r.URL.Query().Get("type"))
	if reqType != "DNS" && reqType != "TLS" && reqType != "HTTP" {
		reqType = "DNS"
	}
	sinceDate := parseUsageRange(r)
	rows, err := s.sqlStore.GetRequestStatsDaily(r.Context(), reqType, sinceDate)
	if err != nil {
		slog.Error("get request stats daily error", "type", reqType, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.RequestStatDayRow{}
	}
	jsonOK(w, map[string]interface{}{"days": rows})
}

func (s *Server) handleGetGlobalUsageDaily(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	days := parseUsageDays(r)
	sinceDate := time.Now().UTC().AddDate(0, 0, -days)

	rows, err := s.sqlStore.GetGlobalUsageDaily(r.Context(), sinceDate)
	if err != nil {
		slog.Error("admin panel get global usage error", "error", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.GlobalUsageDayRow{}
	}
	jsonOK(w, map[string]interface{}{"days": rows})
}
