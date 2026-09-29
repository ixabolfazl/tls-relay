package panel

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

type domainEntry struct {
	ID                 int64       `json:"id"`
	Domain             string      `json:"domain"`
	GroupName          string      `json:"group_name"`
	Ports              interface{} `json:"ports"` // []int or "all"
	UseEgressProxy     string      `json:"use_egress_proxy"`
	Mode               string      `json:"mode"`
	TotalBytesSent     int64       `json:"total_bytes_sent"`
	TotalBytesReceived int64       `json:"total_bytes_received"`
	TotalDNSQueries    int64       `json:"total_dns_queries"`
	CreatedAt          string      `json:"created_at"`
	UpdatedAt          string      `json:"updated_at"`
}

func ruleToDomainEntry(domain string, rule rules.DomainRule) domainEntry {
	e := domainEntry{
		Domain:    domain,
		GroupName: rule.GroupName,
		Mode:      rule.Mode,
	}
	if e.Mode == "" {
		e.Mode = "proxy"
	}
	if rule.Ports.All {
		e.Ports = "all"
	} else {
		e.Ports = rule.Ports.Ports
	}
	e.UseEgressProxy = rule.UseEgressProxy
	if e.UseEgressProxy == "" || e.UseEgressProxy == "default" {
		e.UseEgressProxy = "false"
	}
	return e
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	sinceDate := parseUsageRange(r)
	if s.sqlStore != nil {
		usageMap, _ := s.sqlStore.ListDomainsTotalUsage(r.Context(), sinceDate)
		dnsMap, _ := s.sqlStore.ListDomainsDNSTotals(r.Context(), sinceDate)
		rules, err := s.sqlStore.ListDomainRules(r.Context())
		if err == nil {
			entries := make([]domainEntry, 0, len(rules))
			for _, rRow := range rules {
				var portsVal interface{}
				if rRow.Ports == `"all"` || rRow.Ports == "all" {
					portsVal = "all"
				} else {
					var pList []int
					if err := json.Unmarshal([]byte(rRow.Ports), &pList); err == nil {
						portsVal = pList
					} else {
						portsVal = []int{443}
					}
				}
				proxyVal := rRow.UseEgressProxy
				if proxyVal == "" || proxyVal == "default" {
					proxyVal = "false"
				}
				modeVal := rRow.Mode
				if modeVal == "" {
					modeVal = "proxy"
				}
				u := usageMap[rRow.Domain]
				entries = append(entries, domainEntry{
					ID:                 rRow.ID,
					Domain:             rRow.Domain,
					GroupName:          rRow.GroupName,
					Ports:              portsVal,
					UseEgressProxy:     proxyVal,
					Mode:               modeVal,
					TotalBytesSent:     u.BytesSent,
					TotalBytesReceived: u.BytesReceived,
					TotalDNSQueries:    dnsMap[rRow.Domain],
					CreatedAt:          formatISO8601(rRow.CreatedAt),
					UpdatedAt:          formatISO8601(rRow.UpdatedAt),
				})
			}
			jsonOK(w, map[string]interface{}{"domains": entries})
			return
		}
	}

	var usageMap map[string]sqlitestore.DomainUsageTotal
	var dnsMap map[string]int64
	if s.sqlStore != nil {
		usageMap, _ = s.sqlStore.ListDomainsTotalUsage(r.Context(), sinceDate)
		dnsMap, _ = s.sqlStore.ListDomainsDNSTotals(r.Context(), sinceDate)
	}
	all := s.ruleStore.AllRules()
	entries := make([]domainEntry, 0, len(all))
	for domain, rule := range all {
		e := ruleToDomainEntry(domain, rule)
		if u, ok := usageMap[domain]; ok {
			e.TotalBytesSent = u.BytesSent
			e.TotalBytesReceived = u.BytesReceived
		}
		if dnsMap != nil {
			e.TotalDNSQueries = dnsMap[domain]
		}
		entries = append(entries, e)
	}
	jsonOK(w, map[string]interface{}{"domains": entries})
}

func parseDomainParam(r *http.Request) string {
	raw := r.PathValue("domain")
	decoded, err := url.PathUnescape(raw)
	if err == nil && decoded != "" {
		return decoded
	}
	return raw
}

func (s *Server) handleGetDomainUsage(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonOK(w, map[string]interface{}{
			"days":              []sqlitestore.DomainUsageDayRow{},
			"dns_days":          []sqlitestore.DomainDNSUsageDayRow{},
			"total_dns_queries": 0,
		})
		return
	}
	domain := parseDomainParam(r)
	sinceDate := parseUsageRange(r)
	if r.URL.Query().Get("range") == "" && r.URL.Query().Get("days") == "" {
		sinceDate = time.Now().UTC().AddDate(0, 0, -30)
	}
	rows, err := s.sqlStore.GetDomainUsageDaily(r.Context(), domain, sinceDate)
	if err != nil {
		slog.Error("get domain usage daily error", "domain", domain, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.DomainUsageDayRow{}
	}

	dnsRows, err := s.sqlStore.GetDomainDNSUsageDaily(r.Context(), domain, sinceDate)
	if err != nil {
		slog.Error("get domain dns usage daily error", "domain", domain, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if dnsRows == nil {
		dnsRows = []sqlitestore.DomainDNSUsageDayRow{}
	}

	var totalDNS int64
	for _, dr := range dnsRows {
		totalDNS += dr.QueryCount
	}

	dayMap := make(map[string]int, len(rows))
	for i, r := range rows {
		dayMap[r.Date] = i
	}
	for _, dr := range dnsRows {
		if idx, ok := dayMap[dr.Date]; ok {
			rows[idx].DNSQueries = dr.QueryCount
		} else {
			rows = append(rows, sqlitestore.DomainUsageDayRow{
				Date:       dr.Date,
				DNSQueries: dr.QueryCount,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Date < rows[j].Date
	})

	jsonOK(w, map[string]interface{}{
		"days":              rows,
		"dns_days":          dnsRows,
		"total_dns_queries": totalDNS,
	})
}

func (s *Server) handleGetDomainUsageMonthly(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonOK(w, map[string]interface{}{"months": []sqlitestore.DomainUsageMonthRow{}})
		return
	}
	domain := parseDomainParam(r)
	months := 12
	if monthsStr := r.URL.Query().Get("months"); monthsStr != "" {
		if m, err := strconv.Atoi(monthsStr); err == nil && m > 0 {
			months = m
		}
	}
	if months > 36 {
		months = 36
	}
	sinceDate := time.Now().UTC().AddDate(0, -months, 0)
	rows, err := s.sqlStore.GetDomainUsageMonthly(r.Context(), domain, sinceDate)
	if err != nil {
		slog.Error("get domain usage monthly error", "domain", domain, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.DomainUsageMonthRow{}
	}
	jsonOK(w, map[string]interface{}{"months": rows})
}

func (s *Server) handleGetDomainUsageUsers(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonOK(w, map[string]interface{}{"users": []sqlitestore.DomainUserTotalRow{}})
		return
	}
	domain := parseDomainParam(r)
	sinceDate := parseUsageRange(r)
	rows, err := s.sqlStore.ListDomainUsageByUser(r.Context(), domain, sinceDate)
	if err != nil {
		slog.Error("list domain usage by user error", "domain", domain, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.DomainUserTotalRow{}
	}
	jsonOK(w, map[string]interface{}{"users": rows})
}

// DomainParseError represents an error that occurred while parsing a domain name input.
type DomainParseError struct {
	Input  string `json:"input"`
	Reason string `json:"reason"`
}

type addDomainRequest struct {
	Domain            string   `json:"domain"`  // Single or multi-line string
	Domains           []string `json:"domains"` // Slice of domains
	GroupName         string   `json:"group_name"`
	Ports             string   `json:"ports"` // Default "443"
	UseEgressProxy    string   `json:"use_egress_proxy"`
	Mode              string   `json:"mode"`
	IncludeSubdomains bool     `json:"include_subdomains"` // If true, also create *.domain for apex domains
}

func extractDomains(rawDomain string, rawDomains []string) []string {
	var list []string
	if rawDomain != "" {
		fields := strings.FieldsFunc(rawDomain, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		})
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if f != "" {
				list = append(list, f)
			}
		}
	}
	for _, d := range rawDomains {
		d = strings.TrimSpace(d)
		if d != "" {
			list = append(list, d)
		}
	}
	seen := make(map[string]bool)
	var result []string
	for _, item := range list {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func normalizeAndExtractDomains(rawDomain string, rawDomains []string) ([]string, []DomainParseError) {
	rawTokens := extractDomains(rawDomain, rawDomains)
	var valid []string
	var errs []DomainParseError
	seen := make(map[string]bool)

	for _, token := range rawTokens {
		norm, err := rules.NormalizeDomainInput(token)
		if err != nil {
			errs = append(errs, DomainParseError{Input: token, Reason: err.Error()})
			continue
		}
		if !seen[norm] {
			seen[norm] = true
			valid = append(valid, norm)
		}
	}
	return valid, errs
}

func (s *Server) handleAddDomain(w http.ResponseWriter, r *http.Request) {
	var req addDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("admin panel add domain request invalid body", "remote_addr", r.RemoteAddr, "error", err)
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	rawTokens := extractDomains(req.Domain, req.Domains)
	if len(rawTokens) == 0 {
		jsonErr(w, "at least one domain is required", http.StatusBadRequest)
		return
	}

	normalizedDomains, parseErrors := normalizeAndExtractDomains(req.Domain, req.Domains)
	if len(normalizedDomains) == 0 && len(parseErrors) > 0 {
		// All tokens failed normalization/validation
		jsonOK(w, map[string]interface{}{
			"added":   0,
			"updated": 0,
			"skipped": len(parseErrors),
			"errors":  parseErrors,
		})
		return
	}

	portsStr := strings.TrimSpace(req.Ports)
	if portsStr == "" {
		portsStr = "443" // Default port is 443
	}

	ps, err := rules.ParsePorts(portsStr)
	if err != nil {
		slog.Warn("admin panel add domain invalid ports", "ports", portsStr, "remote_addr", r.RemoteAddr, "error", err)
		jsonErr(w, "invalid ports: "+err.Error(), http.StatusBadRequest)
		return
	}

	useEgress := strings.ToLower(strings.TrimSpace(req.UseEgressProxy))
	if useEgress == "" || useEgress == "default" || useEgress == "false" || useEgress == "server" {
		useEgress = "false"
	} else if useEgress == "true" || useEgress == "custom" {
		useEgress = "true"
	} else {
		jsonErr(w, "invalid use_egress_proxy option", http.StatusBadRequest)
		return
	}

	mode, err := rules.NormalizeMode(req.Mode)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Expand apex domains to include *.domain wildcard if requested
	var targetDomains []string
	seenTarget := make(map[string]bool)
	for _, d := range normalizedDomains {
		if !seenTarget[d] {
			seenTarget[d] = true
			targetDomains = append(targetDomains, d)
		}
		if req.IncludeSubdomains && !strings.HasPrefix(d, "*.") {
			wc := "*." + d
			if !seenTarget[wc] {
				seenTarget[wc] = true
				targetDomains = append(targetDomains, wc)
			}
		}
	}

	// Marshal ports to JSON for SQLite storage.
	portsJSON := marshalPortsJSON(ps)

	ctx := r.Context()
	addedCount := 0
	updatedCount := 0

	for _, d := range targetDomains {
		existing, _ := s.sqlStore.GetDomainRule(ctx, d)
		if err := s.sqlStore.AddDomainRule(ctx, d, req.GroupName, portsJSON, useEgress, mode); err != nil {
			slog.Error("admin panel add domain sqlite error", "domain", d, "error", err)
			jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if existing != nil {
			updatedCount++
		} else {
			addedCount++
		}
	}

	// Refresh Redis cache + in-memory snapshot.
	if err := s.refreshDomains(ctx); err != nil {
		slog.Error("admin panel refresh domains error", "error", err)
	}

	if parseErrors == nil {
		parseErrors = []DomainParseError{}
	}

	slog.Info("admin panel domain rule(s) processed",
		"added", addedCount, "updated", updatedCount, "skipped", len(parseErrors),
		"domains", targetDomains, "ports", portsStr, "use_egress_proxy", useEgress, "remote_addr", r.RemoteAddr)

	jsonOK(w, map[string]interface{}{
		"status":  "ok",
		"added":   addedCount,
		"updated": updatedCount,
		"skipped": len(parseErrors),
		"errors":  parseErrors,
	})
}

type updateDomainRequest struct {
	GroupName                 string `json:"group_name"`
	Ports                     string `json:"ports"`
	UseEgressProxy            string `json:"use_egress_proxy"`
	Mode                      string `json:"mode"`
	IncludeSubdomains         *bool  `json:"include_subdomains,omitempty"`
	DeleteWildcardCounterpart bool   `json:"delete_wildcard_counterpart,omitempty"`
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	var req updateDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	portsStr := strings.TrimSpace(req.Ports)
	if portsStr == "" {
		portsStr = "443"
	}

	ps, err := rules.ParsePorts(portsStr)
	if err != nil {
		jsonErr(w, "invalid ports: "+err.Error(), http.StatusBadRequest)
		return
	}

	useEgress := strings.ToLower(strings.TrimSpace(req.UseEgressProxy))
	if useEgress == "" || useEgress == "default" || useEgress == "false" || useEgress == "server" {
		useEgress = "false"
	} else if useEgress == "true" || useEgress == "custom" {
		useEgress = "true"
	} else {
		jsonErr(w, "invalid use_egress_proxy option", http.StatusBadRequest)
		return
	}

	mode, err := rules.NormalizeMode(req.Mode)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	portsJSON := marshalPortsJSON(ps)

	ctx := r.Context()
	if s.sqlStore == nil {
		jsonErr(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	existing, err := s.sqlStore.GetDomainRule(ctx, domain)
	if err != nil || existing == nil {
		jsonErr(w, "domain rule not found", http.StatusNotFound)
		return
	}

	// Update primary domain rule
	if err := s.sqlStore.UpdateDomainRule(ctx, domain, req.GroupName, portsJSON, useEgress, mode); err != nil {
		slog.Error("admin panel update domain error", "domain", domain, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Subdomain checkbox logic on edit
	if !strings.HasPrefix(domain, "*.") && req.IncludeSubdomains != nil {
		wildcardDomain := "*." + domain
		if *req.IncludeSubdomains {
			// Add / update matching wildcard rule
			if err := s.sqlStore.AddDomainRule(ctx, wildcardDomain, req.GroupName, portsJSON, useEgress, mode); err != nil {
				slog.Error("admin panel add wildcard counterpart error", "domain", wildcardDomain, "error", err)
			}
		} else if req.DeleteWildcardCounterpart {
			// Safely delete matching wildcard rule
			if err := s.sqlStore.DeleteDomainRule(ctx, wildcardDomain); err != nil {
				slog.Error("admin panel delete wildcard counterpart error", "domain", wildcardDomain, "error", err)
			}
		}
	}

	if err := s.refreshDomains(ctx); err != nil {
		slog.Error("admin panel refresh domains error", "error", err)
	}

	slog.Info("admin panel domain rule updated", "domain", domain, "ports", portsStr, "use_egress_proxy", useEgress, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	ctx := r.Context()

	if err := s.sqlStore.DeleteDomainRule(ctx, domain); err != nil {
		slog.Error("admin panel delete domain sqlite error", "domain", domain, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.refreshDomains(ctx); err != nil {
		slog.Error("admin panel refresh domains error", "error", err)
	}

	slog.Info("admin panel domain rule deleted", "domain", domain, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleBulkDeleteDomains(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	deleted, skipped, err := s.sqlStore.BulkDeleteDomainRules(ctx, req.Domains)
	if err != nil {
		slog.Error("admin panel bulk delete domains error", "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if deleted > 0 {
		if err := s.refreshDomains(ctx); err != nil {
			slog.Error("admin panel refresh domains error", "error", err)
		}
	}

	slog.Info("admin panel bulk delete domains", "deleted", deleted, "skipped", skipped, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]int{"deleted": deleted, "updated": 0, "skipped": skipped})
}

func (s *Server) handleBulkAssignGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains   []string `json:"domains"`
		GroupName string   `json:"group_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	updated, skipped, err := s.sqlStore.BulkAssignDomainGroup(ctx, req.Domains, req.GroupName)
	if err != nil {
		slog.Error("admin panel bulk assign group error", "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if updated > 0 {
		if err := s.refreshDomains(ctx); err != nil {
			slog.Error("admin panel refresh domains error", "error", err)
		}
	}

	slog.Info("admin panel bulk assign group", "group_name", req.GroupName, "updated", updated, "skipped", skipped, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]int{"deleted": 0, "updated": updated, "skipped": skipped})
}

func (s *Server) handleBulkAssignEgress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains        []string `json:"domains"`
		UseEgressProxy string   `json:"use_egress_proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	useEgress := strings.ToLower(strings.TrimSpace(req.UseEgressProxy))
	if useEgress == "" || useEgress == "default" || useEgress == "false" || useEgress == "server" {
		useEgress = "false"
	} else if useEgress == "true" || useEgress == "custom" {
		useEgress = "true"
	} else {
		jsonErr(w, "invalid use_egress_proxy option", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	updated, skipped, err := s.sqlStore.BulkAssignDomainEgress(ctx, req.Domains, useEgress)
	if err != nil {
		slog.Error("admin panel bulk assign egress error", "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if updated > 0 {
		if err := s.refreshDomains(ctx); err != nil {
			slog.Error("admin panel refresh domains error", "error", err)
		}
	}

	slog.Info("admin panel bulk assign egress", "use_egress_proxy", useEgress, "updated", updated, "skipped", skipped, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]int{"deleted": 0, "updated": updated, "skipped": skipped})
}

func (s *Server) handleBulkAssignMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domains []string `json:"domains"`
		Mode    string   `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	mode, err := rules.NormalizeMode(req.Mode)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	updated, skipped, err := s.sqlStore.BulkAssignDomainMode(ctx, req.Domains, mode)
	if err != nil {
		slog.Error("admin panel bulk assign mode error", "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if updated > 0 {
		if err := s.refreshDomains(ctx); err != nil {
			slog.Error("admin panel refresh domains error", "error", err)
		}
	}

	slog.Info("admin panel bulk assign mode", "mode", mode, "updated", updated, "skipped", skipped, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]int{"deleted": 0, "updated": updated, "skipped": skipped})
}
