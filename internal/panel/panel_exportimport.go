package panel

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	data, err := s.sqlStore.ExportAll(r.Context())
	if err != nil {
		slog.Error("admin panel export error", "error", err)
		jsonErr(w, "export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="mydns-export.json"`)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	var payload sqlitestore.ExportData
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonErr(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate and normalize domain rules, deduplicating within payload
	var normalizedDomainRules []sqlitestore.DomainRuleRow
	domainIndices := make(map[string]int)

	for i, dr := range payload.DomainRules {
		rawDomain := strings.TrimSpace(dr.Domain)
		if rawDomain == "" {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d]: domain name is required", i), http.StatusBadRequest)
			return
		}
		normDomain, err := rules.NormalizeDomainInput(rawDomain)
		if err != nil {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d] (%s): invalid domain: %v", i, rawDomain, err), http.StatusBadRequest)
			return
		}

		mode, err := rules.NormalizeMode(dr.Mode)
		if err != nil {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d] (%s): invalid mode: %v", i, normDomain, err), http.StatusBadRequest)
			return
		}

		portsStr := strings.TrimSpace(dr.Ports)
		if portsStr == "" {
			portsStr = "443"
		}
		ps, err := rules.ParsePorts(portsStr)
		if err != nil {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d] (%s): invalid ports: %v", i, normDomain, err), http.StatusBadRequest)
			return
		}
		portsJSON := marshalPortsJSON(ps)

		useProxy := strings.ToLower(strings.TrimSpace(dr.UseEgressProxy))
		if useProxy == "" || useProxy == "default" || useProxy == "false" || useProxy == "server" {
			useProxy = "false"
		} else if useProxy == "true" || useProxy == "custom" {
			useProxy = "true"
		} else {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d] (%s): invalid use_egress_proxy option %q", i, normDomain, dr.UseEgressProxy), http.StatusBadRequest)
			return
		}

		groupName := sqlitestore.SanitizeGroupName(dr.GroupName)

		row := sqlitestore.DomainRuleRow{
			Domain:         normDomain,
			GroupName:      groupName,
			Ports:          portsJSON,
			UseEgressProxy: useProxy,
			Mode:           mode,
			Enabled:        dr.Enabled,
		}

		if idx, exists := domainIndices[normDomain]; exists {
			normalizedDomainRules[idx] = row
		} else {
			domainIndices[normDomain] = len(normalizedDomainRules)
			normalizedDomainRules = append(normalizedDomainRules, row)
		}
	}

	// Validate blacklist entries
	var normalizedBlacklist []sqlitestore.BlacklistEntry
	for i, b := range payload.Blacklist {
		entry := strings.TrimSpace(b.Entry)
		if entry == "" {
			jsonErr(w, fmt.Sprintf("record blacklist[%d]: entry is required", i), http.StatusBadRequest)
			return
		}
		if err := validateIPOrCIDR(entry); err != nil {
			jsonErr(w, fmt.Sprintf("record blacklist[%d] (%s): %v", i, entry, err), http.StatusBadRequest)
			return
		}
		normalizedBlacklist = append(normalizedBlacklist, sqlitestore.BlacklistEntry{
			Entry: entry,
		})
	}

	// Validate user entries
	var normalizedUsers []sqlitestore.UserWithIPs
	for i, u := range payload.Users {
		username := strings.TrimSpace(u.Username)
		if username == "" {
			jsonErr(w, fmt.Sprintf("record users[%d]: username is required", i), http.StatusBadRequest)
			return
		}
		if u.MaxIPs < 0 {
			jsonErr(w, fmt.Sprintf("record users[%d] (%s): max_ips cannot be negative", i, username), http.StatusBadRequest)
			return
		}
		if u.MaxIPs > 1000 {
			jsonErr(w, fmt.Sprintf("record users[%d] (%s): max_ips cannot exceed 1000", i, username), http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(u.MagicLink)
		if token != "" && len(token) < 16 {
			jsonErr(w, fmt.Sprintf("record users[%d] (%s): token must be at least 16 characters", i, username), http.StatusBadRequest)
			return
		}

		for j, ip := range u.IPs {
			ipStr := strings.TrimSpace(ip.IPAddress)
			if ipStr != "" {
				if err := validateIPOrCIDR(ipStr); err != nil {
					jsonErr(w, fmt.Sprintf("record users[%d] (%s) IP[%d] (%s): %v", i, username, j, ipStr, err), http.StatusBadRequest)
					return
				}
			}
		}

		userItem := u
		userItem.Username = username
		userItem.MagicLink = token
		normalizedUsers = append(normalizedUsers, userItem)
	}

	ctx := r.Context()
	result, err := s.sqlStore.ImportData(ctx, normalizedDomainRules, normalizedBlacklist, normalizedUsers)
	if err != nil {
		slog.Error("admin panel import error", "error", err)
		jsonErr(w, "import database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.DomainsAdded > 0 || result.DomainsUpdated > 0 {
		_ = s.refreshDomains(ctx)
	}
	if result.BlacklistAdded > 0 || result.BlacklistUpdated > 0 {
		_ = s.refreshBlacklist(ctx)
	}
	if result.UsersAdded > 0 || result.UsersUpdated > 0 {
		_ = s.refreshUserIPs(ctx)
	}

	slog.Info("admin panel import successful",
		"domains_added", result.DomainsAdded,
		"domains_updated", result.DomainsUpdated,
		"blacklist_added", result.BlacklistAdded,
		"blacklist_updated", result.BlacklistUpdated,
		"users_added", result.UsersAdded,
		"users_updated", result.UsersUpdated,
		"remote_addr", r.RemoteAddr,
	)
	jsonOK(w, result)
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "SQLite store unavailable", http.StatusInternalServerError)
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	filename := fmt.Sprintf("tls-relay-backup-%s.db", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/x-sqlite3")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	if err := s.sqlStore.BackupToWriter(r.Context(), w); err != nil {
		slog.Error("failed to create sqlite backup", "error", err)
	}
}
