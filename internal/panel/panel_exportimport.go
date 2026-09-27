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
	data, err := s.sqlStore.ExportAll(r.Context())
	if err != nil {
		slog.Error("admin panel export error", "error", err)
		jsonErr(w, "export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
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

	// Validate domain rules
	for i, r := range payload.DomainRules {
		domain := strings.TrimSpace(r.Domain)
		if domain == "" {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d]: domain name is required", i), http.StatusBadRequest)
			return
		}
		portsStr := strings.TrimSpace(r.Ports)
		if portsStr == "" {
			portsStr = "443"
		}
		if _, err := rules.ParsePorts(portsStr); err != nil {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d] (%s): invalid ports: %v", i, domain, err), http.StatusBadRequest)
			return
		}
		useProxy := strings.ToLower(strings.TrimSpace(r.UseEgressProxy))
		if useProxy != "" && useProxy != "default" && useProxy != "true" && useProxy != "false" {
			jsonErr(w, fmt.Sprintf("record domain_rules[%d] (%s): invalid use_egress_proxy option %q", i, domain, useProxy), http.StatusBadRequest)
			return
		}
	}

	// Validate blacklist entries
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
	}

	// Validate user entries
	for i, u := range payload.Users {
		username := strings.TrimSpace(u.Username)
		if username == "" {
			jsonErr(w, fmt.Sprintf("record users[%d]: username is required", i), http.StatusBadRequest)
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
	}

	ctx := r.Context()
	result, err := s.sqlStore.ImportData(ctx, payload.DomainRules, payload.Blacklist, payload.Users)
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

	filename := fmt.Sprintf("tls-relay-backup-%s.db", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/x-sqlite3")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	if err := s.sqlStore.BackupToWriter(r.Context(), w); err != nil {
		slog.Error("failed to create sqlite backup", "error", err)
	}
}
