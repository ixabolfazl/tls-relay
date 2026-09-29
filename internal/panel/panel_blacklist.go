package panel

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func entryContainsIP(entry string, target net.IP) bool {
	if target == nil {
		return false
	}
	if ip := net.ParseIP(entry); ip != nil {
		return ip.Equal(target)
	}
	if _, ipNet, err := net.ParseCIDR(entry); err == nil {
		return ipNet.Contains(target)
	}
	return false
}

func (s *Server) handleListBlacklist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.sqlStore.ListBlacklist(r.Context())
	if err != nil {
		slog.Error("admin panel list blacklist error", "error", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	type blacklistDTO struct {
		ID        int64  `json:"id"`
		Entry     string `json:"entry"`
		CreatedAt string `json:"created_at"`
	}
	out := make([]blacklistDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, blacklistDTO{
			ID:        e.ID,
			Entry:     e.Entry,
			CreatedAt: formatISO8601(e.CreatedAt),
		})
	}
	jsonOK(w, map[string]interface{}{"entries": out})
}

func (s *Server) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entry   string   `json:"entry"`
		Entries []string `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ipList := extractIPEntries(req.Entry, req.Entries)
	if len(ipList) == 0 {
		jsonErr(w, "at least one IP address or CIDR range is required", http.StatusBadRequest)
		return
	}

	clientIPStr := getClientIP(r)
	clientIP := net.ParseIP(clientIPStr)
	relayIPStr := s.RelayIP()
	var relayIP net.IP
	if relayIPStr != "" {
		relayIP = net.ParseIP(relayIPStr)
	}

	for _, entry := range ipList {
		if err := validateIPOrCIDR(entry); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if clientIP != nil && entryContainsIP(entry, clientIP) {
			jsonErr(w, fmt.Sprintf("cannot blacklist requester IP (%s) or range containing it: %s", clientIPStr, entry), http.StatusBadRequest)
			return
		}
		if relayIP != nil && entryContainsIP(entry, relayIP) {
			jsonErr(w, fmt.Sprintf("cannot blacklist server relay IP (%s) or range containing it: %s", relayIPStr, entry), http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()
	for _, entry := range ipList {
		if err := s.sqlStore.AddBlacklistEntry(ctx, entry); err != nil {
			slog.Error("admin panel add blacklist sqlite error", "entry", entry, "error", err)
			jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := s.refreshBlacklist(ctx); err != nil {
		slog.Error("admin panel refresh blacklist error", "error", err)
	}

	slog.Info("admin panel blacklist entry/entries added", "count", len(ipList), "entries", ipList, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]interface{}{"status": "ok", "added": len(ipList)})
}

func (s *Server) handleDeleteBlacklist(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := s.sqlStore.DeleteBlacklistEntry(ctx, id); err != nil {
		slog.Error("admin panel delete blacklist sqlite error", "id", id, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.refreshBlacklist(ctx); err != nil {
		slog.Error("admin panel refresh blacklist error", "error", err)
	}

	slog.Info("admin panel blacklist entry deleted", "id", id, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleBulkDeleteBlacklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	deleted, skipped, err := s.sqlStore.BulkDeleteBlacklist(ctx, req.IDs)
	if err != nil {
		slog.Error("admin panel bulk delete blacklist error", "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if deleted > 0 {
		if err := s.refreshBlacklist(ctx); err != nil {
			slog.Error("admin panel refresh blacklist error", "error", err)
		}
	}

	slog.Info("admin panel bulk delete blacklist", "deleted", deleted, "skipped", skipped, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]int{"deleted": deleted, "updated": 0, "skipped": skipped})
}

func extractIPEntries(rawEntry string, rawEntries []string) []string {
	var list []string
	if rawEntry != "" {
		fields := strings.FieldsFunc(rawEntry, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		})
		for _, f := range fields {
			f = strings.TrimSpace(f)
			if f != "" {
				list = append(list, f)
			}
		}
	}
	for _, e := range rawEntries {
		e = strings.TrimSpace(e)
		if e != "" {
			list = append(list, e)
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
