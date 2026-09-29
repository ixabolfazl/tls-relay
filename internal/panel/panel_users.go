package panel

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := s.sqlStore.ListUsers(ctx)
	if err != nil {
		slog.Error("admin panel list users error", "error", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}

	sinceDate := parseUsageRange(r)

	// Load total usage for all users in one query.
	usageTotals := make(map[int64]struct {
		Sent     int64
		Received int64
	})
	if s.sqlStore != nil {
		if totals, err := s.sqlStore.GetUsersTotalUsage(ctx, sinceDate); err == nil {
			usageTotals = totals
		}
	}

	presenceMap := make(map[int64]string)
	if s.connTracker != nil {
		stats := s.connTracker.GetPresenceStats()
		for _, pu := range stats.Users {
			if pu.LastSeenAt != "" {
				presenceMap[pu.UserID] = pu.LastSeenAt
			}
		}
	}

	dnsTotals := make(map[int64]int64)
	if s.sqlStore != nil {
		if dt, err := s.sqlStore.GetAllUsersDNSTotals(ctx, sinceDate); err == nil {
			dnsTotals = dt
		}
	}

	type userDTO struct {
		ID                 int64  `json:"id"`
		Username           string `json:"username"`
		Enabled            bool   `json:"enabled"`
		MagicLink          string `json:"magic_link"`
		MaxIPs             int    `json:"max_ips"`
		CreatedAt          string `json:"created_at"`
		UpdatedAt          string `json:"updated_at"`
		LastSeenAt         string `json:"last_seen_at"`
		TotalBytesSent     int64  `json:"total_bytes_sent"`
		TotalBytesReceived int64  `json:"total_bytes_received"`
		TotalDNSQueries    int64  `json:"total_dns_queries"`
	}
	out := make([]userDTO, 0, len(users))
	for _, u := range users {
		lastSeen := u.LastSeenAt
		if liveLastSeen, ok := presenceMap[u.ID]; ok && liveLastSeen != "" {
			if lastSeen == "" || liveLastSeen > lastSeen {
				lastSeen = liveLastSeen
			}
		}

		utot := usageTotals[u.ID]
		out = append(out, userDTO{
			ID:                 u.ID,
			Username:           u.Username,
			Enabled:            u.Enabled,
			MagicLink:          u.MagicLink,
			MaxIPs:             u.MaxIPs,
			CreatedAt:          formatISO8601(u.CreatedAt),
			UpdatedAt:          formatISO8601(u.UpdatedAt),
			LastSeenAt:         formatISO8601(lastSeen),
			TotalBytesSent:     utot.Sent,
			TotalBytesReceived: utot.Received,
			TotalDNSQueries:    dnsTotals[u.ID],
		})
	}
	jsonOK(w, map[string]interface{}{"users": out})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		MaxIPs    *int   `json:"max_ips"`
		MagicLink string `json:"magic_link"`
		Token     string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		jsonErr(w, "username is required", http.StatusBadRequest)
		return
	}

	maxIPs := s.DefaultMaxIPs()
	if req.MaxIPs != nil {
		if *req.MaxIPs < 0 {
			jsonErr(w, "max_ips cannot be negative", http.StatusBadRequest)
			return
		}
		if *req.MaxIPs > 1000 {
			jsonErr(w, "max_ips cannot exceed 1000", http.StatusBadRequest)
			return
		}
		maxIPs = *req.MaxIPs
	}

	magicLink := strings.TrimSpace(req.MagicLink)
	if magicLink == "" && req.Token != "" {
		magicLink = strings.TrimSpace(req.Token)
	}
	if magicLink != "" && len(magicLink) < 16 {
		jsonErr(w, "magic link token must be at least 16 characters", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user, err := s.sqlStore.CreateUserWithLink(ctx, username, maxIPs, magicLink)
	if err != nil {
		slog.Error("admin panel create user error", "username", username, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin panel user created", "user_id", user.ID, "username", username, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]interface{}{"status": "ok", "user": user})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req struct {
		Username  *string `json:"username"`
		Enabled   *bool   `json:"enabled"`
		MaxIPs    *int    `json:"max_ips"`
		MagicLink *string `json:"magic_link"`
		Token     *string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Fetch current user to merge partial updates.
	current, err := s.sqlStore.GetUser(ctx, id)
	if err != nil {
		jsonErr(w, "user not found", http.StatusNotFound)
		return
	}

	username := current.Username
	enabled := current.Enabled
	maxIPs := current.MaxIPs
	magicLink := current.MagicLink

	if req.Username != nil && strings.TrimSpace(*req.Username) != "" {
		username = strings.TrimSpace(*req.Username)
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.MaxIPs != nil {
		if *req.MaxIPs < 0 {
			jsonErr(w, "max_ips cannot be negative", http.StatusBadRequest)
			return
		}
		if *req.MaxIPs > 1000 {
			jsonErr(w, "max_ips cannot exceed 1000", http.StatusBadRequest)
			return
		}
		maxIPs = *req.MaxIPs
	}
	newLink := req.MagicLink
	if newLink == nil && req.Token != nil {
		newLink = req.Token
	}
	if newLink != nil && strings.TrimSpace(*newLink) != "" {
		m := strings.TrimSpace(*newLink)
		if len(m) < 16 {
			jsonErr(w, "magic link token must be at least 16 characters", http.StatusBadRequest)
			return
		}
		magicLink = m
	}

	if err := s.sqlStore.UpdateUserFull(ctx, id, username, enabled, maxIPs, magicLink); err != nil {
		slog.Error("admin panel update user error", "user_id", id, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Refresh user IPs (enabled status may have changed).
	if err := s.refreshUserIPs(ctx); err != nil {
		slog.Error("admin panel refresh user IPs error", "error", err)
	}

	slog.Info("admin panel user updated", "user_id", id, "username", username, "enabled", enabled, "max_ips", maxIPs, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := s.sqlStore.DeleteUser(ctx, id); err != nil {
		slog.Error("admin panel delete user error", "user_id", id, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Refresh user IPs (user's IPs were cascade-deleted).
	if err := s.refreshUserIPs(ctx); err != nil {
		slog.Error("admin panel refresh user IPs error", "error", err)
	}

	slog.Info("admin panel user deleted", "user_id", id, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleListUserIPs(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	ips, err := s.sqlStore.ListUserIPs(r.Context(), id)
	if err != nil {
		slog.Error("admin panel list user IPs error", "user_id", id, "error", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	type userIPDTO struct {
		ID         int64  `json:"id"`
		UserID     int64  `json:"user_id"`
		IPAddress  string `json:"ip_address"`
		CreatedAt  string `json:"created_at"`
		LastUsedAt string `json:"last_used_at"`
	}
	out := make([]userIPDTO, 0, len(ips))
	for _, ip := range ips {
		out = append(out, userIPDTO{
			ID:         ip.ID,
			UserID:     ip.UserID,
			IPAddress:  ip.IPAddress,
			CreatedAt:  formatISO8601(ip.CreatedAt),
			LastUsedAt: formatISO8601(ip.LastUsedAt),
		})
	}
	jsonOK(w, map[string]interface{}{"ips": out})
}

func (s *Server) handleDeleteUserIP(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	ipRaw := r.PathValue("ip")
	ip, err := url.PathUnescape(ipRaw)
	if err != nil || ip == "" {
		ip = ipRaw
	}
	if ip == "" {
		jsonErr(w, "ip is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := s.sqlStore.DeleteUserIP(ctx, id, ip); err != nil {
		slog.Error("admin panel delete user IP error", "user_id", id, "ip", ip, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.refreshUserIPs(ctx); err != nil {
		slog.Error("admin panel refresh user IPs error", "error", err)
	}

	slog.Info("admin panel user IP deleted", "user_id", id, "ip", ip, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleResetMagicLink(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req struct {
		ClearIPs bool `json:"clear_ips"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	ctx := r.Context()
	link, err := s.sqlStore.ResetMagicLink(ctx, id)
	if err != nil {
		slog.Error("admin panel reset magic link error", "user_id", id, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var clearedCount int
	if req.ClearIPs {
		clearedCount, err = s.sqlStore.DeleteAllUserIPs(ctx, id)
		if err != nil {
			slog.Error("admin panel clear user IPs error", "user_id", id, "error", err)
			jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.refreshUserIPs(ctx); err != nil {
			slog.Error("admin panel refresh user IPs error", "error", err)
		}
	}

	slog.Info("admin panel magic link reset", "user_id", id, "clear_ips", req.ClearIPs, "cleared_ips", clearedCount, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]interface{}{
		"status":      "ok",
		"magic_link":  link,
		"cleared_ips": clearedCount,
	})
}

func (s *Server) handleNewMagicLink(w http.ResponseWriter, r *http.Request) {
	// Same as reset.
	s.handleResetMagicLink(w, r)
}

// parseUsageDays extracts and validates the ?days=N query parameter.
// Default is 30, max is 365.
func parseUsageDays(r *http.Request) int {
	n := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > 365 {
		n = 365
	}
	return n
}

func parseUsageRange(r *http.Request) time.Time {
	now := time.Now().UTC()
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = r.URL.Query().Get("days")
	}
	switch rng {
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	case "7d", "7":
		return now.AddDate(0, 0, -7)
	case "30d", "30":
		return now.AddDate(0, 0, -30)
	case "monthly", "90d", "90", "365":
		return now.AddDate(0, 0, -365)
	case "all":
		return time.Time{}
	default:
		if d, err := strconv.Atoi(rng); err == nil && d > 0 {
			return now.AddDate(0, 0, -d)
		}
		return time.Time{}
	}
}

func (s *Server) handleGetUserUsage(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}
	sinceDate := parseUsageRange(r)

	rows, err := s.sqlStore.GetUserUsageDaily(r.Context(), id, sinceDate)
	if err != nil {
		slog.Error("admin panel get user usage error", "user_id", id, "error", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.UserUsageDayRow{}
	}

	dnsTotal, _ := s.sqlStore.GetUserDNSUsageTotal(r.Context(), id, sinceDate)
	dnsDaily, _ := s.sqlStore.GetUserDNSUsageDaily(r.Context(), id, sinceDate)
	if dnsDaily == nil {
		dnsDaily = []sqlitestore.UserDNSUsageDayRow{}
	}

	jsonOK(w, map[string]interface{}{
		"days":              rows,
		"total_dns_queries": dnsTotal,
		"dns_days":          dnsDaily,
	})
}

func (s *Server) handleResetUserUsage(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := s.sqlStore.ResetUserUsage(r.Context(), id); err != nil {
		slog.Error("admin panel reset user usage error", "user_id", id, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("admin panel user usage reset", "user_id", id, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleGetUserUsageDomains(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonOK(w, map[string]interface{}{"domains": []sqlitestore.UserDomainTotalRow{}})
		return
	}
	idStr := r.PathValue("id")
	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid user id", http.StatusBadRequest)
		return
	}
	sinceDate := parseUsageRange(r)
	rows, err := s.sqlStore.ListUserUsageByDomain(r.Context(), userID, sinceDate)
	if err != nil {
		slog.Error("list user usage by domain error", "user_id", userID, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []sqlitestore.UserDomainTotalRow{}
	}
	jsonOK(w, map[string]interface{}{"domains": rows})
}

func (s *Server) handleAddUserIP(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ipStr := strings.TrimSpace(req.IP)
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		jsonErr(w, "invalid IP address", http.StatusBadRequest)
		return
	}
	if s.accessStore != nil && s.accessStore.IsBlacklisted(parsedIP) {
		jsonErr(w, "cannot add IP: address is in the global blacklist", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	user, err := s.sqlStore.GetUser(ctx, id)
	if err != nil {
		jsonErr(w, "user not found", http.StatusNotFound)
		return
	}

	if err := s.sqlStore.RegisterIP(ctx, id, ipStr, user.MaxIPs); err != nil {
		slog.Error("admin panel add user IP error", "user_id", id, "ip", ipStr, "error", err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.refreshUserIPs(ctx); err != nil {
		slog.Error("admin panel refresh user IPs error", "error", err)
	}

	slog.Info("admin panel manual user IP added", "user_id", id, "ip", ipStr, "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}
