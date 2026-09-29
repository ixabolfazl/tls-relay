package panel

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func (s *Server) handleListRequestLogs(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "database unavailable", http.StatusInternalServerError)
		return
	}

	query := r.URL.Query()
	filter := sqlitestore.RequestLogFilter{
		Domain:      query.Get("domain"),
		ClientIP:    query.Get("client_ip"),
		Username:    query.Get("username"),
		RequestType: query.Get("request_type"),
	}

	if userIDStr := query.Get("user_id"); userIDStr != "" {
		if uid, err := strconv.ParseInt(userIDStr, 10, 64); err == nil {
			filter.UserID = &uid
		}
	}

	if sinceStr := query.Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			filter.Since = &t
		}
	}

	if untilStr := query.Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			filter.Until = &t
		}
	}

	if beforeIDStr := query.Get("before_id"); beforeIDStr != "" {
		if bid, err := strconv.ParseInt(beforeIDStr, 10, 64); err == nil && bid > 0 {
			filter.BeforeID = &bid
		}
	}

	// Default time window: when neither since nor cursor is given, restrict to last 24 hours.
	if filter.Since == nil && filter.BeforeID == nil {
		defaultSince := time.Now().UTC().Add(-24 * time.Hour)
		filter.Since = &defaultSince
	}

	limit := 50
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 500 {
		limit = 500
	}
	filter.Limit = limit + 1

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	logs, _, err := s.sqlStore.ListRequestLogs(r.Context(), filter)
	if err != nil {
		slog.Error("failed to query request logs", "error", err)
		jsonErr(w, "failed to query request logs", http.StatusInternalServerError)
		return
	}

	hasMore := len(logs) > limit
	if hasMore {
		logs = logs[:limit]
	}

	var nextBeforeID int64
	if len(logs) > 0 {
		nextBeforeID = logs[len(logs)-1].ID
	}

	type logDTO struct {
		ID          int64  `json:"id"`
		UserID      int64  `json:"user_id"`
		Username    string `json:"username"`
		ClientIP    string `json:"client_ip"`
		RequestType string `json:"request_type"`
		Domain      string `json:"domain"`
		Port        int    `json:"port"`
		Status      string `json:"status"`
		Timestamp   string `json:"timestamp"`
	}

	dtos := make([]logDTO, 0, len(logs))
	for _, l := range logs {
		dtos = append(dtos, logDTO{
			ID:          l.ID,
			UserID:      l.UserID,
			Username:    l.Username,
			ClientIP:    l.ClientIP,
			RequestType: string(l.RequestType),
			Domain:      l.Domain,
			Port:        l.Port,
			Status:      l.Status,
			Timestamp:   l.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	hasUserFilters := query.Get("domain") != "" ||
		query.Get("client_ip") != "" ||
		query.Get("username") != "" ||
		query.Get("user_id") != "" ||
		query.Get("request_type") != "" ||
		query.Get("since") != "" ||
		query.Get("until") != "" ||
		query.Get("before_id") != ""

	resp := map[string]interface{}{
		"logs":           dtos,
		"next_before_id": nextBeforeID,
		"has_more":       hasMore,
	}

	if !hasUserFilters {
		if total, err := s.sqlStore.CountRequestLogsCached(r.Context()); err == nil {
			resp["total"] = total
		}
	}

	jsonOK(w, resp)
}

func (s *Server) handleClearRequestLogs(w http.ResponseWriter, r *http.Request) {
	if s.sqlStore == nil {
		jsonErr(w, "database unavailable", http.StatusInternalServerError)
		return
	}

	if err := s.sqlStore.ClearAllRequestLogs(r.Context()); err != nil {
		slog.Error("failed to clear request logs", "error", err)
		jsonErr(w, "failed to clear request logs", http.StatusInternalServerError)
		return
	}

	slog.Info("request logs cleared via admin panel", "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}
