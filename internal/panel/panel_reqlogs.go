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

	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = l
		}
	}
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = o
		}
	}

	logs, total, err := s.sqlStore.ListRequestLogs(r.Context(), filter)
	if err != nil {
		slog.Error("failed to query request logs", "error", err)
		jsonErr(w, "failed to query request logs", http.StatusInternalServerError)
		return
	}

	type logDTO struct {
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

	jsonOK(w, map[string]interface{}{
		"logs":  dtos,
		"total": total,
	})
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
