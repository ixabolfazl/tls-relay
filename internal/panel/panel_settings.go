package panel

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
)

type settingsResponse struct {
	AccessMode                 string `json:"access_mode"`
	PanelPath                  string `json:"panel_path"`
	Timezone                   string `json:"timezone"`
	UnknownDomainPolicy        string `json:"unknown_domain_policy"`
	ServerDomain               string `json:"server_domain"`
	PanelAddr                  string `json:"panel_addr"`
	RequestLogsEnabled         bool   `json:"request_logs_enabled"`
	RequestLogsRetention       string `json:"request_logs_retention"`
	MaxConnectionsPerIP        int    `json:"max_connections_per_ip"`
	DNSUnauthorizedPassthrough bool   `json:"dns_unauthorized_passthrough"`
}

func parseDurationWithDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") || strings.HasSuffix(s, "D") {
		numStr := s[:len(s)-1]
		days, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days format %q: %w", s, err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if dur <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return dur, nil
}

func formatDurationClean(d time.Duration) string {
	if d <= 0 {
		return "24h"
	}
	if d%(24*time.Hour) == 0 && d >= 24*time.Hour {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func (s *Server) currentSettings() settingsResponse {
	mode := "user"
	if s.accessStore != nil {
		mode = string(s.accessStore.Mode())
	}

	policy := "allow_default_port"
	if s.ruleStore != nil {
		policy = s.ruleStore.UnknownDomainPolicy()
	}

	reqEnabled := true
	reqRetention := "24h"
	maxConn := 200
	dnsPassthrough := false
	s.mu.RLock()
	if s.reqLogger != nil {
		reqEnabled = s.reqLogger.IsEnabled()
		reqRetention = formatDurationClean(s.reqLogger.Retention())
	}
	if s.limits != nil {
		maxConn = s.limits.MaxPerIP()
	}
	if s.dnsServer != nil {
		dnsPassthrough = s.dnsServer.UnauthorizedPassthroughEnabled()
	}
	s.mu.RUnlock()

	return settingsResponse{
		AccessMode:                 mode,
		PanelPath:                  s.DisplayPath(),
		Timezone:                   s.Timezone(),
		UnknownDomainPolicy:        policy,
		ServerDomain:               s.ServerDomain(),
		PanelAddr:                  s.Addr(),
		RequestLogsEnabled:         reqEnabled,
		RequestLogsRetention:       reqRetention,
		MaxConnectionsPerIP:        maxConn,
		DNSUnauthorizedPassthrough: dnsPassthrough,
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.currentSettings())
}

type updateSettingsRequest struct {
	AccessMode                 *string `json:"access_mode,omitempty"`
	PanelPath                  *string `json:"panel_path,omitempty"`
	Timezone                   *string `json:"timezone,omitempty"`
	UnknownDomainPolicy        *string `json:"unknown_domain_policy,omitempty"`
	ServerDomain               *string `json:"server_domain,omitempty"`
	RequestLogsEnabled         *bool   `json:"request_logs_enabled,omitempty"`
	RequestLogsRetention       *string `json:"request_logs_retention,omitempty"`
	MaxConnectionsPerIP        *int    `json:"max_connections_per_ip,omitempty"`
	DNSUnauthorizedPassthrough *bool   `json:"dns_unauthorized_passthrough_enabled,omitempty"`
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("admin panel settings update decoding error", "remote_addr", r.RemoteAddr, "error", err)
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validation
	if req.AccessMode != nil {
		mode := strings.ToLower(strings.TrimSpace(*req.AccessMode))
		if mode != "public" && mode != "user" {
			jsonErr(w, "access_mode must be 'public' or 'user'", http.StatusBadRequest)
			return
		}
	}

	if req.Timezone != nil {
		tz := strings.TrimSpace(*req.Timezone)
		if _, err := time.LoadLocation(tz); err != nil {
			jsonErr(w, fmt.Sprintf("invalid timezone %q", tz), http.StatusBadRequest)
			return
		}
	}

	if req.UnknownDomainPolicy != nil {
		policy := strings.ToLower(strings.TrimSpace(*req.UnknownDomainPolicy))
		if policy != "allow_default_port" && policy != "reject" {
			jsonErr(w, "unknown_domain_policy must be 'allow_default_port' or 'reject'", http.StatusBadRequest)
			return
		}
	}

	var normalizedDomain string
	if req.ServerDomain != nil {
		var err error
		normalizedDomain, err = NormalizeAndValidateServerDomain(*req.ServerDomain)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if req.RequestLogsRetention != nil {
		retentionStr := strings.TrimSpace(*req.RequestLogsRetention)
		if _, err := parseDurationWithDays(retentionStr); err != nil {
			jsonErr(w, fmt.Sprintf("invalid retention duration %q (e.g. 1h, 12h, 24h, 7d)", retentionStr), http.StatusBadRequest)
			return
		}
	}

	if req.MaxConnectionsPerIP != nil {
		if *req.MaxConnectionsPerIP <= 0 {
			jsonErr(w, "max_connections_per_ip must be positive", http.StatusBadRequest)
			return
		}
	}

	// Execution
	if req.AccessMode != nil {
		mode := strings.ToLower(strings.TrimSpace(*req.AccessMode))
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "access_mode", mode); err != nil {
				slog.Error("failed to persist access_mode setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		if s.accessStore != nil {
			s.accessStore.SetMode(access.AccessMode(mode))
		}
		slog.Info("access mode updated via admin panel", "mode", mode, "remote_addr", r.RemoteAddr)
	}

	if req.Timezone != nil {
		tz := strings.TrimSpace(*req.Timezone)
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "timezone", tz); err != nil {
				slog.Error("failed to persist timezone setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		_ = s.SetTimezone(tz)
		slog.Info("timezone updated via admin panel", "timezone", tz, "remote_addr", r.RemoteAddr)
	}

	if req.ServerDomain != nil {
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "server_domain", normalizedDomain); err != nil {
				slog.Error("failed to persist server_domain setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		s.SetServerDomain(normalizedDomain)
		slog.Info("server domain updated via admin panel", "domain", normalizedDomain, "remote_addr", r.RemoteAddr)
	}

	if req.UnknownDomainPolicy != nil {
		policy := strings.ToLower(strings.TrimSpace(*req.UnknownDomainPolicy))
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "unknown_domain_policy", policy); err != nil {
				slog.Error("failed to persist unknown_domain_policy setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		if s.ruleStore != nil {
			s.ruleStore.SetUnknownDomainPolicy(policy)
		}
		slog.Info("unknown domain policy updated via admin panel", "policy", policy, "remote_addr", r.RemoteAddr)
	}

	if req.RequestLogsEnabled != nil {
		enabled := *req.RequestLogsEnabled
		val := "false"
		if enabled {
			val = "true"
		}
		if s.sqlStore != nil {
			_ = s.sqlStore.SetSetting(r.Context(), "request_logs_enabled", val)
		}
		s.mu.RLock()
		if s.reqLogger != nil {
			s.reqLogger.SetEnabled(enabled)
		}
		s.mu.RUnlock()
		slog.Info("request logs enabled state updated via admin panel", "enabled", enabled, "remote_addr", r.RemoteAddr)
	}

	if req.RequestLogsRetention != nil {
		retentionStr := strings.TrimSpace(*req.RequestLogsRetention)
		dur, _ := parseDurationWithDays(retentionStr)
		cleanStr := formatDurationClean(dur)
		if s.sqlStore != nil {
			_ = s.sqlStore.SetSetting(r.Context(), "request_logs_retention", cleanStr)
		}
		s.mu.RLock()
		if s.reqLogger != nil {
			s.reqLogger.SetRetention(dur)
		}
		s.mu.RUnlock()
		slog.Info("request logs retention updated via admin panel", "retention", cleanStr, "remote_addr", r.RemoteAddr)
	}

	if req.PanelPath != nil {
		path := strings.TrimSpace(*req.PanelPath)
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "panel_path", path); err != nil {
				slog.Error("failed to persist panel_path setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		if err := s.ApplyPathPrefix(path); err != nil {
			slog.Error("failed to apply new panel path prefix", "error", err)
			jsonErr(w, "failed to apply panel path", http.StatusInternalServerError)
			return
		}
		slog.Info("panel path prefix updated via admin panel", "path", s.DisplayPath(), "remote_addr", r.RemoteAddr)
	}

	if req.MaxConnectionsPerIP != nil {
		maxConn := *req.MaxConnectionsPerIP
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "max_connections_per_ip", strconv.Itoa(maxConn)); err != nil {
				slog.Error("failed to persist max_connections_per_ip setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		s.mu.RLock()
		if s.limits != nil {
			s.limits.SetMaxPerIP(maxConn)
		}
		s.mu.RUnlock()
		slog.Info("max_connections_per_ip updated via admin panel", "max_connections_per_ip", maxConn, "remote_addr", r.RemoteAddr)
	}

	if req.DNSUnauthorizedPassthrough != nil {
		enabled := *req.DNSUnauthorizedPassthrough
		val := "false"
		if enabled {
			val = "true"
		}
		if s.sqlStore != nil {
			_ = s.sqlStore.SetSetting(r.Context(), "dns_unauthorized_passthrough_enabled", val)
		}
		s.mu.RLock()
		if s.dnsServer != nil {
			s.dnsServer.SetUnauthorizedPassthrough(enabled)
		}
		s.mu.RUnlock()
		slog.Info("dns_unauthorized_passthrough_enabled updated via admin panel", "enabled", enabled, "remote_addr", r.RemoteAddr)
	}

	jsonOK(w, s.currentSettings())
}
