package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/relay"
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
	EgressProxyEnabled         bool   `json:"egress_proxy_enabled"`
	EgressProxyAddr            string `json:"egress_proxy_addr"`
	EgressProxyUser            string `json:"egress_proxy_user"`
	EgressProxyHasPassword     bool   `json:"egress_proxy_has_password"`
	AllowedDestPorts           []int  `json:"allowed_dest_ports"`
	ListenPorts                []int  `json:"listen_ports"`
	ListenHTTPPorts            []int  `json:"listen_http_ports"`
	AdminUsername              string `json:"admin_username"`
	UptimeSeconds              int64  `json:"uptime_seconds"`
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
	egressEnabled := false
	proxyAddr := ""
	proxyUser := ""
	proxyHasPass := false
	allowedPorts := []int{443, 8443, 2053, 2083, 2087, 2096, 9443}
	listenPorts := []int{443}
	listenHTTPPorts := []int{80}

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
	if s.egressDialer != nil {
		cfg := s.egressDialer.Config()
		egressEnabled = cfg.Enabled
		proxyAddr = cfg.Addr
		proxyUser = cfg.User
		proxyHasPass = cfg.Password != ""
	}
	if s.allowList != nil {
		allowedPorts = s.allowList.Ports()
	} else if s.ruleStore != nil {
		allowedPorts = s.ruleStore.GlobalPorts()
	}
	if len(s.listenPorts) > 0 {
		listenPorts = make([]int, len(s.listenPorts))
		copy(listenPorts, s.listenPorts)
	}
	if len(s.listenHTTPPorts) > 0 {
		listenHTTPPorts = make([]int, len(s.listenHTTPPorts))
		copy(listenHTTPPorts, s.listenHTTPPorts)
	}
	username := s.username
	uptime := int64(time.Since(s.startTime).Seconds())
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
		EgressProxyEnabled:         egressEnabled,
		EgressProxyAddr:            proxyAddr,
		EgressProxyUser:            proxyUser,
		EgressProxyHasPassword:     proxyHasPass,
		AllowedDestPorts:           allowedPorts,
		ListenPorts:                listenPorts,
		ListenHTTPPorts:            listenHTTPPorts,
		AdminUsername:              username,
		UptimeSeconds:              uptime,
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
	EgressProxyEnabled         *bool   `json:"egress_proxy_enabled,omitempty"`
	EgressProxyAddr            *string `json:"egress_proxy_addr,omitempty"`
	EgressProxyUser            *string `json:"egress_proxy_user,omitempty"`
	EgressProxyPassword        *string `json:"egress_proxy_password,omitempty"`
	AllowedDestPorts           *[]int  `json:"allowed_dest_ports,omitempty"`
	ListenPorts                *[]int  `json:"listen_ports,omitempty"`
	ListenHTTPPorts            *[]int  `json:"listen_http_ports,omitempty"`
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
		validPath, err := config.ValidatePanelPath(path)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.DryRunPathPrefix(validPath); err != nil {
			slog.Error("failed to dry-run new panel path prefix", "path", validPath, "error", err)
			jsonErr(w, "invalid panel path", http.StatusBadRequest)
			return
		}
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "panel_path", validPath); err != nil {
				slog.Error("failed to persist panel_path setting", "error", err)
				jsonErr(w, "failed to save setting", http.StatusInternalServerError)
				return
			}
		}
		if err := s.ApplyPathPrefix(validPath); err != nil {
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

	if req.AllowedDestPorts != nil {
		if len(*req.AllowedDestPorts) == 0 {
			jsonErr(w, "allowed_dest_ports cannot be empty", http.StatusBadRequest)
			return
		}
		for _, p := range *req.AllowedDestPorts {
			if p <= 0 || p > 65535 {
				jsonErr(w, fmt.Sprintf("invalid port %d: must be between 1 and 65535", p), http.StatusBadRequest)
				return
			}
		}
		portsJSON, _ := json.Marshal(*req.AllowedDestPorts)
		if s.sqlStore != nil {
			if err := s.sqlStore.SetSetting(r.Context(), "allowed_dest_ports", string(portsJSON)); err != nil {
				slog.Error("failed to persist allowed_dest_ports", "error", err)
			}
		}
		s.mu.RLock()
		if s.allowList != nil {
			s.allowList.SetPorts(*req.AllowedDestPorts)
		}
		if s.ruleStore != nil {
			s.ruleStore.SetGlobalPorts(*req.AllowedDestPorts)
		}
		s.mu.RUnlock()
		slog.Info("allowed_dest_ports updated via admin panel", "ports", *req.AllowedDestPorts, "remote_addr", r.RemoteAddr)
	}

	if req.ListenPorts != nil {
		if len(*req.ListenPorts) == 0 {
			jsonErr(w, "listen_ports cannot be empty", http.StatusBadRequest)
			return
		}
		for _, p := range *req.ListenPorts {
			if p <= 0 || p > 65535 {
				jsonErr(w, fmt.Sprintf("invalid listen port %d", p), http.StatusBadRequest)
				return
			}
		}
		portsJSON, _ := json.Marshal(*req.ListenPorts)
		if s.sqlStore != nil {
			_ = s.sqlStore.SetSetting(r.Context(), "listen_ports", string(portsJSON))
		}
		s.SetListenPorts(*req.ListenPorts)
		slog.Info("listen_ports updated via admin panel", "ports", *req.ListenPorts, "remote_addr", r.RemoteAddr)
	}

	if req.ListenHTTPPorts != nil {
		if len(*req.ListenHTTPPorts) == 0 {
			jsonErr(w, "listen_http_ports cannot be empty", http.StatusBadRequest)
			return
		}
		for _, p := range *req.ListenHTTPPorts {
			if p <= 0 || p > 65535 {
				jsonErr(w, fmt.Sprintf("invalid listen http port %d", p), http.StatusBadRequest)
				return
			}
		}
		portsJSON, _ := json.Marshal(*req.ListenHTTPPorts)
		if s.sqlStore != nil {
			_ = s.sqlStore.SetSetting(r.Context(), "listen_http_ports", string(portsJSON))
		}
		s.SetListenHTTPPorts(*req.ListenHTTPPorts)
		slog.Info("listen_http_ports updated via admin panel", "ports", *req.ListenHTTPPorts, "remote_addr", r.RemoteAddr)
	}

	if req.EgressProxyEnabled != nil || req.EgressProxyAddr != nil || req.EgressProxyUser != nil || req.EgressProxyPassword != nil {
		s.mu.RLock()
		ed := s.egressDialer
		s.mu.RUnlock()

		if ed != nil {
			cfg := ed.Config()
			if req.EgressProxyEnabled != nil {
				cfg.Enabled = *req.EgressProxyEnabled
			}
			if req.EgressProxyAddr != nil {
				cfg.Addr = strings.TrimSpace(*req.EgressProxyAddr)
			}
			if req.EgressProxyUser != nil {
				cfg.User = strings.TrimSpace(*req.EgressProxyUser)
			}
			if req.EgressProxyPassword != nil && *req.EgressProxyPassword != "" {
				cfg.Password = *req.EgressProxyPassword
			}

			if cfg.Enabled && cfg.Addr == "" {
				jsonErr(w, "proxy address cannot be empty when egress proxy is enabled", http.StatusBadRequest)
				return
			}

			if err := ed.UpdateConfig(cfg); err != nil {
				jsonErr(w, fmt.Sprintf("failed to update egress proxy: %v", err), http.StatusBadRequest)
				return
			}

			if s.sqlStore != nil {
				_ = s.sqlStore.SetSetting(r.Context(), "egress_proxy_enabled", fmt.Sprintf("%t", cfg.Enabled))
				_ = s.sqlStore.SetSetting(r.Context(), "egress_proxy_addr", cfg.Addr)
				_ = s.sqlStore.SetSetting(r.Context(), "egress_proxy_user", cfg.User)
				if req.EgressProxyPassword != nil && *req.EgressProxyPassword != "" {
					_ = s.sqlStore.SetSetting(r.Context(), "egress_proxy_password", cfg.Password)
				}
			}
			slog.Info("egress proxy updated via admin panel", "enabled", cfg.Enabled, "addr", cfg.Addr, "remote_addr", r.RemoteAddr)
		}
	}

	jsonOK(w, s.currentSettings())
}

type testProxyRequest struct {
	Addr     string `json:"addr"`
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *Server) handleTestProxy(w http.ResponseWriter, r *http.Request) {
	var req testProxyRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var latency time.Duration
	var err error

	req.Addr = strings.TrimSpace(req.Addr)
	if req.Addr != "" {
		tempEd, dialerErr := relay.NewEgressDialer(config.EgressProxyConfig{
			Enabled:  true,
			Addr:     req.Addr,
			User:     strings.TrimSpace(req.User),
			Password: req.Password,
		})
		if dialerErr != nil {
			jsonOK(w, map[string]interface{}{
				"ok":    false,
				"error": dialerErr.Error(),
			})
			return
		}
		latency, err = tempEd.TestConnection(ctx, "1.1.1.1:53")
	} else {
		s.mu.RLock()
		ed := s.egressDialer
		s.mu.RUnlock()

		if ed == nil {
			jsonErr(w, "Egress proxy dialer is not initialized", http.StatusBadRequest)
			return
		}
		latency, err = ed.TestConnection(ctx, "1.1.1.1:53")
	}

	if err != nil {
		slog.Warn("proxy test connection failed", "error", err)
		jsonOK(w, map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	jsonOK(w, map[string]interface{}{
		"ok":         true,
		"latency_ms": latency.Milliseconds(),
	})
}

type updateAdminCredentialsRequest struct {
	CurrentPassword string `json:"current_password"`
	NewUsername     string `json:"new_username"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleUpdateAdminCredentials(w http.ResponseWriter, r *http.Request) {
	var req updateAdminCredentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.UpdateAdminCredentials(r.Context(), req.CurrentPassword, req.NewUsername, req.NewPassword); err != nil {
		slog.Warn("failed to update admin credentials", "error", err, "remote_addr", r.RemoteAddr)
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	slog.Info("admin credentials updated successfully via admin panel", "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]interface{}{
		"ok":       true,
		"message":  "Admin credentials updated successfully.",
		"username": s.AdminUsername(),
	})
}

func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	slog.Info("service restart triggered via admin panel", "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]interface{}{
		"ok":      true,
		"message": "Service restart initiated. The server will restart shortly.",
	})

	go func() {
		time.Sleep(500 * time.Millisecond)
		s.mu.RLock()
		fn := s.restartHandler
		s.mu.RUnlock()
		if fn != nil {
			fn()
		} else {
			os.Exit(0)
		}
	}()
}
