package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
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
	LookupEnabled              bool   `json:"lookup_enabled"`
	LookupRequireRegistered    bool   `json:"lookup_require_registered"`
	DefaultMaxIPs              int    `json:"default_max_ips"`
	HttpFrontMaxConnsPerIP     int    `json:"http_front_max_conns_per_ip"`
	HttpFrontMaxGlobalConns    int    `json:"http_front_max_global_conns"`
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

func normalizeAndValidateEgressAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", nil
	}
	addrLower := strings.ToLower(addr)
	if strings.HasPrefix(addrLower, "http://") || strings.HasPrefix(addrLower, "https://") {
		return "", fmt.Errorf("only SOCKS5 host:port is supported")
	}
	if strings.HasPrefix(addrLower, "socks5://") {
		addr = addr[len("socks5://"):]
	} else if strings.HasPrefix(addrLower, "socks5h://") {
		addr = addr[len("socks5h://"):]
	}
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("invalid proxy address (must be host:port): %s", raw)
	}
	return addr, nil
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
	frontMaxIP := 60
	frontMaxGlobal := 5000
	if s.frontLimits != nil {
		frontMaxIP = s.frontLimits.MaxPerIP()
		frontMaxGlobal = s.frontLimits.MaxGlobal()
	}
	s.mu.RUnlock()

	lookupEn, lookupReq := s.LookupPolicy()

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
		LookupEnabled:              lookupEn,
		LookupRequireRegistered:    lookupReq,
		DefaultMaxIPs:              s.DefaultMaxIPs(),
		HttpFrontMaxConnsPerIP:     frontMaxIP,
		HttpFrontMaxGlobalConns:    frontMaxGlobal,
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
	LookupEnabled              *bool   `json:"lookup_enabled,omitempty"`
	LookupRequireRegistered    *bool   `json:"lookup_require_registered,omitempty"`
	HttpFrontMaxConnsPerIP     *int    `json:"http_front_max_conns_per_ip,omitempty"`
	HttpFrontMaxGlobalConns    *int    `json:"http_front_max_global_conns,omitempty"`
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("admin panel settings update decoding error", "remote_addr", r.RemoteAddr, "error", err)
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	toPersist := make(map[string]string)

	// (1) Decode + Validate EVERYTHING first
	var validMode string
	if req.AccessMode != nil {
		var err error
		validMode, err = config.ValidateAccessMode(*req.AccessMode)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		toPersist["access_mode"] = validMode
	}

	var validPolicy string
	if req.UnknownDomainPolicy != nil {
		var err error
		validPolicy, err = config.ValidateUnknownDomainPolicy(*req.UnknownDomainPolicy, "")
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		toPersist["unknown_domain_policy"] = validPolicy
	}

	var tz string
	if req.Timezone != nil {
		tz = strings.TrimSpace(*req.Timezone)
		if tz == "" {
			tz = "UTC"
		}
		if _, err := time.LoadLocation(tz); err != nil {
			jsonErr(w, fmt.Sprintf("invalid timezone %q: %v", tz, err), http.StatusBadRequest)
			return
		}
		toPersist["timezone"] = tz
	}

	var normDomain string
	if req.ServerDomain != nil {
		var err error
		normDomain, err = NormalizeAndValidateServerDomain(*req.ServerDomain)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		toPersist["server_domain"] = normDomain
	}

	var retentionClean string
	var retentionDur time.Duration
	if req.RequestLogsRetention != nil {
		retentionStr := strings.TrimSpace(*req.RequestLogsRetention)
		var err error
		retentionDur, err = parseDurationWithDays(retentionStr)
		if err != nil {
			jsonErr(w, fmt.Sprintf("invalid retention duration %q (e.g. 1h, 12h, 24h, 7d)", retentionStr), http.StatusBadRequest)
			return
		}
		retentionClean = formatDurationClean(retentionDur)
		toPersist["request_logs_retention"] = retentionClean
	}

	if req.RequestLogsEnabled != nil {
		val := "false"
		if *req.RequestLogsEnabled {
			val = "true"
		}
		toPersist["request_logs_enabled"] = val
	}

	if req.MaxConnectionsPerIP != nil {
		if *req.MaxConnectionsPerIP <= 0 {
			jsonErr(w, "max_connections_per_ip must be positive", http.StatusBadRequest)
			return
		}
		toPersist["max_connections_per_ip"] = strconv.Itoa(*req.MaxConnectionsPerIP)
	}

	if req.DNSUnauthorizedPassthrough != nil {
		val := "false"
		if *req.DNSUnauthorizedPassthrough {
			val = "true"
		}
		toPersist["dns_unauthorized_passthrough_enabled"] = val
	}

	var allowedPortsJSON string
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
		b, _ := json.Marshal(*req.AllowedDestPorts)
		allowedPortsJSON = string(b)
		toPersist["allowed_dest_ports"] = allowedPortsJSON
	}

	var listenPortsJSON string
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
		b, _ := json.Marshal(*req.ListenPorts)
		listenPortsJSON = string(b)
		toPersist["listen_ports"] = listenPortsJSON
	}

	var listenHTTPPortsJSON string
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
		b, _ := json.Marshal(*req.ListenHTTPPorts)
		listenHTTPPortsJSON = string(b)
		toPersist["listen_http_ports"] = listenHTTPPortsJSON
	}

	var validPanelPath string
	if req.PanelPath != nil {
		path := strings.TrimSpace(*req.PanelPath)
		var err error
		validPanelPath, err = config.ValidatePanelPath(path)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.DryRunPathPrefix(validPanelPath); err != nil {
			slog.Error("failed to dry-run new panel path prefix", "path", validPanelPath, "error", err)
			jsonErr(w, "invalid panel path", http.StatusBadRequest)
			return
		}
		toPersist["panel_path"] = validPanelPath
	}

	if req.LookupEnabled != nil {
		val := "false"
		if *req.LookupEnabled {
			val = "true"
		}
		toPersist["lookup_enabled"] = val
	}

	if req.LookupRequireRegistered != nil {
		val := "false"
		if *req.LookupRequireRegistered {
			val = "true"
		}
		toPersist["lookup_require_registered"] = val
	}

	if req.HttpFrontMaxConnsPerIP != nil {
		if *req.HttpFrontMaxConnsPerIP <= 0 {
			jsonErr(w, "http_front_max_conns_per_ip must be positive", http.StatusBadRequest)
			return
		}
		toPersist["http_front_max_conns_per_ip"] = strconv.Itoa(*req.HttpFrontMaxConnsPerIP)
	}

	if req.HttpFrontMaxGlobalConns != nil {
		if *req.HttpFrontMaxGlobalConns <= 0 {
			jsonErr(w, "http_front_max_global_conns must be positive", http.StatusBadRequest)
			return
		}
		toPersist["http_front_max_global_conns"] = strconv.Itoa(*req.HttpFrontMaxGlobalConns)
	}

	// (2) Verify egress config by building a candidate dialer without swapping
	var candidateEgressCfg *config.EgressProxyConfig
	if req.EgressProxyEnabled != nil || req.EgressProxyAddr != nil || req.EgressProxyUser != nil || req.EgressProxyPassword != nil {
		s.mu.RLock()
		ed := s.egressDialer
		s.mu.RUnlock()

		var curCfg config.EgressProxyConfig
		if ed != nil {
			curCfg = ed.Config()
		}
		if req.EgressProxyEnabled != nil {
			curCfg.Enabled = *req.EgressProxyEnabled
		}
		if req.EgressProxyAddr != nil {
			normAddr, err := normalizeAndValidateEgressAddr(*req.EgressProxyAddr)
			if err != nil {
				jsonErr(w, err.Error(), http.StatusBadRequest)
				return
			}
			curCfg.Addr = normAddr
		}
		if req.EgressProxyUser != nil {
			curCfg.User = strings.TrimSpace(*req.EgressProxyUser)
		}
		if req.EgressProxyPassword != nil && *req.EgressProxyPassword != "" {
			curCfg.Password = *req.EgressProxyPassword
		}

		if curCfg.Enabled && curCfg.Addr == "" {
			jsonErr(w, "proxy address cannot be empty when egress proxy is enabled", http.StatusBadRequest)
			return
		}

		if curCfg.Enabled || curCfg.Addr != "" {
			if _, err := relay.NewEgressDialer(curCfg); err != nil {
				jsonErr(w, fmt.Sprintf("failed to configure egress proxy: %v", err), http.StatusBadRequest)
				return
			}
		}

		candidateEgressCfg = &curCfg
		toPersist["egress_proxy_enabled"] = fmt.Sprintf("%t", curCfg.Enabled)
		toPersist["egress_proxy_addr"] = curCfg.Addr
		toPersist["egress_proxy_user"] = curCfg.User
		if req.EgressProxyPassword != nil && *req.EgressProxyPassword != "" {
			toPersist["egress_proxy_password"] = curCfg.Password
		}
	}

	// (3) Persist all keys in ONE transaction
	if s.sqlStore != nil && len(toPersist) > 0 {
		if err := s.sqlStore.SetSettings(r.Context(), toPersist); err != nil {
			slog.Error("failed to persist settings", "error", err)
			jsonErr(w, "failed to save settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// (4) Apply in memory only after persistence succeeded
	if req.AccessMode != nil && s.accessStore != nil {
		s.accessStore.SetMode(access.AccessMode(validMode))
		slog.Info("access mode updated via admin panel", "mode", validMode, "remote_addr", r.RemoteAddr)
	}

	if req.UnknownDomainPolicy != nil && s.ruleStore != nil {
		s.ruleStore.SetUnknownDomainPolicy(validPolicy)
		slog.Info("unknown domain policy updated via admin panel", "policy", validPolicy, "remote_addr", r.RemoteAddr)
	}

	if req.Timezone != nil {
		_ = s.SetTimezone(tz)
		slog.Info("timezone updated via admin panel", "timezone", tz, "remote_addr", r.RemoteAddr)
	}

	if req.ServerDomain != nil {
		s.SetServerDomain(normDomain)
		slog.Info("server domain updated via admin panel", "domain", normDomain, "remote_addr", r.RemoteAddr)
	}

	if req.RequestLogsEnabled != nil {
		s.mu.RLock()
		if s.reqLogger != nil {
			s.reqLogger.SetEnabled(*req.RequestLogsEnabled)
		}
		s.mu.RUnlock()
		slog.Info("request logs enabled state updated via admin panel", "enabled", *req.RequestLogsEnabled, "remote_addr", r.RemoteAddr)
	}

	if req.RequestLogsRetention != nil {
		s.mu.RLock()
		if s.reqLogger != nil {
			s.reqLogger.SetRetention(retentionDur)
		}
		s.mu.RUnlock()
		slog.Info("request logs retention updated via admin panel", "retention", retentionClean, "remote_addr", r.RemoteAddr)
	}

	if req.MaxConnectionsPerIP != nil {
		s.mu.RLock()
		if s.limits != nil {
			s.limits.SetMaxPerIP(*req.MaxConnectionsPerIP)
		}
		s.mu.RUnlock()
		slog.Info("max_connections_per_ip updated via admin panel", "max_connections_per_ip", *req.MaxConnectionsPerIP, "remote_addr", r.RemoteAddr)
	}

	if req.HttpFrontMaxConnsPerIP != nil || req.HttpFrontMaxGlobalConns != nil {
		s.mu.RLock()
		fl := s.frontLimits
		s.mu.RUnlock()
		if fl != nil {
			if req.HttpFrontMaxConnsPerIP != nil {
				fl.SetMaxPerIP(*req.HttpFrontMaxConnsPerIP)
			}
			if req.HttpFrontMaxGlobalConns != nil {
				fl.SetMaxGlobal(*req.HttpFrontMaxGlobalConns)
			}
		}
		slog.Info("http front limits updated via admin panel", "remote_addr", r.RemoteAddr)
	}

	if req.DNSUnauthorizedPassthrough != nil {
		s.mu.RLock()
		if s.dnsServer != nil {
			s.dnsServer.SetUnauthorizedPassthrough(*req.DNSUnauthorizedPassthrough)
		}
		s.mu.RUnlock()
		slog.Info("dns_unauthorized_passthrough_enabled updated via admin panel", "enabled", *req.DNSUnauthorizedPassthrough, "remote_addr", r.RemoteAddr)
	}

	if req.AllowedDestPorts != nil {
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
		s.SetListenPorts(*req.ListenPorts)
		slog.Info("listen_ports updated via admin panel", "ports", *req.ListenPorts, "remote_addr", r.RemoteAddr)
	}

	if req.ListenHTTPPorts != nil {
		s.SetListenHTTPPorts(*req.ListenHTTPPorts)
		slog.Info("listen_http_ports updated via admin panel", "ports", *req.ListenHTTPPorts, "remote_addr", r.RemoteAddr)
	}

	if req.LookupEnabled != nil || req.LookupRequireRegistered != nil {
		curEn, curReq := s.LookupPolicy()
		if req.LookupEnabled != nil {
			curEn = *req.LookupEnabled
		}
		if req.LookupRequireRegistered != nil {
			curReq = *req.LookupRequireRegistered
		}
		s.SetLookupPolicy(curEn, curReq)
		slog.Info("lookup policy updated via admin panel", "enabled", curEn, "require_registered", curReq, "remote_addr", r.RemoteAddr)
	}

	if candidateEgressCfg != nil {
		s.mu.RLock()
		ed := s.egressDialer
		s.mu.RUnlock()
		if ed != nil {
			_ = ed.UpdateConfig(*candidateEgressCfg)
		}
		slog.Info("egress proxy updated via admin panel", "enabled", candidateEgressCfg.Enabled, "addr", candidateEgressCfg.Addr, "remote_addr", r.RemoteAddr)
	}

	if req.PanelPath != nil {
		_ = s.ApplyPathPrefix(validPanelPath)
		slog.Info("panel path prefix updated via admin panel", "path", s.DisplayPath(), "remote_addr", r.RemoteAddr)
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
		normAddr, normErr := normalizeAndValidateEgressAddr(req.Addr)
		if normErr != nil {
			jsonOK(w, map[string]interface{}{
				"ok":    false,
				"error": normErr.Error(),
			})
			return
		}
		tempEd, dialerErr := relay.NewEgressDialer(config.EgressProxyConfig{
			Enabled:  true,
			Addr:     normAddr,
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

	var callerToken string
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		callerToken = cookie.Value
	}

	if err := s.UpdateAdminCredentials(r.Context(), req.CurrentPassword, req.NewUsername, req.NewPassword); err != nil {
		slog.Warn("failed to update admin credentials", "error", err, "remote_addr", r.RemoteAddr)
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	if callerToken != "" {
		s.sessions.deleteAllExcept(callerToken)
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
