package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/settings"
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
	DNSUpstreamAddr            string `json:"dns_upstream_addr"`
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
	UpdateCheckEnabled         bool   `json:"update_check_enabled"`
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
	dnsUpstreamAddr := ""
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
		reqRetention = settings.FormatDurationClean(s.reqLogger.Retention())
	}
	if s.limits != nil {
		maxConn = s.limits.MaxPerIP()
	}
	if s.dnsServer != nil {
		dnsPassthrough = s.dnsServer.UnauthorizedPassthroughEnabled()
		dnsUpstreamAddr = strings.Join(s.dnsServer.Upstreams(), ",")
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

	if dnsUpstreamAddr == "" && s.sqlStore != nil {
		if val, found, err := s.sqlStore.GetSetting(context.Background(), "dns_upstream_addr"); err == nil && found {
			dnsUpstreamAddr = val
		}
	}

	lookupEn, lookupReq := s.LookupPolicy()

	updateCheckEnabled := true
	if s.sqlStore != nil {
		if val, found, err := s.sqlStore.GetSetting(context.Background(), "update_check_enabled"); err == nil && found {
			updateCheckEnabled = (val != "false")
		}
	}

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
		DNSUpstreamAddr:            dnsUpstreamAddr,
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
		UpdateCheckEnabled:         updateCheckEnabled,
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
	DNSUpstreamAddr            *string `json:"dns_upstream_addr,omitempty"`
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
	UpdateCheckEnabled         *bool   `json:"update_check_enabled,omitempty"`
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
		retentionDur, err = settings.ParseDurationWithDays(retentionStr)
		if err != nil {
			jsonErr(w, fmt.Sprintf("invalid retention duration %q (e.g. 1h, 12h, 24h, 7d)", retentionStr), http.StatusBadRequest)
			return
		}
		retentionClean = settings.FormatDurationClean(retentionDur)
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

	if req.UpdateCheckEnabled != nil {
		val := "false"
		if *req.UpdateCheckEnabled {
			val = "true"
		}
		toPersist["update_check_enabled"] = val
	}

	var candidateDNSUpstream *string
	var candidateDNSUpstreams []string
	if req.DNSUpstreamAddr != nil {
		list, canon, err := settings.ValidateUpstreamList(*req.DNSUpstreamAddr)
		if err != nil {
			jsonErr(w, fmt.Sprintf("invalid dns_upstream_addr: %v", err), http.StatusBadRequest)
			return
		}
		candidateDNSUpstream = &canon
		candidateDNSUpstreams = list
		toPersist["dns_upstream_addr"] = canon
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
			normAddr, err := settings.ValidateEgressAddr(*req.EgressProxyAddr)
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

	if candidateDNSUpstream != nil {
		s.mu.RLock()
		dnsSrv := s.dnsServer
		s.mu.RUnlock()
		if dnsSrv != nil {
			dnsSrv.SetUpstreams(candidateDNSUpstreams)
		}
		slog.Info("dns_upstream_addr updated via admin panel", "addrs", *candidateDNSUpstream, "remote_addr", r.RemoteAddr)
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req.Addr = strings.TrimSpace(req.Addr)

	var ed *relay.EgressDialer
	if req.Addr != "" {
		normAddr, normErr := settings.ValidateEgressAddr(req.Addr)
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
		ed = tempEd
	} else {
		s.mu.RLock()
		ed = s.egressDialer
		s.mu.RUnlock()
		if ed == nil {
			jsonErr(w, "Egress proxy dialer is not initialized", http.StatusBadRequest)
			return
		}
	}

	hc := ed.HTTPClient(9 * time.Second)
	const traceURL = "https://cloudflare.com/cdn-cgi/trace"

	hreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	start := time.Now()
	resp, err := hc.Do(hreq)
	latencyMS := time.Since(start).Milliseconds()

	if err != nil {
		slog.Warn("proxy test HTTP request failed", "error", err)
		jsonOK(w, map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// Parse key=value pairs from cloudflare trace
	proxyIP := ""
	country := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "ip="); ok {
			proxyIP = after
		} else if after, ok := strings.CutPrefix(line, "loc="); ok {
			country = after
		}
	}

	flag := countryCodeToFlag(country)

	jsonOK(w, map[string]interface{}{
		"ok":         true,
		"ip":         proxyIP,
		"flag":       flag,
		"country":    country,
		"latency_ms": latencyMS,
	})
}

// countryCodeToFlag converts a 2-letter ISO 3166-1 alpha-2 country code to a flag emoji.
func countryCodeToFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	// Regional indicator symbols: offset from 'A' = 0x1F1E6
	r1 := rune(0x1F1E6 + int(code[0]-'A'))
	r2 := rune(0x1F1E6 + int(code[1]-'A'))
	return string([]rune{r1, r2})
}

type testDNSRequest struct {
	Addr  string   `json:"addr"`
	Addrs []string `json:"addrs"`
}

type testDNSResult struct {
	Addr      string `json:"addr"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Rcode     int    `json:"rcode"`
	Error     string `json:"error"`
}

func (s *Server) handleTestDNS(w http.ResponseWriter, r *http.Request) {
	var req testDNSRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	var targets []string
	if strings.TrimSpace(req.Addr) != "" {
		targets = []string{strings.TrimSpace(req.Addr)}
	} else if len(req.Addrs) > 0 {
		for _, a := range req.Addrs {
			if t := strings.TrimSpace(a); t != "" {
				targets = append(targets, t)
			}
		}
	} else {
		s.mu.RLock()
		dnsSrv := s.dnsServer
		s.mu.RUnlock()
		if dnsSrv != nil {
			targets = dnsSrv.Upstreams()
		}
		if len(targets) == 0 && s.sqlStore != nil {
			if raw, found, err := s.sqlStore.GetSetting(r.Context(), "dns_upstream_addr"); err == nil && found {
				if list, _, valErr := settings.ValidateUpstreamList(raw); valErr == nil {
					targets = list
				}
			}
		}
	}

	results := make([]testDNSResult, 0, len(targets))
	for _, target := range targets {
		list, _, err := settings.ValidateUpstreamList(target)
		if err != nil {
			results = append(results, testDNSResult{
				Addr:      target,
				OK:        false,
				LatencyMS: 0,
				Rcode:     dns.RcodeServerFailure,
				Error:     err.Error(),
			})
			continue
		}

		targetAddr := list[0]
		client := &dns.Client{Timeout: 4 * time.Second}
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		start := time.Now()
		resp, _, qErr := client.Exchange(msg, targetAddr)
		latency := time.Since(start).Milliseconds()

		if qErr != nil {
			results = append(results, testDNSResult{
				Addr:      targetAddr,
				OK:        false,
				LatencyMS: latency,
				Rcode:     dns.RcodeServerFailure,
				Error:     qErr.Error(),
			})
		} else if resp == nil {
			results = append(results, testDNSResult{
				Addr:      targetAddr,
				OK:        false,
				LatencyMS: latency,
				Rcode:     dns.RcodeServerFailure,
				Error:     "nil response from upstream",
			})
		} else {
			ok := (resp.Rcode == dns.RcodeSuccess)
			errStr := ""
			if !ok {
				errStr = dns.RcodeToString[resp.Rcode]
			}
			results = append(results, testDNSResult{
				Addr:      targetAddr,
				OK:        ok,
				LatencyMS: latency,
				Rcode:     resp.Rcode,
				Error:     errStr,
			})
		}
	}

	jsonOK(w, results)
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
