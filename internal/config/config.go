package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the full application configuration.
type Config struct {
	Listen              ListenConfig      `yaml:"listen"`
	AllowedDestPorts    []int             `yaml:"allowed_dest_ports"`
	UnknownDomainPolicy string            `yaml:"unknown_domain_policy"` // "reject" | "allow_default_port"
	AccessMode          string            `yaml:"access_mode"`           // "public" | "user"
	Timezone            string            `yaml:"timezone"`              // e.g. "UTC" or "Asia/Tehran"
	Timeouts            TimeoutConfig     `yaml:"timeouts"`
	Limits              LimitConfig       `yaml:"limits"`
	Logging             LogConfig         `yaml:"logging"`
	Security            SecurityConfig    `yaml:"security"`
	Shutdown            ShutdownConfig    `yaml:"shutdown"`
	SQLite              SQLiteConfig      `yaml:"sqlite"`
	Panel               PanelConfig       `yaml:"panel"`
	MagicLink           MagicLinkConfig   `yaml:"magic_link"`
	DNS                 DNSConfig         `yaml:"dns"`
	Users               UsersConfig       `yaml:"users"`
	EgressProxy         EgressProxyConfig `yaml:"-"`
}

// EgressProxyConfig holds outbound SOCKS5 egress proxy settings configured via environment variables.
type EgressProxyConfig struct {
	Enabled  bool   `yaml:"-"`
	Addr     string `yaml:"-"`
	User     string `yaml:"-"`
	Password string `yaml:"-"`
}

// ListenConfig describes the TCP listen parameters.
type ListenConfig struct {
	Addr      string `yaml:"addr"`
	Ports     []int  `yaml:"ports"`
	HTTPPorts []int  `yaml:"http_ports"`
}

// TimeoutConfig holds all timeout settings.
type TimeoutConfig struct {
	ClientHello           Duration `yaml:"client_hello"`
	HTTPHeader            Duration `yaml:"http_header"`
	Idle                  Duration `yaml:"idle"`
	MaxConnectionDuration Duration `yaml:"max_connection_duration"`
	TCPKeepalive          Duration `yaml:"tcp_keepalive"` // OS-level TCP keepalive period; 0 disables
}

// LimitConfig holds connection limit settings.
type LimitConfig struct {
	MaxGlobalConnections int `yaml:"max_global_connections"`
	MaxConnectionsPerIP  int `yaml:"max_connections_per_ip"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Path        string            `yaml:"path"`
	Format      string            `yaml:"format"`
	Rotation    RotationConfig    `yaml:"rotation"`
	RequestLogs RequestLogsConfig `yaml:"request_logs"`
}

// RequestLogsConfig holds request logging settings.
type RequestLogsConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Retention Duration `yaml:"retention"`
}

// RotationConfig holds log rotation settings.
type RotationConfig struct {
	MaxSizeMB  int  `yaml:"max_size_mb"`
	MaxBackups int  `yaml:"max_backups"`
	MaxAgeDays int  `yaml:"max_age_days"`
	Compress   bool `yaml:"compress"`
}

// SecurityConfig holds security-related settings.
type SecurityConfig struct {
	BlockPrivateIPs   bool     `yaml:"block_private_ips"`
	BlockOwnIPs       bool     `yaml:"block_own_ips"`
	ExtraBlockedCIDRs []string `yaml:"extra_blocked_cidrs"`
}

// ShutdownConfig holds graceful shutdown settings.
type ShutdownConfig struct {
	GracePeriod Duration `yaml:"grace_period"`
}

// PanelConfig holds the admin panel settings.
type PanelConfig struct {
	Addr string `yaml:"addr"` // e.g. "0.0.0.0:8080"
	Path string `yaml:"path"` // e.g. "/" or "/admin" or "/secret-panel"
}

// SQLiteConfig holds SQLite database settings.
type SQLiteConfig struct {
	Path string `yaml:"path"` // e.g. "/var/lib/tls-relay/data.db"
}

// MagicLinkConfig holds legacy magic link HTTP service settings.
// Deprecated: Public portal routes (/connect, /lookup, /setup, /api/portal/*) are
// mounted directly on the panel / frontrouter HTTP listener.
type MagicLinkConfig struct {
	Addr string `yaml:"addr"` // Deprecated: preserved for backward compatibility
}

// UsersConfig holds default user settings.
type UsersConfig struct {
	DefaultMaxIPs int `yaml:"default_max_ips"`
}

// DNSConfig holds the custom DNS resolver settings.
type DNSConfig struct {
	Addr                    string                        `yaml:"addr"`          // e.g. "0.0.0.0:53"
	RelayIP                 string                        `yaml:"relay_ip"`      // authoritative A record IP
	UpstreamAddr            string                        `yaml:"upstream_addr"` // e.g. "1.1.1.1:53"
	TTL                     int                           `yaml:"ttl"`           // seconds, for authoritative answers
	RateLimit               DNSRateLimitConfig            `yaml:"rate_limit"`
	UnauthorizedPassthrough UnauthorizedPassthroughConfig `yaml:"unauthorized_passthrough"`
	EDNSBufSize             uint16                        `yaml:"edns_buf_size"` // cap advertised EDNS0 buffer size
}

// UnauthorizedPassthroughConfig holds settings for allowing unregistered IPs to query non-relay domains.
type UnauthorizedPassthroughConfig struct {
	Enabled   bool               `yaml:"enabled"`
	RateLimit DNSRateLimitConfig `yaml:"rate_limit"`
}

// DNSRateLimitConfig holds per-IP rate limiter settings.
type DNSRateLimitConfig struct {
	QPS   float64 `yaml:"qps"`
	Burst int     `yaml:"burst"`
}

// Duration is a yaml-unmarshalable time.Duration.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// defaultConfig returns a Config populated with all sane defaults.
func defaultConfig() Config {
	return Config{
		Listen: ListenConfig{
			Addr:      "0.0.0.0",
			Ports:     []int{443},
			HTTPPorts: []int{80},
		},
		AllowedDestPorts:    []int{443, 8443, 2053, 2083, 2087, 2096, 9443},
		UnknownDomainPolicy: "reject",
		AccessMode:          "user",
		Timezone:            "UTC",
		Timeouts: TimeoutConfig{
			ClientHello:           Duration{Duration: 5 * time.Second},
			HTTPHeader:            Duration{Duration: 5 * time.Second},
			Idle:                  Duration{Duration: 300 * time.Second},
			MaxConnectionDuration: Duration{Duration: 0},
			TCPKeepalive:          Duration{Duration: 30 * time.Second},
		},
		Limits: LimitConfig{
			MaxGlobalConnections: 10000,
			MaxConnectionsPerIP:  200,
		},
		Logging: LogConfig{
			Path:   "",
			Format: "json",
			Rotation: RotationConfig{
				MaxSizeMB:  100,
				MaxBackups: 7,
				MaxAgeDays: 14,
				Compress:   true,
			},
			RequestLogs: RequestLogsConfig{
				Enabled:   true,
				Retention: Duration{Duration: 24 * time.Hour},
			},
		},
		Security: SecurityConfig{
			BlockPrivateIPs:   true,
			BlockOwnIPs:       true,
			ExtraBlockedCIDRs: []string{},
		},
		Shutdown: ShutdownConfig{
			GracePeriod: Duration{Duration: 10 * time.Second},
		},
		SQLite: SQLiteConfig{
			Path: "/var/lib/tls-relay/data.db",
		},
		Panel: PanelConfig{
			Addr: "0.0.0.0:80",
			Path: "/admin",
		},
		MagicLink: MagicLinkConfig{
			Addr: "0.0.0.0:80",
		},
		DNS: DNSConfig{
			Addr:         "0.0.0.0:53",
			RelayIP:      "",
			UpstreamAddr: "1.1.1.1:53",
			TTL:          30,
			RateLimit: DNSRateLimitConfig{
				QPS:   20,
				Burst: 40,
			},
			UnauthorizedPassthrough: UnauthorizedPassthroughConfig{
				Enabled: false,
				RateLimit: DNSRateLimitConfig{
					QPS:   5,
					Burst: 10,
				},
			},
			EDNSBufSize: 1232,
		},
		Users: UsersConfig{
			DefaultMaxIPs: 3,
		},
	}
}

// NormalizePanelPath normalizes a URL path prefix for the admin panel.
// Examples: "" -> "/", "/" -> "/", "admin" -> "/admin", "/admin/" -> "/admin"
func NormalizePanelPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

var panelPathRegex = regexp.MustCompile(`^/[A-Za-z0-9_-]{1,64}$`)

var reservedPanelPaths = map[string]struct{}{
	"api":        {},
	"connect":    {},
	"setup":      {},
	"static":     {},
	"css":        {},
	"js":         {},
	"pages":      {},
	"index.html": {},
}

// ValidatePanelPath validates and normalizes a panel URL path prefix.
// After NormalizePanelPath, it must match ^/[A-Za-z0-9_-]{1,64}$ or be "/".
// Reserved prefixes (case-insensitive): api, connect, setup, static, css, js, pages, index.html.
func ValidatePanelPath(p string) (string, error) {
	norm := NormalizePanelPath(p)
	if norm == "/" {
		return "/", nil
	}
	if !panelPathRegex.MatchString(norm) {
		return "", fmt.Errorf("panel_path %q is invalid: must match ^/[A-Za-z0-9_-]{1,64}$ or be '/'", p)
	}
	seg := strings.ToLower(strings.TrimPrefix(norm, "/"))
	if _, reserved := reservedPanelPaths[seg]; reserved {
		return "", fmt.Errorf("panel_path %q is reserved", p)
	}
	return norm, nil
}

// ValidateAccessMode validates and normalizes the access mode ("public" or "user").
// On invalid value, it returns "user" and an error.
func ValidateAccessMode(val string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(val))
	switch norm {
	case "public", "user":
		return norm, nil
	default:
		return "user", fmt.Errorf("invalid access_mode %q: must be 'public' or 'user'", val)
	}
}

// ValidateUnknownDomainPolicy validates and normalizes the unknown domain policy ("reject" or "allow_default_port").
// On invalid value, it returns the provided fallback and an error.
func ValidateUnknownDomainPolicy(val string, fallback string) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(val))
	switch norm {
	case "reject", "allow_default_port":
		return norm, nil
	default:
		if fallback == "" {
			fallback = "reject"
		}
		return fallback, fmt.Errorf("invalid unknown_domain_policy %q: must be 'reject' or 'allow_default_port'", val)
	}
}

// Load reads and parses the YAML file at path, then merges in defaults
// for any fields that were left unset. Returns a validated Config or an error.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — use all defaults.
			return &cfg, nil
		}
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	// Unmarshal on top of defaults so unset keys keep their default values.
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	// Override relay_ip from RELAY_IP environment variable if provided.
	if envRelayIP := os.Getenv("RELAY_IP"); envRelayIP != "" {
		cfg.DNS.RelayIP = envRelayIP
	}

	// Override access_mode from ACCESS_MODE environment variable if provided.
	// This allows switching between 'public' and 'user' mode at deploy-time
	// without rebuilding the image.
	if envAccessMode := os.Getenv("ACCESS_MODE"); envAccessMode != "" {
		cfg.AccessMode = strings.ToLower(strings.TrimSpace(envAccessMode))
	}

	// Override unknown_domain_policy from UNKNOWN_DOMAIN_POLICY environment variable if provided.
	if envPolicy := os.Getenv("UNKNOWN_DOMAIN_POLICY"); envPolicy != "" {
		cfg.UnknownDomainPolicy = strings.ToLower(strings.TrimSpace(envPolicy))
	}

	// Override panel path from PANEL_PATH or PANEL_ADMIN_PATH environment variable if provided.
	if envPanelPath := os.Getenv("PANEL_PATH"); envPanelPath != "" {
		cfg.Panel.Path = envPanelPath
	} else if envPanelPath := os.Getenv("PANEL_ADMIN_PATH"); envPanelPath != "" {
		cfg.Panel.Path = envPanelPath
	}

	cfg.Panel.Path = NormalizePanelPath(cfg.Panel.Path)

	// Override timezone from TIMEZONE environment variable if provided.
	if envTZ := os.Getenv("TIMEZONE"); envTZ != "" {
		cfg.Timezone = strings.TrimSpace(envTZ)
	}

	// Load egress proxy configuration from environment variables.
	egressEnabled := os.Getenv("EGRESS_PROXY_ENABLED")
	cfg.EgressProxy = EgressProxyConfig{
		Enabled:  strings.EqualFold(egressEnabled, "true") || egressEnabled == "1",
		Addr:     os.Getenv("EGRESS_PROXY_ADDR"),
		User:     os.Getenv("EGRESS_PROXY_USER"),
		Password: os.Getenv("EGRESS_PROXY_PASSWORD"),
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if len(cfg.Listen.Ports) == 0 {
		return fmt.Errorf("listen.ports must not be empty")
	}
	for _, p := range cfg.Listen.Ports {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("listen port %d is out of range", p)
		}
	}
	for _, p := range cfg.Listen.HTTPPorts {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("listen http_port %d is out of range", p)
		}
	}
	if len(cfg.AllowedDestPorts) == 0 {
		return fmt.Errorf("allowed_dest_ports must not be empty")
	}
	for _, p := range cfg.AllowedDestPorts {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("allowed_dest_port %d is out of range", p)
		}
	}
	if cfg.Limits.MaxGlobalConnections <= 0 {
		return fmt.Errorf("limits.max_global_connections must be positive")
	}
	if cfg.Limits.MaxConnectionsPerIP <= 0 {
		return fmt.Errorf("limits.max_connections_per_ip must be positive")
	}
	if cfg.Logging.Format != "json" && cfg.Logging.Format != "text" {
		return fmt.Errorf("logging.format must be 'json' or 'text'")
	}
	if cfg.UnknownDomainPolicy != "reject" && cfg.UnknownDomainPolicy != "allow_default_port" {
		return fmt.Errorf("unknown_domain_policy must be 'reject' or 'allow_default_port'")
	}
	if cfg.EgressProxy.Enabled && cfg.EgressProxy.Addr == "" {
		return fmt.Errorf("egress proxy is enabled but EGRESS_PROXY_ADDR is empty")
	}
	if cfg.AccessMode != "public" && cfg.AccessMode != "user" {
		return fmt.Errorf("access_mode must be 'public' or 'user'")
	}
	if cfg.SQLite.Path == "" {
		return fmt.Errorf("sqlite.path must not be empty")
	}
	if cfg.Users.DefaultMaxIPs < 1 {
		return fmt.Errorf("users.default_max_ips must be at least 1")
	}
	return nil
}

// ResolveSetting resolves a setting value according to strict startup precedence:
// 1. Explicit environment variable value (if non-empty)
// 2. Value stored in SQLite DB (if dbFound is true and dbVal is non-empty)
// 3. Fallback default value (from config.yaml or hardcoded default)
func ResolveSetting(envVal string, dbVal string, dbFound bool, fallbackVal string) string {
	if strings.TrimSpace(envVal) != "" {
		return strings.TrimSpace(envVal)
	}
	if dbFound && strings.TrimSpace(dbVal) != "" {
		return strings.TrimSpace(dbVal)
	}
	return strings.TrimSpace(fallbackVal)
}
