package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/config"
)

func TestResolveSettingPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		envVal      string
		dbVal       string
		dbFound     bool
		fallbackVal string
		expected    string
	}{
		{
			name:        "env takes precedence over DB and fallback",
			envVal:      "public",
			dbVal:       "user",
			dbFound:     true,
			fallbackVal: "user",
			expected:    "public",
		},
		{
			name:        "DB takes precedence over fallback when env is empty",
			envVal:      "",
			dbVal:       "/admin",
			dbFound:     true,
			fallbackVal: "/",
			expected:    "/admin",
		},
		{
			name:        "fallback used when env is empty and DB not found",
			envVal:      "",
			dbVal:       "",
			dbFound:     false,
			fallbackVal: "UTC",
			expected:    "UTC",
		},
		{
			name:        "fallback used when DB is found but value is empty",
			envVal:      "",
			dbVal:       "   ",
			dbFound:     true,
			fallbackVal: "UTC",
			expected:    "UTC",
		},
		{
			name:        "whitespace trimmed from all sources",
			envVal:      "  Asia/Tehran  ",
			dbVal:       "UTC",
			dbFound:     true,
			fallbackVal: "UTC",
			expected:    "Asia/Tehran",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.ResolveSetting(tt.envVal, tt.dbVal, tt.dbFound, tt.fallbackVal)
			if got != tt.expected {
				t.Errorf("ResolveSetting(%q, %q, %v, %q) = %q; want %q",
					tt.envVal, tt.dbVal, tt.dbFound, tt.fallbackVal, got, tt.expected)
			}
		})
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty listen ports",
			yaml:    "listen:\n  ports: []",
			wantErr: "listen.ports must not be empty",
		},
		{
			name:    "invalid listen port",
			yaml:    "listen:\n  ports: [0]",
			wantErr: "listen port 0 is out of range",
		},
		{
			name:    "invalid listen http port",
			yaml:    "listen:\n  http_ports: [99999]",
			wantErr: "listen http_port 99999 is out of range",
		},
		{
			name:    "empty allowed destination ports",
			yaml:    "allowed_dest_ports: []",
			wantErr: "allowed_dest_ports must not be empty",
		},
		{
			name:    "invalid allowed destination port",
			yaml:    "allowed_dest_ports: [70000]",
			wantErr: "allowed_dest_port 70000 is out of range",
		},
		{
			name:    "negative max global connections",
			yaml:    "limits:\n  max_global_connections: 0",
			wantErr: "limits.max_global_connections must be positive",
		},
		{
			name:    "negative max connections per IP",
			yaml:    "limits:\n  max_connections_per_ip: -10",
			wantErr: "limits.max_connections_per_ip must be positive",
		},
		{
			name:    "invalid logging format",
			yaml:    "logging:\n  format: xml",
			wantErr: "logging.format must be 'json' or 'text'",
		},
		{
			name:    "invalid unknown domain policy",
			yaml:    "unknown_domain_policy: bypass",
			wantErr: "unknown_domain_policy must be 'reject' or 'allow_default_port'",
		},
		{
			name:    "invalid access mode",
			yaml:    "access_mode: admin",
			wantErr: "access_mode must be 'public' or 'user'",
		},
		{
			name:    "empty sqlite path",
			yaml:    "sqlite:\n  path: ''",
			wantErr: "sqlite.path must not be empty",
		},
		{
			name:    "invalid default max IPs",
			yaml:    "users:\n  default_max_ips: 0",
			wantErr: "users.default_max_ips must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tempDir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			_, err := config.Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestLoad_SuccessDefaults(t *testing.T) {
	// Loading non-existent file should succeed with defaults
	cfg, err := config.Load("nonexistent-file.yaml")
	if err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}

	if cfg.AccessMode != "user" {
		t.Errorf("expected default AccessMode 'user', got %q", cfg.AccessMode)
	}
	if cfg.Timezone != "UTC" {
		t.Errorf("expected default Timezone 'UTC', got %q", cfg.Timezone)
	}
}

func TestLoad_EgressProxyEnv(t *testing.T) {
	tempDir := t.TempDir()
	emptyPath := filepath.Join(tempDir, "empty.yaml")
	if err := os.WriteFile(emptyPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write empty yaml: %v", err)
	}

	t.Setenv("EGRESS_PROXY_ENABLED", "true")
	t.Setenv("EGRESS_PROXY_ADDR", "")

	// Egress enabled but no address -> should fail validation
	_, err := config.Load(emptyPath)
	if err == nil {
		t.Fatal("expected validation error for enabled egress proxy without address")
	}

	t.Setenv("EGRESS_PROXY_ADDR", "127.0.0.1:1080")
	cfg, err := config.Load(emptyPath)
	if err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}

	if !cfg.EgressProxy.Enabled {
		t.Error("expected EgressProxy.Enabled to be true")
	}
	if cfg.EgressProxy.Addr != "127.0.0.1:1080" {
		t.Errorf("expected egress proxy addr '127.0.0.1:1080', got %q", cfg.EgressProxy.Addr)
	}
}

func TestValidatePanelPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "root slash", input: "/", want: "/", wantErr: false},
		{name: "empty string normalizes to root", input: "", want: "/", wantErr: false},
		{name: "valid admin", input: "/admin", want: "/admin", wantErr: false},
		{name: "valid admin trailing slash", input: "/admin/", want: "/admin", wantErr: false},
		{name: "valid custom with hyphen and underscore", input: "/my_secret-panel_123", want: "/my_secret-panel_123", wantErr: false},
		{name: "reserved setup", input: "/setup", wantErr: true},
		{name: "reserved connect", input: "/connect", wantErr: true},
		{name: "reserved api", input: "/api", wantErr: true},
		{name: "reserved static", input: "/static", wantErr: true},
		{name: "reserved css", input: "/css", wantErr: true},
		{name: "reserved js", input: "/js", wantErr: true},
		{name: "reserved pages", input: "/pages", wantErr: true},
		{name: "reserved index.html", input: "/index.html", wantErr: true},
		{name: "invalid curly braces", input: "/{x}", wantErr: true},
		{name: "invalid space", input: "/a b", wantErr: true},
		{name: "too long path", input: "/" + strings.Repeat("a", 65), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := config.ValidatePanelPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePanelPath(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ValidatePanelPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateAccessMode(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "public", want: "public", wantErr: false},
		{input: "user", want: "user", wantErr: false},
		{input: "  PUBLIC  ", want: "public", wantErr: false},
		{input: "  User\n", want: "user", wantErr: false},
		{input: "invalid", want: "user", wantErr: true},
		{input: "", want: "user", wantErr: true},
	}

	for _, tt := range tests {
		got, err := config.ValidateAccessMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateAccessMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ValidateAccessMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidateUnknownDomainPolicy(t *testing.T) {
	tests := []struct {
		input    string
		fallback string
		want     string
		wantErr  bool
	}{
		{input: "reject", fallback: "allow_default_port", want: "reject", wantErr: false},
		{input: "allow_default_port", fallback: "reject", want: "allow_default_port", wantErr: false},
		{input: "  ALLOW_DEFAULT_PORT  ", fallback: "reject", want: "allow_default_port", wantErr: false},
		{input: "unknown", fallback: "allow_default_port", want: "allow_default_port", wantErr: true},
		{input: "bad", fallback: "reject", want: "reject", wantErr: true},
	}

	for _, tt := range tests {
		got, err := config.ValidateUnknownDomainPolicy(tt.input, tt.fallback)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateUnknownDomainPolicy(%q, %q) error = %v, wantErr %v", tt.input, tt.fallback, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("ValidateUnknownDomainPolicy(%q, %q) = %q, want %q", tt.input, tt.fallback, got, tt.want)
		}
	}
}
