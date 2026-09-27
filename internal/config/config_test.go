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
