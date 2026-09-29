package settings_test

import (
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/settings"
)

func TestValidateSetting_Table(t *testing.T) {
	tests := []struct {
		key     string
		val     string
		wantErr bool
		wantVal string
	}{
		{"access_mode", "user", false, "user"},
		{"access_mode", "PUBLIC", false, "public"},
		{"access_mode", "invalid", true, ""},
		{"unknown_domain_policy", "reject", false, "reject"},
		{"unknown_domain_policy", "allow_default_port", false, "allow_default_port"},
		{"unknown_domain_policy", "invalid", true, ""},
		{"panel_path", "/my-panel", false, "/my-panel"},
		{"panel_path", "/", false, "/"},
		{"panel_path", "/api", true, ""},
		{"timezone", "UTC", false, "UTC"},
		{"timezone", "America/New_York", false, "America/New_York"},
		{"timezone", "NonExistent/TZ", true, ""},
		{"request_logs_enabled", "true", false, "true"},
		{"request_logs_enabled", "1", false, "true"},
		{"request_logs_enabled", "false", false, "false"},
		{"request_logs_enabled", "invalid", true, ""},
		{"request_logs_retention", "7d", false, "7d"},
		{"request_logs_retention", "24h", false, "1d"},
		{"request_logs_retention", "12h", false, "12h"},
		{"request_logs_retention", "-5h", true, ""},
		{"max_connections_per_ip", "200", false, "200"},
		{"max_connections_per_ip", "0", true, ""},
		{"max_connections_per_ip", "-10", true, ""},
		{"allowed_dest_ports", "443, 80, 8443", false, "[443,80,8443]"},
		{"allowed_dest_ports", "[443, 8443]", false, "[443,8443]"},
		{"allowed_dest_ports", "70000", true, ""},
		{"egress_proxy_addr", "127.0.0.1:1080", false, "127.0.0.1:1080"},
		{"egress_proxy_addr", "socks5://10.0.0.1:1080", false, "10.0.0.1:1080"},
		{"egress_proxy_addr", "http://10.0.0.1:1080", true, ""},
		{"http_front_max_conns_per_ip", "60", false, "60"},
		{"http_front_max_global_conns", "5000", false, "5000"},
		{"unknown_key", "val", true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			got, err := settings.ValidateSetting(tc.key, tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateSetting(%q, %q) error = %v, wantErr %v", tc.key, tc.val, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.wantVal {
				t.Errorf("ValidateSetting(%q, %q) = %q, want %q", tc.key, tc.val, got, tc.wantVal)
			}
		})
	}
}

func TestParseDurationWithDays(t *testing.T) {
	d, err := settings.ParseDurationWithDays("7d")
	if err != nil || d != 7*24*time.Hour {
		t.Errorf("expected 7d to equal 168h, got %v, err %v", d, err)
	}

	d, err = settings.ParseDurationWithDays("12h")
	if err != nil || d != 12*time.Hour {
		t.Errorf("expected 12h, got %v, err %v", d, err)
	}
}
