package rules_test

import (
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/rules"
)

func TestNormalizeDomainInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errSub  string
	}{
		// Valid cases
		{
			name:  "bare domain passthrough",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "full URL with path query fragment",
			input: "https://claude.ai/chat/d1c26f38-efb3-4dd9-9de8-7760457a19ea?foo=bar#section",
			want:  "claude.ai",
		},
		{
			name:  "URL with port",
			input: "https://example.com:8443/foo",
			want:  "example.com",
		},
		{
			name:  "host with port non-URL",
			input: "example.com:8443",
			want:  "example.com",
		},
		{
			name:  "scheme http",
			input: "http://example.com/page",
			want:  "example.com",
		},
		{
			name:  "scheme ws",
			input: "ws://example.com/socket",
			want:  "example.com",
		},
		{
			name:  "scheme wss",
			input: "wss://example.com/socket",
			want:  "example.com",
		},
		{
			name:  "scheme ftp",
			input: "ftp://example.com/files",
			want:  "example.com",
		},
		{
			name:  "bare protocol relative //",
			input: "//example.com/path",
			want:  "example.com",
		},
		{
			name:  "existing wildcard passthrough",
			input: "*.example.com",
			want:  "*.example.com",
		},
		{
			name:  "uppercase normalization",
			input: "EXAMPLE.COM",
			want:  "example.com",
		},
		{
			name:  "mixed case with wildcard and path",
			input: "HTTPS://*.Sub.Example.COM:8080/test",
			want:  "*.sub.example.com",
		},
		{
			name:  "trailing FQDN dot",
			input: "example.com.",
			want:  "example.com",
		},
		{
			name:  "userinfo stripped",
			input: "https://user:pass@example.com/",
			want:  "example.com",
		},
		{
			name:  "IDN unicode conversion to punycode",
			input: "مکان.ایران", // Persian domain
			want:  "xn--mgb3de80b.xn--mgba3a4f16a",
		},
		{
			name:  "IDN German umlaut",
			input: "münchen.de",
			want:  "xn--mnchen-3ya.de",
		},

		// Rejection cases - IP addresses
		{
			name:    "bare IPv4",
			input:   "192.168.1.1",
			wantErr: true,
			errSub:  "IP addresses are not valid SNI domains",
		},
		{
			name:    "bare IPv4 with port",
			input:   "192.168.1.1:443",
			wantErr: true,
			errSub:  "IP addresses are not valid SNI domains",
		},
		{
			name:    "bare IPv6",
			input:   "::1",
			wantErr: true,
			errSub:  "IP addresses are not valid SNI domains",
		},
		{
			name:    "bracketed IPv6",
			input:   "[::1]",
			wantErr: true,
			errSub:  "IP addresses are not valid SNI domains",
		},
		{
			name:    "bracketed IPv6 with port",
			input:   "[2001:db8::1]:443",
			wantErr: true,
			errSub:  "IP addresses are not valid SNI domains",
		},
		{
			name:    "IPv6 full URL",
			input:   "https://[2001:db8::1]:8080/path",
			wantErr: true,
			errSub:  "IP addresses are not valid SNI domains",
		},

		// Rejection cases - Wildcards
		{
			name:    "double wildcard",
			input:   "*.*.example.com",
			wantErr: true,
			errSub:  "invalid wildcard syntax",
		},
		{
			name:    "middle wildcard",
			input:   "example.*.com",
			wantErr: true,
			errSub:  "invalid wildcard syntax",
		},
		{
			name:    "prefix wildcard without dot",
			input:   "*example.com",
			wantErr: true,
			errSub:  "invalid wildcard syntax",
		},
		{
			name:    "suffix wildcard",
			input:   "foo*.example.com",
			wantErr: true,
			errSub:  "invalid wildcard syntax",
		},
		{
			name:    "wildcard alone without dot",
			input:   "*",
			wantErr: true,
			errSub:  "invalid wildcard syntax",
		},
		{
			name:    "wildcard alone with dot",
			input:   "*.",
			wantErr: true,
			errSub:  "invalid hostname syntax",
		},

		// Rejection cases - Invalid domain syntax & others
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
			errSub:  "empty domain",
		},
		{
			name:    "spaces only",
			input:   "   ",
			wantErr: true,
			errSub:  "empty domain",
		},
		{
			name:    "scheme only",
			input:   "https://",
			wantErr: true,
			errSub:  "empty domain",
		},
		{
			name:    "not a domain invalid chars",
			input:   "not a domain!!",
			wantErr: true,
			errSub:  "invalid hostname syntax",
		},
		{
			name:    "label starting with hyphen",
			input:   "-example.com",
			wantErr: true,
			errSub:  "invalid hostname syntax",
		},
		{
			name:    "label ending with hyphen",
			input:   "example-.com",
			wantErr: true,
			errSub:  "invalid hostname syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rules.NormalizeDomainInput(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeDomainInput(%q) expected error containing %q, got nil", tt.input, tt.errSub)
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("NormalizeDomainInput(%q) error = %q, want error containing %q", tt.input, err.Error(), tt.errSub)
				}
			} else {
				if err != nil {
					t.Fatalf("NormalizeDomainInput(%q) unexpected error: %v", tt.input, err)
				}
				if got != tt.want {
					t.Errorf("NormalizeDomainInput(%q) = %q, want %q", tt.input, got, tt.want)
				}
			}
		})
	}
}
