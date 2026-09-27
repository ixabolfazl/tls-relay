package httphost_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/httphost"
)

func TestReadHostAndRequestLine_Valid(t *testing.T) {
	tests := []struct {
		name         string
		rawInput     string
		expectedHost string
	}{
		{
			name:         "Standard GET request",
			rawInput:     "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
			expectedHost: "example.com",
		},
		{
			name:         "Host with port suffix",
			rawInput:     "POST /api/login HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 0\r\n\r\n",
			expectedHost: "example.com",
		},
		{
			name:         "Uppercase host",
			rawInput:     "GET / HTTP/1.1\r\nHost: MySub.Example.ORG:80\r\n\r\n",
			expectedHost: "mysub.example.org",
		},
		{
			name:         "IPv6 Host without port",
			rawInput:     "GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n",
			expectedHost: "::1",
		},
		{
			name:         "IPv6 Host with port",
			rawInput:     "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
			expectedHost: "::1",
		},
		{
			name:         "LF only newlines",
			rawInput:     "GET / HTTP/1.0\nHost: unix.example.com\n\n",
			expectedHost: "unix.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peeked, host, err := httphost.ReadHostAndRequestLine(bytes.NewBufferString(tt.rawInput))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if host != tt.expectedHost {
				t.Errorf("expected host %q, got %q", tt.expectedHost, host)
			}
			if string(peeked) != tt.rawInput {
				t.Errorf("expected peeked bytes to equal raw input")
			}
		})
	}
}

func TestReadHostAndRequestLine_Errors(t *testing.T) {
	tests := []struct {
		name        string
		rawInput    string
		expectedErr error
	}{
		{
			name:        "Garbage non-HTTP input",
			rawInput:    "\x16\x03\x01\x00\x05hello world",
			expectedErr: httphost.ErrNotHTTP,
		},
		{
			name:        "Missing Host header",
			rawInput:    "GET / HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\n\r\n",
			expectedErr: httphost.ErrNoHost,
		},
		{
			name:        "Invalid HTTP version",
			rawInput:    "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n",
			expectedErr: httphost.ErrNotHTTP,
		},
		{
			name:        "Empty input",
			rawInput:    "",
			expectedErr: httphost.ErrNotHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peeked, host, err := httphost.ReadHostAndRequestLine(bytes.NewBufferString(tt.rawInput))
			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("expected error %v, got %v", tt.expectedErr, err)
			}
			if host != "" {
				t.Errorf("expected empty host on error, got %q", host)
			}
			if string(peeked) != tt.rawInput && tt.rawInput != "" {
				t.Errorf("expected peeked bytes to match input")
			}
		})
	}
}

func TestReadHostAndRequestLine_HeaderTooLarge(t *testing.T) {
	// Generate headers exceeding 16KB
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\nHost: example.com\r\n")
	for i := 0; i < 500; i++ {
		sb.WriteString(fmt.Sprintf("X-Long-Header-%d: %s\r\n", i, strings.Repeat("A", 100)))
	}
	sb.WriteString("\r\n")

	_, _, err := httphost.ReadHostAndRequestLine(bytes.NewBufferString(sb.String()))
	if !errors.Is(err, httphost.ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge, got %v", err)
	}
}

func TestReadHostAndRequestLine_SlowReader(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: slow.example.com\r\n\r\n"
	sr := &slowReader{data: []byte(raw), chunkSize: 5}

	peeked, host, err := httphost.ReadHostAndRequestLine(sr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "slow.example.com" {
		t.Errorf("expected host 'slow.example.com', got %q", host)
	}
	if string(peeked) != raw {
		t.Errorf("peeked bytes mismatch")
	}
}

type slowReader struct {
	data      []byte
	pos       int
	chunkSize int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	end := s.pos + s.chunkSize
	if end > len(s.data) {
		end = len(s.data)
	}
	n := copy(p, s.data[s.pos:end])
	s.pos += n
	return n, nil
}
