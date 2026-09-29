// Package httphost peeks initial HTTP/1.x request headers to extract the Host
// header without consuming or mutating the underlying protocol stream.
package httphost

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/textproto"
	"strings"
)

// maxHeaderSize is the maximum number of bytes we buffer while peeking HTTP headers.
// Mirrors internal/sni maxClientHelloSize (16 KiB + 5 bytes).
const maxHeaderSize = 16*1024 + 5

// Common sentinel errors.
var (
	ErrNotHTTP        = errors.New("not a valid HTTP request")
	ErrNoHost         = errors.New("missing Host header")
	ErrHeaderTooLarge = errors.New("HTTP headers exceed maximum allowed size")
	ErrAmbiguousHost  = errors.New("ambiguous Host header or request target")
)

// ReadHostAndRequestLine reads up to maxHeaderSize bytes from r, returning all
// peeked bytes verbatim, the normalized Host header value, and any error encountered.
//
// r must already have an appropriate read deadline set by the caller if needed.
func ReadHostAndRequestLine(r io.Reader) (peeked []byte, host string, err error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)

	headerEnd := -1
	headerEndLen := 0

	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxHeaderSize {
				return buf, "", ErrHeaderTooLarge
			}

			// Check for end of HTTP headers (\r\n\r\n or \n\n)
			if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx != -1 {
				headerEnd = idx
				headerEndLen = 4
				break
			}
			if idx := bytes.Index(buf, []byte("\n\n")); idx != -1 {
				headerEnd = idx
				headerEndLen = 2
				break
			}
		}

		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				// Unexpected EOF before end of headers
				if len(buf) == 0 {
					return nil, "", ErrNotHTTP
				}
				// Try to parse what we have if EOF reached
				break
			}
			return buf, "", rerr
		}
	}

	if len(buf) == 0 {
		return nil, "", ErrNotHTTP
	}

	// Work with header bytes up to headerEnd (or full buffer if truncated EOF)
	headerBytes := buf
	if headerEnd != -1 {
		headerBytes = buf[:headerEnd+headerEndLen]
	}

	// Use bufio.Reader / textproto to parse HTTP request line & headers
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerBytes)))

	reqLine, err := tp.ReadLine()
	if err != nil {
		return buf, "", ErrNotHTTP
	}

	// Validate request line: MUST be "METHOD PATH HTTP/1.X"
	parts := strings.Fields(reqLine)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return buf, "", ErrNotHTTP
	}

	// Read MIME headers
	headers, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return buf, "", ErrNotHTTP
	}

	hostHeaders := headers["Host"]
	if len(hostHeaders) == 0 {
		return buf, "", ErrNoHost
	}
	if len(hostHeaders) > 1 {
		return buf, "", ErrAmbiguousHost
	}

	hostHeader := hostHeaders[0]
	if strings.Contains(hostHeader, ",") {
		return buf, "", ErrAmbiguousHost
	}

	normalizedHost := normalizeHost(hostHeader)
	if normalizedHost == "" {
		return buf, "", ErrNoHost
	}

	// Reject absolute-form request targets whose authority differs from the Host header.
	target := parts[1]
	targetLower := strings.ToLower(target)
	if strings.HasPrefix(targetLower, "http://") || strings.HasPrefix(targetLower, "https://") {
		rest := target[strings.Index(target, "://")+3:]
		end := len(rest)
		for i, c := range rest {
			if c == '/' || c == '?' || c == '#' {
				end = i
				break
			}
		}
		authority := rest[:end]
		if atIdx := strings.LastIndex(authority, "@"); atIdx != -1 {
			authority = authority[atIdx+1:]
		}
		targetHost := normalizeHost(authority)
		if targetHost != normalizedHost {
			return buf, "", ErrAmbiguousHost
		}
	}

	return buf, normalizedHost, nil
}

// normalizeHost fast-normalizes the Host header for the per-connection hot path:
// strips port if present, handles bracketed IPv6 literals, trims spaces/dots, and lowercases.
// Critical invariant: NEVER call rules.NormalizeDomainInput from the hot path.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}

	// Handle bracketed IPv6 with optional port: [::1]:8080 or [::1]
	if strings.HasPrefix(h, "[") {
		closeIdx := strings.Index(h, "]")
		if closeIdx != -1 {
			ip := h[1:closeIdx]
			return strings.ToLower(ip)
		}
	}

	// Handle host:port or IP:port
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else if idx := strings.LastIndex(h, ":"); idx != -1 && !strings.Contains(h[:idx], ":") {
		h = h[:idx]
	}

	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(strings.TrimSpace(h))
}
