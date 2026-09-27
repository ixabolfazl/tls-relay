package sni_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/sni"
)

// buildClientHello constructs a minimal but valid TLS ClientHello record
// containing the given SNI hostname. If hostname is empty, the SNI extension
// is omitted.
func buildClientHello(hostname string) []byte {
	// Extensions
	var exts []byte
	if hostname != "" {
		// server_name extension (type 0x0000)
		name := []byte(hostname)
		// ServerName entry: 1 byte type + 2 byte length + name
		snEntry := make([]byte, 0, 3+len(name))
		snEntry = append(snEntry, 0x00) // host_name
		snEntry = append16(snEntry, uint16(len(name)))
		snEntry = append(snEntry, name...)

		// ServerNameList: 2 byte list length + entries
		snList := append16(nil, uint16(len(snEntry)))
		snList = append(snList, snEntry...)

		// Extension: 2 byte type + 2 byte data length + data
		ext := append16(nil, 0x0000) // type: server_name
		ext = append16(ext, uint16(len(snList)))
		ext = append(ext, snList...)
		exts = ext
	}

	// Extensions block: 2 byte total length + extensions
	extBlock := append16(nil, uint16(len(exts)))
	extBlock = append(extBlock, exts...)

	// ClientHello body
	var body []byte
	body = append(body, 0x03, 0x03)          // version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session ID length = 0
	body = append16(body, 2)                 // cipher suites length
	body = append16(body, 0x0035)            // one cipher suite
	body = append(body, 0x01, 0x00)          // compression methods: 1 method (null)
	body = append(body, extBlock...)

	// Handshake message: type + 3-byte length + body
	hsLen := len(body)
	hs := []byte{
		0x01, // ClientHello
		byte(hsLen >> 16),
		byte(hsLen >> 8),
		byte(hsLen),
	}
	hs = append(hs, body...)

	// TLS record: content type + version + 2-byte length + payload
	rec := []byte{
		0x16,       // handshake
		0x03, 0x01, // TLS 1.0 compat version
		byte(len(hs) >> 8),
		byte(len(hs)),
	}
	rec = append(rec, hs...)
	return rec
}

func append16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestReadSNI_WithHostname(t *testing.T) {
	want := "example.com"
	raw := buildClientHello(want)

	peeked, got, err := sni.ReadSNI(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("hostname = %q, want %q", got, want)
	}
	if !bytes.Equal(peeked, raw) {
		t.Error("peeked bytes do not match original record bytes")
	}
}

func TestReadSNI_NoSNIExtension(t *testing.T) {
	raw := buildClientHello("") // no SNI extension
	_, _, err := sni.ReadSNI(bytes.NewReader(raw))
	if !errors.Is(err, sni.ErrNoSNI) {
		t.Errorf("expected ErrNoSNI, got %v", err)
	}
}

func TestReadSNI_NotTLS(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, _, err := sni.ReadSNI(bytes.NewReader(raw))
	if !errors.Is(err, sni.ErrNotTLS) {
		t.Errorf("expected ErrNotTLS, got %v", err)
	}
}

func TestReadSNI_TruncatedRecord(t *testing.T) {
	raw := buildClientHello("example.com")
	// Trim the record to trigger a truncated-payload read.
	_, _, err := sni.ReadSNI(bytes.NewReader(raw[:10]))
	if err == nil {
		t.Fatal("expected error for truncated record, got nil")
	}
}

func TestReadSNI_BadContentType(t *testing.T) {
	raw := buildClientHello("example.com")
	raw[0] = 0x14 // change content type to ChangeCipherSpec
	_, _, err := sni.ReadSNI(bytes.NewReader(raw))
	if !errors.Is(err, sni.ErrNotTLS) {
		t.Errorf("expected ErrNotTLS for bad content type, got %v", err)
	}
}

func TestReadSNI_OversizedRecord(t *testing.T) {
	// Build a record header claiming a 20 KiB payload (over limit).
	hdr := []byte{0x16, 0x03, 0x01, 0x50, 0x00} // 20480 bytes
	binary.BigEndian.PutUint16(hdr[3:], 20480)
	_, _, err := sni.ReadSNI(bytes.NewReader(hdr))
	if !errors.Is(err, sni.ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestReadSNI_LongHostname(t *testing.T) {
	// 253-char hostname — maximum valid DNS label.
	long := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." +
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." +
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z." +
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.com"
	if len(long) > 253 {
		long = long[:253]
	}
	raw := buildClientHello(long)
	_, got, err := sni.ReadSNI(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error for long hostname: %v", err)
	}
	if got != long {
		t.Errorf("hostname mismatch: got %q", got)
	}
}
