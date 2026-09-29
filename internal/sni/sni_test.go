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

func buildHandshakePayload(hostname string) []byte {
	raw := buildClientHello(hostname)
	// Strip 5-byte TLS record header, returning raw handshake message
	return raw[5:]
}

func makeRecord(contentType byte, payload []byte) []byte {
	rec := []byte{
		contentType,
		0x03, 0x01,
		byte(len(payload) >> 8),
		byte(len(payload)),
	}
	return append(rec, payload...)
}

func TestReadSNI_FragmentedAcrossTwoRecords(t *testing.T) {
	want := "fragmented.example.com"
	hs := buildHandshakePayload(want)

	splitIdx := 25
	rec1 := makeRecord(0x16, hs[:splitIdx])
	rec2 := makeRecord(0x16, hs[splitIdx:])
	allBytes := append(rec1, rec2...)

	peeked, got, err := sni.ReadSNI(bytes.NewReader(allBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !bytes.Equal(peeked, allBytes) {
		t.Errorf("peeked bytes mismatch: got %d bytes, want %d bytes", len(peeked), len(allBytes))
	}
}

func TestReadSNI_FragmentedAcrossThreeRecords_SplitInsideSNI(t *testing.T) {
	want := "split-inside-sni.test.internal"
	hs := buildHandshakePayload(want)

	// Find the hostname inside hs to split precisely inside the SNI name
	nameIdx := bytes.Index(hs, []byte(want))
	if nameIdx == -1 {
		t.Fatal("could not find hostname inside handshake payload")
	}

	split1 := nameIdx - 5 // split before extension
	split2 := nameIdx + 5 // split right inside hostname

	rec1 := makeRecord(0x16, hs[:split1])
	rec2 := makeRecord(0x16, hs[split1:split2])
	rec3 := makeRecord(0x16, hs[split2:])
	allBytes := append(append(rec1, rec2...), rec3...)

	peeked, got, err := sni.ReadSNI(bytes.NewReader(allBytes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !bytes.Equal(peeked, allBytes) {
		t.Errorf("peeked bytes mismatch")
	}
}

func TestReadSNI_NonHandshakeRecordInMiddle(t *testing.T) {
	want := "example.com"
	hs := buildHandshakePayload(want)

	rec1 := makeRecord(0x16, hs[:20])
	rec2 := makeRecord(0x15, []byte{0x02, 0x28}) // Alert record (0x15) in the middle
	allBytes := append(rec1, rec2...)

	_, _, err := sni.ReadSNI(bytes.NewReader(allBytes))
	if !errors.Is(err, sni.ErrNotTLS) {
		t.Errorf("expected ErrNotTLS for non-handshake record in middle, got %v", err)
	}
}

func TestReadSNI_OversizedHandshakeMessage(t *testing.T) {
	// Construct record with handshake header claiming 40 KiB (> 32 KiB cap)
	rec := makeRecord(0x16, []byte{
		0x01,             // ClientHello
		0x00, 0xa0, 0x00, // 40960 bytes
		0x03, 0x03,
	})

	_, _, err := sni.ReadSNI(bytes.NewReader(rec))
	if !errors.Is(err, sni.ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestReadSNI_TooManyFragments(t *testing.T) {
	want := "fragment.limit.test"
	hs := buildHandshakePayload(want)

	// First record has 10 bytes (valid handshake header + some body)
	var allBytes []byte
	allBytes = append(allBytes, makeRecord(0x16, hs[:10])...)
	pos := 10
	// 7 more records with 2 bytes each (total 8 records so far)
	for i := 0; i < 7; i++ {
		allBytes = append(allBytes, makeRecord(0x16, hs[pos:pos+2])...)
		pos += 2
	}
	// 9th record with remainder
	allBytes = append(allBytes, makeRecord(0x16, hs[pos:])...)

	_, _, err := sni.ReadSNI(bytes.NewReader(allBytes))
	if !errors.Is(err, sni.ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge when fragments exceed 8 records, got %v", err)
	}
}
