// Package sni extracts the Server Name Indication (SNI) hostname from a raw
// TLS ClientHello record without terminating or modifying the TLS session.
//
// Parsing follows RFC 5246 (TLS record layer) and RFC 6066 (TLS extensions
// including SNI). It is intentionally hand-rolled to avoid any dependency on
// crypto/tls (which would terminate the handshake).
package sni

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// maxClientHelloSize is the maximum number of bytes we are willing to buffer
// while looking for an SNI. A TLS record can be up to 16 KiB; we cap at 16 KiB
// + 5-byte header to be safe.
const maxClientHelloSize = 16*1024 + 5

// Common sentinel errors.
var (
	ErrNotTLS          = errors.New("not a TLS ClientHello")
	ErrNoSNI           = errors.New("no SNI extension in ClientHello")
	ErrMessageTooLarge = errors.New("TLS record exceeds maximum allowed size")
)

// ReadSNI reads the minimum necessary bytes from r, returns the raw bytes that
// were read (so the caller can replay them verbatim to the destination), and
// the extracted SNI hostname.
//
// r must already have an appropriate read deadline set by the caller.
func ReadSNI(r io.Reader) (peeked []byte, hostname string, err error) {
	// -----------------------------------------------------------------------
	// TLS Record header: 5 bytes
	//   [0]    content type  (0x16 = handshake)
	//   [1][2] protocol version (major.minor, e.g. 0x03 0x01 for TLS 1.0)
	//   [3][4] length of the record payload (big-endian uint16)
	// -----------------------------------------------------------------------
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, "", fmt.Errorf("reading TLS record header: %w", err)
	}

	// Content type must be 0x16 (handshake).
	if hdr[0] != 0x16 {
		return hdr, "", ErrNotTLS
	}
	// Version major byte must be 0x03 (SSL 3.0 / TLS 1.x / TLS 1.3 compat).
	if hdr[1] != 0x03 {
		return hdr, "", ErrNotTLS
	}

	recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recordLen > maxClientHelloSize {
		return hdr, "", ErrMessageTooLarge
	}

	payload := make([]byte, recordLen)
	if _, err = io.ReadFull(r, payload); err != nil {
		return append(hdr, payload...), "", fmt.Errorf("reading TLS record payload: %w", err)
	}
	raw := append(hdr, payload...)

	// -----------------------------------------------------------------------
	// Handshake message layout inside the record payload:
	//   [0]    handshake type (0x01 = ClientHello)
	//   [1][2][3] length of the handshake body (24-bit big-endian)
	// -----------------------------------------------------------------------
	if len(payload) < 4 {
		return raw, "", ErrNotTLS
	}
	if payload[0] != 0x01 { // not ClientHello
		return raw, "", ErrNotTLS
	}

	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	needed := 4 + hsLen

	const maxTotalHandshake = 32 * 1024
	if needed > maxTotalHandshake {
		return raw, "", ErrMessageTooLarge
	}

	// Fragmented ClientHello across consecutive records (up to 8 records and 32 KiB total)
	recordsRead := 1
	for len(payload) < needed {
		recordsRead++
		if recordsRead > 8 {
			return raw, "", ErrMessageTooLarge
		}

		recHdr := make([]byte, 5)
		if _, err = io.ReadFull(r, recHdr); err != nil {
			return raw, "", fmt.Errorf("reading TLS record header: %w", err)
		}
		raw = append(raw, recHdr...)

		if recHdr[0] != 0x16 {
			return raw, "", ErrNotTLS
		}
		if recHdr[1] != 0x03 {
			return raw, "", ErrNotTLS
		}

		recLen := int(binary.BigEndian.Uint16(recHdr[3:5]))
		if recLen > maxClientHelloSize || len(raw)+recLen > maxTotalHandshake {
			return raw, "", ErrMessageTooLarge
		}

		recPayload := make([]byte, recLen)
		if _, err = io.ReadFull(r, recPayload); err != nil {
			return raw, "", fmt.Errorf("reading TLS record payload: %w", err)
		}
		raw = append(raw, recPayload...)
		payload = append(payload, recPayload...)
	}

	body := payload[4:needed]

	// -----------------------------------------------------------------------
	// ClientHello body layout:
	//   [0][1]           ProtocolVersion (2 bytes)
	//   [2..33]          Random (32 bytes)
	//   [34]             SessionID length (1 byte)
	//   [35..34+sidLen]  SessionID
	//   next 2 bytes     CipherSuites length
	//   ...              CipherSuites
	//   1 byte           CompressionMethods length
	//   ...              CompressionMethods
	//   2 bytes          Extensions length (optional if no extensions)
	//   ...              Extensions
	// -----------------------------------------------------------------------
	pos := 0

	// ProtocolVersion (2 bytes)
	if !advance(&pos, body, 2) {
		return raw, "", ErrNotTLS
	}

	// Random (32 bytes)
	if !advance(&pos, body, 32) {
		return raw, "", ErrNotTLS
	}

	// SessionID length (1 byte) + SessionID
	if !advance(&pos, body, 1) {
		return raw, "", ErrNotTLS
	}
	sidLen := int(body[pos-1])
	if !advance(&pos, body, sidLen) {
		return raw, "", ErrNotTLS
	}

	// CipherSuites length (2 bytes) + CipherSuites
	if !advance(&pos, body, 2) {
		return raw, "", ErrNotTLS
	}
	csLen := int(binary.BigEndian.Uint16(body[pos-2 : pos]))
	if !advance(&pos, body, csLen) {
		return raw, "", ErrNotTLS
	}

	// CompressionMethods length (1 byte) + CompressionMethods
	if !advance(&pos, body, 1) {
		return raw, "", ErrNotTLS
	}
	cmLen := int(body[pos-1])
	if !advance(&pos, body, cmLen) {
		return raw, "", ErrNotTLS
	}

	// Extensions — may be absent entirely (very old clients).
	if pos+2 > len(body) {
		return raw, "", ErrNoSNI
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+extTotalLen > len(body) {
		return raw, "", fmt.Errorf("%w: extensions block truncated", ErrNotTLS)
	}

	extData := body[pos : pos+extTotalLen]
	hostname, err = parseSNIExtension(extData)
	if err != nil {
		return raw, "", err
	}
	return raw, hostname, nil
}

// parseSNIExtension iterates over the TLS extension list and extracts the
// hostname from the SNI extension (type 0x0000).
func parseSNIExtension(extData []byte) (string, error) {
	pos := 0
	for pos+4 <= len(extData) {
		extType := binary.BigEndian.Uint16(extData[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(extData[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > len(extData) {
			return "", fmt.Errorf("%w: extension data truncated", ErrNotTLS)
		}

		if extType == 0x0000 { // server_name extension
			return parseSNIList(extData[pos : pos+extLen])
		}
		pos += extLen
	}
	return "", ErrNoSNI
}

// parseSNIList parses the ServerNameList structure inside the SNI extension.
//
//	struct {
//	    NameType name_type;         // 1 byte: 0 = host_name
//	    opaque   HostName<1..2^16-1>;
//	} ServerName;
//
//	ServerName server_name_list<1..2^16-1>
func parseSNIList(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("%w: SNI extension too short", ErrNotTLS)
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return "", fmt.Errorf("%w: SNI list truncated", ErrNotTLS)
	}

	pos := 2
	end := 2 + listLen
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > end {
			return "", fmt.Errorf("%w: SNI name truncated", ErrNotTLS)
		}

		if nameType == 0x00 { // host_name
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}
	return "", ErrNoSNI
}

// advance moves pos forward by n bytes, returning false if that would go out
// of bounds.
func advance(pos *int, data []byte, n int) bool {
	if *pos+n > len(data) {
		return false
	}
	*pos += n
	return true
}
