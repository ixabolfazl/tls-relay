package panel

import "crypto/rand"

// cryptoRandRead is a thin alias so panel.go can call it without importing
// crypto/rand directly (keeping the import in one file).
func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}
