package domain

import (
	"crypto/sha256"
	"encoding/hex"
)

const ShareTokenBytes = 32

func HashShareToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
