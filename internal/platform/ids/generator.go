package ids

import (
	"crypto/rand"
	"encoding/hex"
)

type IDGenerator interface {
	New(prefix string) string
}

type RandomGenerator struct{}

func (RandomGenerator) New(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
