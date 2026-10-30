package crypto

import "crypto/rand"

func NewNonce(n int) ([]byte, error) {
	out := make([]byte, n)
	_, err := rand.Read(out)
	return out, err
}
