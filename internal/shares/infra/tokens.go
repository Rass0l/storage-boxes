package infra

import (
	"crypto/rand"
	"encoding/base64"
)

type RandomTokenService struct{}

func (RandomTokenService) NewShareToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
