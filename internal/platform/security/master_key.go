package security

import (
	"encoding/hex"
	"errors"
)

func ValidateMasterKeyHex(v string) error {
	if len(v) < 64 {
		return errors.New("server master key must be at least 64 hex characters")
	}
	_, err := hex.DecodeString(v)
	return err
}
