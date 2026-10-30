package config

import "github.com/Rass0l/storage-boxes/internal/platform/security"

func (c Config) ValidateMasterKey(required bool) error {
	if !required && c.ServerMasterKey == "" {
		return nil
	}
	return security.ValidateMasterKeyHex(c.ServerMasterKey)
}
