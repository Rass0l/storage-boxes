package security

import "testing"

func TestValidateMasterKeyHex(t *testing.T) {
	if err := ValidateMasterKeyHex("zz"); err == nil {
		t.Fatal("expected validation failure")
	}
}
