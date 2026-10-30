package infra

import "testing"

func TestEncryptedFSBoxEngine(t *testing.T) {
	if (&EncryptedFSBoxEngine{}) == nil {
		t.Fatal("expected engine")
	}
}
