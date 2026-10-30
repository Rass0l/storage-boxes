package infra

import "testing"

func TestNewMemoryCredentialStore(t *testing.T) {
	if NewMemoryCredentialStore() == nil {
		t.Fatal("expected store")
	}
}
