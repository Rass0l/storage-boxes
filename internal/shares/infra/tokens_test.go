package infra

import "testing"

func TestRandomTokenService(t *testing.T) {
	token, err := (RandomTokenService{}).NewShareToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("expected token")
	}
}
