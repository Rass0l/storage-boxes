package domain

import "testing"

func TestUserZeroValue(t *testing.T) {
	var u User
	if u.ID != "" {
		t.Fatal("expected zero value")
	}
}
