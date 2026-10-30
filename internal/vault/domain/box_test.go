package domain

import "testing"

func TestBoxZeroValue(t *testing.T) {
	var box Box
	if box.ID != "" {
		t.Fatal("expected zero value")
	}
}
