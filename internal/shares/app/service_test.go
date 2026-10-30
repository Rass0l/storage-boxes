package app

import "testing"

func TestCreateShareInputZeroValue(t *testing.T) {
	var in CreateShareInput
	if in.BoxID != "" {
		t.Fatal("expected zero value")
	}
}
