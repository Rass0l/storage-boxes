package app

import "testing"

func TestCreateBoxInputZeroValue(t *testing.T) {
	var in CreateBoxInput
	if in.Name != "" {
		t.Fatal("expected zero value")
	}
}
