package app

import "testing"

func TestCreateUserInputZeroValue(t *testing.T) {
	var in CreateUserInput
	if in.Email != "" {
		t.Fatal("expected zero value")
	}
}
