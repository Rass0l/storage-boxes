package errors

import "testing"

func TestDomainErrorError(t *testing.T) {
	err := New(CategoryValidation, "invalid_input", "bad")
	if err.Error() == "" {
		t.Fatal("expected error string")
	}
}
