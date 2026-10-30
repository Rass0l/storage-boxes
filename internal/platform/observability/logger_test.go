package observability

import "testing"

func TestNewStdLogger(t *testing.T) {
	if NewStdLogger("stage1") == nil {
		t.Fatal("expected logger")
	}
}
