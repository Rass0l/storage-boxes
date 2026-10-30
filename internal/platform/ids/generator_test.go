package ids

import "testing"

func TestRandomGenerator(t *testing.T) {
	got := (RandomGenerator{}).New("x")
	if len(got) <= 2 {
		t.Fatalf("expected opaque id, got %q", got)
	}
}
