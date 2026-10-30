package clock

import (
	"testing"
	"time"
)

func TestFixedClock(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	if got := (FixedClock{Value: now}).Now(); !got.Equal(now) {
		t.Fatal("unexpected time")
	}
}
