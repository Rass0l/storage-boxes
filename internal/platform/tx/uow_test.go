package tx

import (
	"context"
	"testing"
)

func TestNoopUnitOfWork(t *testing.T) {
	err := (NoopUnitOfWork{}).Within(context.Background(), func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
