package infra

import "testing"

func TestMemoryAuditRepository(t *testing.T) {
	if (&MemoryAuditRepository{}) == nil {
		t.Fatal("expected repository")
	}
}
