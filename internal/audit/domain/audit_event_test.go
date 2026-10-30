package domain

import "testing"

func TestAuditEventZeroValue(t *testing.T) {
	var evt AuditEvent
	if evt.ID != "" {
		t.Fatal("expected zero value")
	}
}
