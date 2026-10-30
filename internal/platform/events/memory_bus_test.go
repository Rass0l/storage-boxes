package events

import "testing"

func TestMemoryBusPublish(t *testing.T) {
	var bus MemoryBus
	if err := bus.Publish(DomainEvent{ID: "evt_1"}); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
}
