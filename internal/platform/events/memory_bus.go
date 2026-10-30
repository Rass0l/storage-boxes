package events

type MemoryBus struct {
	Events []DomainEvent
}

func (b *MemoryBus) Publish(event DomainEvent) error {
	b.Events = append(b.Events, event)
	return nil
}
