package domain

type OutboxRecord struct {
	ID      string
	Topic   string
	Payload []byte
}
