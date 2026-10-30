package domain

import "time"

type Box struct {
	ID          string
	OwnerUserID string
	Name        string
	SizeBytes   int64
	Status      string
	CreatedAt   time.Time
}
