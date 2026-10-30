package domain

import "time"

type User struct {
	ID          string
	Email       string
	DisplayName string
	Status      string
	CreatedAt   time.Time
}
