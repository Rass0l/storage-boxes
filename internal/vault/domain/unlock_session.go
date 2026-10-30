package domain

import "time"

type UnlockSession struct {
	ID        string
	BoxID     string
	UserID    string
	ExpiresAt time.Time
}
