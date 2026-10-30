package domain

import "time"

// Session is a server-side authentication session. `ExpiresAt` carries the
// sliding idle deadline and is advanced on every successful lookup;
// `AbsoluteExpiresAt` is set at issue time and never moves, so an attacker
// with a stolen cookie cannot keep a session alive indefinitely by pinging
// it.
type Session struct {
	ID                string
	UserID            string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}
