package helpers

type SessionFixture struct {
	UserID    string
	SessionID string
	Roles     []string
}

func NewAdminSessionFixture() SessionFixture {
	return SessionFixture{
		UserID:    "usr_admin_01",
		SessionID: "sess_admin_01",
		Roles:     []string{"admin"},
	}
}
