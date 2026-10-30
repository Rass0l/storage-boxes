package app

type TokenService interface {
	NewShareToken() (string, error)
}
