package domain

type Credential struct {
	UserID        string
	PasswordHash  string
	HashAlgorithm string
	HashVersion   int
}
