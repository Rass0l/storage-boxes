package domain

type Role struct {
	Name string
}

type RoleBinding struct {
	UserID string
	Role   string
}
