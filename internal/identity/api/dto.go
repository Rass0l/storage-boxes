package api

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	User      UserResponse `json:"user"`
	CSRFToken string       `json:"csrf_token,omitempty"`
}

type MeResponse struct {
	User UserResponse `json:"user"`
}

type CreateUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type UserResponse struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name,omitempty"`
	Roles       []string `json:"roles,omitempty"`
}

type UserListResponse struct {
	Items []UserResponse `json:"items"`
}
