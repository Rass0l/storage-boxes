package api

import "time"

type CreateBoxRequest struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	Password  string `json:"password"`
}

type BoxResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	OwnerUserID string    `json:"owner_user_id"`
	SizeBytes   int64     `json:"size_bytes"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type BoxListResponse struct {
	Items []BoxResponse `json:"items"`
}

type UnlockBoxRequest struct {
	Password string `json:"password"`
}

type UnlockResponse struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type MoveFileRequest struct {
	FromPath string `json:"from_path"`
	ToPath   string `json:"to_path"`
}

type CreateFolderRequest struct {
	LogicalPath string `json:"logical_path"`
}

type FileTreeItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	LogicalPath string `json:"logical_path"`
	ContentType string `json:"content_type,omitempty"`
	Kind        string `json:"kind"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
}

type FileTreeResponse struct {
	Items []FileTreeItem `json:"items"`
}

type FileResponse struct {
	Entry FileTreeItem `json:"entry"`
}
