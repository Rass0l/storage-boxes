package domain

import "time"

type FileEntry struct {
	ID          string
	BoxID       string
	ParentID    *string
	LogicalPath string
	Name        string
	ContentType string
	SizeBytes   int64
	CreatedAt   time.Time
}
