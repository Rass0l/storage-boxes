package domain

type FileObject struct {
	ID          string
	FileEntryID string
	StorageKey  string
	SizeBytes   int64
}
