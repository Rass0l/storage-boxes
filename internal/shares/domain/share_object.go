package domain

import "time"

// ShareObject is the staged encrypted copy of a shared file. The bytes on
// disk are AES-256-GCM sealed under a per-share key that is itself wrapped
// by the server master key and stored in WrappedShareKey. This separation
// is what lets revocation and expiry operate independently of the original
// vault file: deleting the share object renders the share payload
// unreadable without touching vault.
type ShareObject struct {
	ID              string
	ShareID         string
	StorageKey      string
	WrappedShareKey []byte
	Nonce           []byte
	SizeBytes       int64
	ContentType     string
	OriginalName    string
	CreatedAt       time.Time
}
