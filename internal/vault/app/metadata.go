package app

type MetadataVisibility string

const (
	MetadataVisibleWithoutUnlock MetadataVisibility = "visible_without_unlock"
	MetadataEncryptedAtRest      MetadataVisibility = "encrypted_at_rest"
)
