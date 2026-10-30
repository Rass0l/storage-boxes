package domain

// BoxCryptoMaterial stores everything needed to recover the box master key
// given the box password.
type BoxCryptoMaterial struct {
	BoxID        string
	KDFAlgorithm string // e.g. "argon2id"
	KDFSalt      []byte
	KDFTime      uint32
	KDFMemory    uint32
	KDFThreads   uint8
	CipherAlgo   string // e.g. "aes-256-gcm"
	Nonce        []byte
	WrappedBMK   []byte // AEAD ciphertext of the box master key
}
