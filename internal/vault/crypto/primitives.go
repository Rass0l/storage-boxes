package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultKDFTime    uint32 = 3
	DefaultKDFMemory  uint32 = 64 * 1024
	DefaultKDFThreads uint8  = 2
	BoxMasterKeyLen          = 32
	KEKLen                   = 32
	KDFSaltLen               = 16
)

func DeriveKEK(password string, salt []byte, time, memory uint32, threads uint8) []byte {
	if time == 0 {
		time = DefaultKDFTime
	}
	if memory == 0 {
		memory = DefaultKDFMemory
	}
	if threads == 0 {
		threads = DefaultKDFThreads
	}
	return argon2.IDKey([]byte(password), salt, time, memory, threads, KEKLen)
}

func GenerateBMK() (BoxMasterKey, error) {
	k := make([]byte, BoxMasterKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return BoxMasterKey(k), nil
}

func RandomSalt() ([]byte, error) {
	b := make([]byte, KDFSaltLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// SealWithKEK wraps plaintext with AES-256-GCM under the given key.
// Returns (nonce, ciphertext-including-tag).
func SealWithKEK(kek, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if len(kek) != KEKLen {
		return nil, nil, errors.New("invalid kek length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func OpenWithKEK(kek, nonce, ciphertext []byte) ([]byte, error) {
	if len(kek) != KEKLen {
		return nil, errors.New("invalid kek length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
