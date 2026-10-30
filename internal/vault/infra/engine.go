package infra

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/crypto"
)

// MaxUploadBytes caps single-shot uploads.
const MaxUploadBytes = 100 << 20

// EncryptedFSBoxEngine persists per-file AES-256-GCM blobs under a root dir.
// The caller supplies the key (typically the unwrapped BMK).
type EncryptedFSBoxEngine struct {
	Root string
	mu   sync.Mutex
}

var _ app.BoxEngine = (*EncryptedFSBoxEngine)(nil)

func NewEncryptedFSBoxEngine(root string) *EncryptedFSBoxEngine {
	return &EncryptedFSBoxEngine{Root: root}
}

func (e *EncryptedFSBoxEngine) boxDir(boxID string) string {
	return filepath.Join(e.Root, boxID)
}

func (e *EncryptedFSBoxEngine) CreateBox(ctx context.Context, boxID string, sizeBytes int64) error {
	_ = ctx
	_ = sizeBytes
	if e.Root == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return os.MkdirAll(e.boxDir(boxID), 0o700)
}

func (e *EncryptedFSBoxEngine) DeleteBox(ctx context.Context, boxID string) error {
	_ = ctx
	if e.Root == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return os.RemoveAll(e.boxDir(boxID))
}

func (e *EncryptedFSBoxEngine) UnlockBox(ctx context.Context, boxID string) error {
	_ = ctx
	_ = boxID
	return nil
}

func (e *EncryptedFSBoxEngine) LockBox(ctx context.Context, boxID string) error {
	_ = ctx
	_ = boxID
	return nil
}

func (e *EncryptedFSBoxEngine) WriteBlob(ctx context.Context, boxID, storageKey string, content io.Reader, key []byte) (int64, error) {
	_ = ctx
	if e.Root == "" {
		return 0, errors.New("engine root not configured")
	}
	buf := &bytes.Buffer{}
	n, err := io.Copy(buf, io.LimitReader(content, MaxUploadBytes+1))
	if err != nil {
		return 0, err
	}
	if n > MaxUploadBytes {
		return 0, fmt.Errorf("upload exceeds %d bytes", MaxUploadBytes)
	}
	nonce, ct, err := crypto.SealWithKEK(key, buf.Bytes())
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(e.boxDir(boxID), 0o700); err != nil {
		return 0, err
	}
	path := filepath.Join(e.boxDir(boxID), storageKey)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write(nonce); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	if _, err := f.Write(ct); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, err
	}
	return n, nil
}

func (e *EncryptedFSBoxEngine) ReadBlob(ctx context.Context, boxID, storageKey string, key []byte) (io.ReadCloser, error) {
	_ = ctx
	if e.Root == "" {
		return nil, errors.New("engine root not configured")
	}
	raw, err := os.ReadFile(filepath.Join(e.boxDir(boxID), storageKey))
	if err != nil {
		return nil, err
	}
	if len(raw) < 12 {
		return nil, errors.New("corrupt blob")
	}
	pt, err := crypto.OpenWithKEK(key, raw[:12], raw[12:])
	if err != nil {
		return nil, fmt.Errorf("decrypt blob: %w", err)
	}
	return io.NopCloser(bytes.NewReader(pt)), nil
}

func (e *EncryptedFSBoxEngine) DeleteBlob(ctx context.Context, boxID, storageKey string) error {
	_ = ctx
	if e.Root == "" {
		return nil
	}
	path := filepath.Join(e.boxDir(boxID), storageKey)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// SweepOrphans walks a single box's blob directory and removes any blob
// whose storage key is absent from the provided set of known entry IDs.
// Returns the number of blobs deleted. Safe to call while the box is live:
// the check is best-effort and a blob that appears mid-scan is simply left
// alone for the next pass.
func (e *EncryptedFSBoxEngine) SweepOrphans(ctx context.Context, boxID string, knownEntryIDs map[string]bool) (int, error) {
	_ = ctx
	if e.Root == "" {
		return 0, nil
	}
	dir := e.boxDir(boxID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		// Skip in-flight temp files — WriteBlob uses the `.tmp` suffix.
		if len(name) > 4 && name[len(name)-4:] == ".tmp" {
			continue
		}
		if knownEntryIDs[name] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
