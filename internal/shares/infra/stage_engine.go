package infra

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
	vaultapp "github.com/Rass0l/storage-boxes/internal/vault/app"
	"github.com/Rass0l/storage-boxes/internal/vault/crypto"
	vaultdomain "github.com/Rass0l/storage-boxes/internal/vault/domain"
)

// ShareStageEngine copies + re-encrypts vault blobs under a fresh per-share
// key so that share lifecycle (revocation, expiry, purge) does not touch
// the original vault file. The share key itself is wrapped under the
// server master key so stage blobs remain encrypted at rest.
//
// Layout on disk: Root/<shareID prefix first 2 hex chars>/<storageKey>
// Each blob file is nonce || ciphertext (same framing as vault engine).
type ShareStageEngine struct {
	Root         string
	MasterKey    []byte // 32 bytes derived from SERVER_MASTER_KEY
	VaultService *vaultapp.Service
	Files        app.FileLookup
	mu           sync.Mutex
}

var _ app.StageEngine = (*ShareStageEngine)(nil)
var _ app.FileLookup = (*VaultFileLookup)(nil)

// NewShareStageEngine configures a stage engine. The master key must be 32
// bytes; callers typically derive it via SHA-256 of a stable server key.
func NewShareStageEngine(root string, masterKey []byte, vault *vaultapp.Service) *ShareStageEngine {
	return &ShareStageEngine{Root: root, MasterKey: masterKey, VaultService: vault}
}

// VaultFileLookup adapts vault.Service to the FileLookup interface.
type VaultFileLookup struct{ V *vaultapp.Service }

func (l *VaultFileLookup) LookupFile(ctx context.Context, boxID, fileID string) (app.FileMeta, error) {
	entries, err := l.V.ListFiles(ctx, boxID)
	if err != nil {
		return app.FileMeta{}, err
	}
	for _, e := range entries {
		if e.ID == fileID {
			if e.ContentType == vaultapp.FolderContentType {
				return app.FileMeta{}, fmt.Errorf("cannot share a folder")
			}
			return app.FileMeta{Name: e.Name, ContentType: e.ContentType, SizeBytes: e.SizeBytes}, nil
		}
	}
	return app.FileMeta{}, fmt.Errorf("file not in box")
}

func (e *ShareStageEngine) Stage(ctx context.Context, boxID, fileID string, unlockBMK []byte) (app.StagedPayload, error) {
	if e.Root == "" {
		return app.StagedPayload{}, errors.New("share stage root not configured")
	}
	if e.VaultService == nil {
		return app.StagedPayload{}, errors.New("vault service not configured")
	}
	if len(e.MasterKey) != 32 {
		return app.StagedPayload{}, errors.New("share stage master key must be 32 bytes")
	}
	entry, body, err := e.VaultService.ReadToBuffer(ctx, boxID, fileID, unlockBMK)
	if err != nil {
		return app.StagedPayload{}, err
	}
	// Fresh per-share key.
	shareKey := make([]byte, 32)
	if _, err := rand.Read(shareKey); err != nil {
		return app.StagedPayload{}, err
	}
	nonce, ct, err := crypto.SealWithKEK(shareKey, body)
	if err != nil {
		return app.StagedPayload{}, err
	}
	// Wrap the share key under MasterKey so it can rest in the DB.
	wrapNonce, wrappedKey, err := crypto.SealWithKEK(e.MasterKey, shareKey)
	if err != nil {
		return app.StagedPayload{}, err
	}
	storageKey := hex.EncodeToString(randomBytes(12))
	dir := e.shardDir(storageKey)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return app.StagedPayload{}, err
	}
	blob := append(append([]byte{}, nonce...), ct...)
	path := filepath.Join(dir, storageKey)
	tmp := path + ".tmp"
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return app.StagedPayload{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return app.StagedPayload{}, err
	}
	// Stash wrap nonce + wrapped key together so Open can reverse it.
	combined := append(append([]byte{}, wrapNonce...), wrappedKey...)
	return app.StagedPayload{
		StorageKey:      storageKey,
		WrappedShareKey: combined,
		Nonce:           nonce,
		SizeBytes:       int64(len(body)),
		ContentType:     entry.ContentType,
		OriginalName:    entry.Name,
	}, nil
}

func (e *ShareStageEngine) Delete(ctx context.Context, shareID, storageKey string) error {
	_ = ctx
	_ = shareID
	if e.Root == "" || storageKey == "" {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	path := filepath.Join(e.shardDir(storageKey), storageKey)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (e *ShareStageEngine) Open(ctx context.Context, storageKey string, wrappedShareKey, nonce []byte) (io.ReadCloser, error) {
	_ = ctx
	if e.Root == "" {
		return nil, errors.New("share stage root not configured")
	}
	if len(wrappedShareKey) < 13 {
		return nil, errors.New("wrapped share key truncated")
	}
	wrapNonce := wrappedShareKey[:12]
	wrappedKey := wrappedShareKey[12:]
	shareKey, err := crypto.OpenWithKEK(e.MasterKey, wrapNonce, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap share key: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(e.shardDir(storageKey), storageKey))
	if err != nil {
		return nil, err
	}
	if len(raw) < 12 {
		return nil, errors.New("corrupt share blob")
	}
	// The share-object row preserved the original seal nonce separately, but
	// our write layout also prefixes the ciphertext with the same nonce, so
	// we accept either framing and favour the on-disk nonce.
	_ = nonce
	pt, err := crypto.OpenWithKEK(shareKey, raw[:12], raw[12:])
	if err != nil {
		return nil, fmt.Errorf("decrypt share blob: %w", err)
	}
	return io.NopCloser(bytes.NewReader(pt)), nil
}

func (e *ShareStageEngine) shardDir(storageKey string) string {
	shard := "00"
	if len(storageKey) >= 2 {
		shard = storageKey[:2]
	}
	return filepath.Join(e.Root, shard)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Ensure vault types are imported; unused import guard.
var _ = vaultdomain.FileEntry{}
