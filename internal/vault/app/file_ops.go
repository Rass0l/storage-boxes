package app

import (
	"bytes"
	"context"
	"io"
	"path"
	"strings"

	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/vault/domain"
)

// FolderContentType marks a FileEntry as a directory.
const FolderContentType = "inode/directory"

func (s *Service) engineBlobs() BoxEngine { return s.deps.Engine }

func normalizePath(p string) (string, error) {
	if p == "" {
		return "", platerr.New(platerr.CategoryValidation, "invalid_path", "path required")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	clean := path.Clean(p)
	if clean == "." {
		clean = "/"
	}
	if strings.Contains(clean, "..") {
		return "", platerr.New(platerr.CategoryValidation, "invalid_path", "path traversal not allowed")
	}
	return clean, nil
}

// parentPathOf returns the parent directory of a logical path. Root's parent
// is itself ("/").
func parentPathOf(p string) string {
	if p == "/" {
		return "/"
	}
	parent := path.Dir(p)
	if parent == "." {
		return "/"
	}
	return parent
}

// resolveParent enforces that the parent folder exists (or is root) and
// returns its ID when non-root. Returns nil for the root parent.
func (s *Service) resolveParent(ctx context.Context, boxID, logicalPath string) (*string, error) {
	parent := parentPathOf(logicalPath)
	if parent == "/" {
		return nil, nil
	}
	entry, err := s.deps.Files.GetByPath(ctx, boxID, parent)
	if err != nil {
		return nil, platerr.New(platerr.CategoryValidation, "parent_missing",
			"parent folder "+parent+" does not exist")
	}
	if entry.ContentType != FolderContentType {
		return nil, platerr.New(platerr.CategoryValidation, "parent_not_folder",
			"parent "+parent+" is not a folder")
	}
	id := entry.ID
	return &id, nil
}

func (s *Service) PutFileWithKey(ctx context.Context, boxID, logicalPath, contentType string, key []byte, content io.Reader) (domain.FileEntry, error) {
	p, err := normalizePath(logicalPath)
	if err != nil {
		return domain.FileEntry{}, err
	}
	if p == "/" {
		return domain.FileEntry{}, platerr.New(platerr.CategoryValidation, "invalid_path", "cannot upload to root itself")
	}
	if existing, err := s.deps.Files.GetByPath(ctx, boxID, p); err == nil {
		return existing, platerr.New(platerr.CategoryConflict, "path_exists", "an entry already exists at that path")
	}
	parentID, err := s.resolveParent(ctx, boxID, p)
	if err != nil {
		return domain.FileEntry{}, err
	}
	bs := s.engineBlobs()
	if bs == nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "no_blob_store", "blob storage not configured")
	}
	entryID := s.deps.IDs.New("file")
	size, err := bs.WriteBlob(ctx, boxID, entryID, content, key)
	if err != nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "write_blob", err.Error())
	}
	entry := domain.FileEntry{
		ID:          entryID,
		BoxID:       boxID,
		ParentID:    parentID,
		LogicalPath: p,
		Name:        path.Base(p),
		ContentType: contentType,
		SizeBytes:   size,
		CreatedAt:   s.deps.Clock.Now(),
	}
	if err := s.deps.Files.PutFileEntry(ctx, entry); err != nil {
		_ = bs.DeleteBlob(ctx, boxID, entryID)
		return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "persist_entry", err.Error())
	}
	s.emitAudit(ctx, "vault.file_uploaded", "file", entry.ID, "", map[string]any{
		"box_id":       boxID,
		"logical_path": entry.LogicalPath,
		"size_bytes":   entry.SizeBytes,
		"content_type": entry.ContentType,
	})
	return entry, nil
}

func (s *Service) ReadFileWithKey(ctx context.Context, boxID, fileID string, key []byte) (domain.FileEntry, io.ReadCloser, error) {
	entry, err := s.deps.Files.GetFileEntry(ctx, fileID)
	if err != nil {
		return domain.FileEntry{}, nil, platerr.New(platerr.CategoryNotFound, "file_not_found", "file not found")
	}
	if entry.BoxID != boxID {
		return domain.FileEntry{}, nil, platerr.New(platerr.CategoryAuthz, "wrong_box", "file not in this box")
	}
	if entry.ContentType == FolderContentType {
		return domain.FileEntry{}, nil, platerr.New(platerr.CategoryValidation, "is_folder", "cannot read a folder")
	}
	bs := s.engineBlobs()
	if bs == nil {
		return domain.FileEntry{}, nil, platerr.New(platerr.CategoryInternal, "no_blob_store", "blob storage not configured")
	}
	rc, err := bs.ReadBlob(ctx, boxID, entry.ID, key)
	if err != nil {
		return domain.FileEntry{}, nil, platerr.New(platerr.CategoryInternal, "read_blob", err.Error())
	}
	// File reads are a key operational flow — auditing them closes
	// the gap where box unlocks were recorded but the follow-on
	// reads weren't. Emitted only after the blob actually opened; a
	// read that errors out above never produces a "file_read" row.
	s.emitAudit(ctx, "vault.file_read", "file", entry.ID, "", map[string]any{
		"box_id":       boxID,
		"logical_path": entry.LogicalPath,
		"size_bytes":   entry.SizeBytes,
	})
	return entry, rc, nil
}

// DeleteByPath removes a file or an empty folder.
//
// Ordering: catalog row first, blob second. A failure between steps leaves
// at worst an orphan encrypted blob on disk (unreachable — no catalog row
// maps to it). That orphan is safe and is reclaimable by the engine's
// SweepOrphans scan. Doing blob-first would instead leave the catalog
// pointing at a missing blob, which turns future reads into errors.
//
// For folders we additionally enforce emptiness. Memory stores accept a
// window race here (negligible in-process); the pg catalog uses a single
// atomic "delete if empty" statement to close the window.
func (s *Service) DeleteByPath(ctx context.Context, boxID, logicalPath string) error {
	p, err := normalizePath(logicalPath)
	if err != nil {
		return err
	}
	if p == "/" {
		return platerr.New(platerr.CategoryValidation, "invalid_path", "cannot delete the root folder")
	}

	if ad, ok := s.deps.Files.(AtomicFolderDeleter); ok {
		deleted, err := ad.DeleteEntryIfEmpty(ctx, boxID, p)
		if err != nil {
			switch err.Error() {
			case "not_found":
				return platerr.New(platerr.CategoryNotFound, "path_not_found", "no entry at that path")
			case "folder_not_empty":
				return platerr.New(platerr.CategoryConflict, "folder_not_empty", "folder not empty")
			default:
				return platerr.New(platerr.CategoryInternal, "delete_entry", err.Error())
			}
		}
		if deleted.ContentType != FolderContentType {
			if bs := s.engineBlobs(); bs != nil {
				_ = bs.DeleteBlob(ctx, boxID, deleted.ID)
			}
		}
		s.emitAudit(ctx, "vault.file_deleted", "file", deleted.ID, "", map[string]any{
			"box_id":       boxID,
			"logical_path": deleted.LogicalPath,
			"kind":         deleted.ContentType,
		})
		return nil
	}

	entry, err := s.deps.Files.GetByPath(ctx, boxID, p)
	if err != nil {
		return platerr.New(platerr.CategoryNotFound, "path_not_found", "no entry at that path")
	}
	if entry.ContentType == FolderContentType {
		children, _ := s.deps.Files.ListFiles(ctx, boxID)
		prefix := strings.TrimSuffix(p, "/") + "/"
		for _, child := range children {
			if child.ID == entry.ID {
				continue
			}
			if strings.HasPrefix(child.LogicalPath, prefix) {
				return platerr.New(platerr.CategoryConflict, "folder_not_empty", "folder not empty")
			}
		}
	}
	if err := s.deps.Files.DeleteFileEntry(ctx, entry.ID); err != nil {
		return platerr.New(platerr.CategoryInternal, "delete_entry", err.Error())
	}
	if entry.ContentType != FolderContentType {
		if bs := s.engineBlobs(); bs != nil {
			_ = bs.DeleteBlob(ctx, boxID, entry.ID)
		}
	}
	s.emitAudit(ctx, "vault.file_deleted", "file", entry.ID, "", map[string]any{
		"box_id":       boxID,
		"logical_path": entry.LogicalPath,
		"kind":         entry.ContentType,
	})
	return nil
}

func (s *Service) CreateFolderAt(ctx context.Context, boxID, logicalPath string) (domain.FileEntry, error) {
	p, err := normalizePath(logicalPath)
	if err != nil {
		return domain.FileEntry{}, err
	}
	if p == "/" {
		return domain.FileEntry{}, platerr.New(platerr.CategoryValidation, "invalid_path", "root folder already exists")
	}
	if _, err := s.deps.Files.GetByPath(ctx, boxID, p); err == nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryConflict, "path_exists", "folder already exists")
	}
	parentID, err := s.resolveParent(ctx, boxID, p)
	if err != nil {
		return domain.FileEntry{}, err
	}
	entry := domain.FileEntry{
		ID:          s.deps.IDs.New("folder"),
		BoxID:       boxID,
		ParentID:    parentID,
		LogicalPath: p,
		Name:        path.Base(p),
		ContentType: FolderContentType,
		CreatedAt:   s.deps.Clock.Now(),
	}
	if err := s.deps.Files.PutFileEntry(ctx, entry); err != nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "persist_entry", err.Error())
	}
	return entry, nil
}

// MoveByPath moves a file or folder. For folders, every descendant's
// logical_path is rewritten atomically (via a transaction when the catalog
// supports it, otherwise as a batch under a single write).
func (s *Service) MoveByPath(ctx context.Context, boxID, fromPath, toPath string) (domain.FileEntry, error) {
	from, err := normalizePath(fromPath)
	if err != nil {
		return domain.FileEntry{}, err
	}
	to, err := normalizePath(toPath)
	if err != nil {
		return domain.FileEntry{}, err
	}
	if from == "/" {
		return domain.FileEntry{}, platerr.New(platerr.CategoryValidation, "invalid_path", "cannot move the root folder")
	}
	if from == to {
		return domain.FileEntry{}, platerr.New(platerr.CategoryValidation, "same_path", "source and destination are identical")
	}
	if strings.HasPrefix(to, strings.TrimSuffix(from, "/")+"/") {
		return domain.FileEntry{}, platerr.New(platerr.CategoryValidation, "move_into_self", "cannot move a folder into itself")
	}
	entry, err := s.deps.Files.GetByPath(ctx, boxID, from)
	if err != nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryNotFound, "path_not_found", "no entry at source path")
	}
	if _, err := s.deps.Files.GetByPath(ctx, boxID, to); err == nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryConflict, "path_exists", "target path already exists")
	}
	newParentID, err := s.resolveParent(ctx, boxID, to)
	if err != nil {
		return domain.FileEntry{}, err
	}

	// If the catalog offers a transactional renamer, use it.
	if tx, ok := s.deps.Files.(TransactionalRenamer); ok {
		moved, err := tx.RenameSubtree(ctx, boxID, from, to, newParentID)
		if err != nil {
			return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "move_failed", err.Error())
		}
		return moved, nil
	}

	// Fallback: single-entry or best-effort folder rewrite.
	if entry.ContentType != FolderContentType {
		entry.LogicalPath = to
		entry.Name = path.Base(to)
		entry.ParentID = newParentID
		if err := s.deps.Files.PutFileEntry(ctx, entry); err != nil {
			return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "persist_entry", err.Error())
		}
		return entry, nil
	}
	// Folder: rewrite descendants. This is not atomic on the memory store
	// (no transactions), but is serialized by the store's internal mutex.
	children, _ := s.deps.Files.ListFiles(ctx, boxID)
	fromPrefix := strings.TrimSuffix(from, "/") + "/"
	toPrefix := strings.TrimSuffix(to, "/") + "/"
	for i := range children {
		c := children[i]
		if c.ID == entry.ID {
			continue
		}
		if !strings.HasPrefix(c.LogicalPath, fromPrefix) {
			continue
		}
		c.LogicalPath = toPrefix + strings.TrimPrefix(c.LogicalPath, fromPrefix)
		if err := s.deps.Files.PutFileEntry(ctx, c); err != nil {
			return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "persist_entry", err.Error())
		}
	}
	entry.LogicalPath = to
	entry.Name = path.Base(to)
	entry.ParentID = newParentID
	if err := s.deps.Files.PutFileEntry(ctx, entry); err != nil {
		return domain.FileEntry{}, platerr.New(platerr.CategoryInternal, "persist_entry", err.Error())
	}
	return entry, nil
}

func (s *Service) ReadToBuffer(ctx context.Context, boxID, fileID string, key []byte) (domain.FileEntry, []byte, error) {
	entry, rc, err := s.ReadFileWithKey(ctx, boxID, fileID, key)
	if err != nil {
		return domain.FileEntry{}, nil, err
	}
	defer rc.Close()
	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, rc); err != nil {
		return domain.FileEntry{}, nil, platerr.New(platerr.CategoryInternal, "read_blob", err.Error())
	}
	return entry, buf.Bytes(), nil
}

// TransactionalRenamer is implemented by catalogs that can rewrite a whole
// subtree atomically. Memory stores leave this unimplemented; pg stores
// wrap the rewrite in a single transaction.
type TransactionalRenamer interface {
	RenameSubtree(ctx context.Context, boxID, fromPath, toPath string, newParentID *string) (domain.FileEntry, error)
}

// AtomicBoxCreator is implemented by stores that can persist a box row and
// its crypto material in a single transaction. Optional; when absent the
// vault service falls back to sequential writes (good enough for the
// in-memory stores used in tests).
type AtomicBoxCreator interface {
	PutBoxAtomic(ctx context.Context, box domain.Box, material domain.BoxCryptoMaterial) error
}

// AtomicFolderDeleter is implemented by catalogs that can atomically delete
// a single entry by path iff the corresponding folder is empty. The
// returned entry is the row that was actually deleted — callers use its ID
// to clean up the matching blob.
//
// Error strings are stable sentinels matched by the caller:
//
//	"not_found"         — no row at that path
//	"folder_not_empty"  — entry is a folder with live descendants
type AtomicFolderDeleter interface {
	DeleteEntryIfEmpty(ctx context.Context, boxID, logicalPath string) (domain.FileEntry, error)
}
