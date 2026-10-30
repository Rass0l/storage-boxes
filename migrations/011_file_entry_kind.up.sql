-- 011_file_entry_kind.up.sql
-- Adds explicit `kind` column to distinguish folders from files in the
-- catalogue. The in-memory implementation already uses ContentType of
-- "inode/directory" as the folder marker; this migration documents the
-- future Postgres projection of the same model.

ALTER TABLE file_entries
  ADD COLUMN kind TEXT NOT NULL DEFAULT 'file'
  CHECK (kind IN ('file', 'folder'));

ALTER TABLE file_entries
  ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS ix_file_entries_box_path
  ON file_entries (box_id, logical_path);
