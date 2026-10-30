-- 011_file_entry_kind.down.sql
DROP INDEX IF EXISTS ix_file_entries_box_path;
ALTER TABLE file_entries DROP COLUMN IF EXISTS updated_at;
ALTER TABLE file_entries DROP COLUMN IF EXISTS kind;
