CREATE TABLE file_entries (
  id TEXT PRIMARY KEY,
  box_id TEXT NOT NULL REFERENCES boxes(id) ON DELETE CASCADE,
  parent_id TEXT NULL REFERENCES file_entries(id) ON DELETE CASCADE,
  logical_path TEXT NOT NULL,
  name TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  size_bytes BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (box_id, logical_path)
);

CREATE TABLE file_objects (
  id TEXT PRIMARY KEY,
  file_entry_id TEXT NOT NULL UNIQUE REFERENCES file_entries(id) ON DELETE CASCADE,
  storage_key TEXT NOT NULL UNIQUE,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE file_crypto_material (
  file_entry_id TEXT PRIMARY KEY REFERENCES file_entries(id) ON DELETE CASCADE,
  wrapped_file_data_key BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  crypto_version INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_file_entries_box_id ON file_entries(box_id);
