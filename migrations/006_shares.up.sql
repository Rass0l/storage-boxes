CREATE TABLE shares (
  id TEXT PRIMARY KEY,
  box_id TEXT NOT NULL REFERENCES boxes(id) ON DELETE CASCADE,
  file_entry_id TEXT NOT NULL REFERENCES file_entries(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  expires_at TIMESTAMPTZ NOT NULL,
  max_downloads INT NOT NULL DEFAULT 1,
  download_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE share_objects (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL UNIQUE REFERENCES shares(id) ON DELETE CASCADE,
  storage_key TEXT NOT NULL UNIQUE,
  wrapped_share_key BYTEA NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE share_access_events (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  remote_ip INET NULL,
  user_agent TEXT NULL,
  referer TEXT NULL,
  succeeded BOOLEAN NOT NULL,
  accessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_share_access_events_share_id ON share_access_events(share_id);
