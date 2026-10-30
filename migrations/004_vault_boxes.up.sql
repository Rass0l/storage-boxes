CREATE TABLE boxes (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (owner_user_id, name)
);

CREATE TABLE box_crypto_material (
  box_id TEXT PRIMARY KEY REFERENCES boxes(id) ON DELETE CASCADE,
  crypto_version INT NOT NULL,
  kdf_algorithm TEXT NOT NULL,
  kdf_params JSONB NOT NULL,
  cipher_algorithm TEXT NOT NULL,
  cipher_params JSONB NOT NULL,
  key_wrapping_algorithm TEXT NOT NULL,
  wrapped_box_master_key BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE box_unlock_sessions (
  id TEXT PRIMARY KEY,
  box_id TEXT NOT NULL REFERENCES boxes(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE box_policy_bindings (
  box_id TEXT NOT NULL REFERENCES boxes(id) ON DELETE CASCADE,
  subject_id TEXT NOT NULL,
  role_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (box_id, subject_id, role_name)
);
CREATE INDEX idx_box_unlock_sessions_box_id ON box_unlock_sessions(box_id);
