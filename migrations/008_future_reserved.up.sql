CREATE TABLE box_memberships (
  id TEXT PRIMARY KEY,
  box_id TEXT NOT NULL REFERENCES boxes(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE file_versions (
  id TEXT PRIMARY KEY,
  file_entry_id TEXT NOT NULL REFERENCES file_entries(id) ON DELETE CASCADE,
  version_no INT NOT NULL,
  file_object_id TEXT NULL REFERENCES file_objects(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (file_entry_id, version_no)
);

CREATE TABLE policy_rules (
  id TEXT PRIMARY KEY,
  policy_type TEXT NOT NULL,
  body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE retention_policies (
  id TEXT PRIMARY KEY,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sso_providers (
  id TEXT PRIMARY KEY,
  provider_type TEXT NOT NULL,
  issuer TEXT NOT NULL,
  config JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
