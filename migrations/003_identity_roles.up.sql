CREATE TABLE roles (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_bindings (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_name)
);
