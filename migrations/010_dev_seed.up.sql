-- 010_dev_seed.up.sql
-- Dev-only bootstrap data. The API process seeds the admin identity at
-- startup via SEED_ADMIN_* env vars; this migration documents the matching
-- Postgres shape for when persistence moves off the in-memory stores.

INSERT INTO roles(name, description)
  VALUES ('admin', 'bootstrap administrator')
  ON CONFLICT DO NOTHING;

INSERT INTO users(id, email, display_name, status, created_at)
  VALUES ('usr_seed_admin', 'admin@example.local', 'Administrator', 'active', now())
  ON CONFLICT (id) DO NOTHING;

-- The password hash is a placeholder; the running service computes the real
-- hash at startup from SEED_ADMIN_PASSWORD using argon2id (m=65536,t=3,p=2).
-- Rotate before promoting to any shared environment.
INSERT INTO user_credentials(user_id, password_hash, hash_algorithm, hash_version)
  VALUES (
    'usr_seed_admin',
    '$argon2id$v=19$m=65536,t=3,p=2$REPLACE_WITH_REAL_SALT$REPLACE_WITH_REAL_DIGEST',
    'argon2id',
    1
  )
  ON CONFLICT (user_id) DO NOTHING;

INSERT INTO role_bindings(user_id, role_name)
  VALUES ('usr_seed_admin', 'admin')
  ON CONFLICT DO NOTHING;

-- Shares subsystem seed: no pre-staged share (staging requires an
-- unlocked box, which only the running API can do). The admin user +
-- admin role above is the minimum identity floor needed for a fresh
-- install to immediately POST /api/v1/shares once a box is created.
-- The share-gateway and worker need SHARE_STAGE_ROOT to exist; compose
-- mounts `share_stage_data` into both. See DEPLOYMENT.md.
--
-- Restricted-share seed (migration 015): likewise not pre-populated.
-- A working restricted share requires:
--   1. an unlocked box (via /api/v1/boxes/{id}/sessions + BMK),
--   2. a staged encrypted object under SHARE_STAGE_ROOT,
--   3. per-recipient passcodes returned exactly once at create time.
-- None of those can be forged in a migration without exposing
-- passcodes in plain SQL or fabricating a stage blob. Operators who
-- want a demo restricted share should call:
--
--   POST /api/v1/shares
--     {
--       "box_id": "...", "file_entry_id": "...",
--       "access_mode": "restricted",
--       "recipient_emails": ["demo@example.com"],
--       "require_otp": false
--     }
--
-- See docs/implementation/shares.md (Restricted shares) for the full
-- create + verify + download flow.
