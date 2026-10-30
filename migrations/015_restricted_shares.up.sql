-- 015_restricted_shares.up.sql
-- Extend the share model to support recipient-scoped, verified delivery
-- alongside the existing temporary-link mode. All existing shares default
-- to access_mode='public' so current behavior is unchanged.
--
-- Three new tables model the verification lifecycle:
--   share_recipients  — allowed recipients per share, one passcode hash each
--   share_challenges  — append-only audit of every verification attempt
--   share_claims      — short-lived, per-recipient, cookie-backed sessions
--
-- share_challenges is append-only (mirrors share_access_events / audit_events)
-- so verification history cannot be rewritten. share_claims is mutable only
-- for revocation (revoked_at stamp); expiry is read from expires_at.

ALTER TABLE shares
  ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'public'
    CHECK (access_mode IN ('public','restricted')),
  ADD COLUMN IF NOT EXISTS recipient_domain_allowlist TEXT[] NULL,
  ADD COLUMN IF NOT EXISTS require_otp BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_shares_access_mode
  ON shares(access_mode)
  WHERE access_mode = 'restricted';

CREATE TABLE IF NOT EXISTS share_recipients (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  passcode_hash BYTEA NOT NULL,
  passcode_salt BYTEA NOT NULL,
  passcode_rotated_at TIMESTAMPTZ NULL,
  verified_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  last_attempt_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (share_id, email_normalized)
);

CREATE INDEX IF NOT EXISTS idx_share_recipients_share
  ON share_recipients(share_id);

CREATE TABLE IF NOT EXISTS share_challenges (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  recipient_id TEXT NULL REFERENCES share_recipients(id) ON DELETE SET NULL,
  kind TEXT NOT NULL CHECK (kind IN ('passcode','otp')),
  succeeded BOOLEAN NOT NULL,
  reason TEXT NULL,
  remote_ip INET NULL,
  user_agent TEXT NULL,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  risk_score SMALLINT NOT NULL DEFAULT 0,
  country_code TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_share_challenges_share
  ON share_challenges(share_id, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_share_challenges_recipient
  ON share_challenges(recipient_id, attempted_at DESC);

CREATE TRIGGER share_challenges_no_update
  BEFORE UPDATE OR DELETE ON share_challenges
  FOR EACH ROW EXECUTE FUNCTION prevent_append_only_mutation();

CREATE TABLE IF NOT EXISTS share_claims (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES share_recipients(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL,
  otp_pending BOOLEAN NOT NULL DEFAULT FALSE,
  otp_hash BYTEA NULL,
  otp_expires_at TIMESTAMPTZ NULL,
  remote_ip INET NULL,
  user_agent TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_share_claims_share
  ON share_claims(share_id);
CREATE INDEX IF NOT EXISTS idx_share_claims_recipient
  ON share_claims(recipient_id);
CREATE INDEX IF NOT EXISTS idx_share_claims_expiry
  ON share_claims(expires_at)
  WHERE revoked_at IS NULL;
