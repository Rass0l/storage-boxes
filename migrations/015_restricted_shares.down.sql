DROP TRIGGER IF EXISTS share_challenges_no_update ON share_challenges;
DROP TABLE IF EXISTS share_claims;
DROP TABLE IF EXISTS share_challenges;
DROP TABLE IF EXISTS share_recipients;

ALTER TABLE shares
  DROP COLUMN IF EXISTS require_otp,
  DROP COLUMN IF EXISTS recipient_domain_allowlist,
  DROP COLUMN IF EXISTS access_mode;

DROP INDEX IF EXISTS idx_shares_access_mode;
