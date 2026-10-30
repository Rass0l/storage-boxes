-- 017_share_access_requests.up.sql
-- Owner-approved recipient access requests for restricted shares.
--
-- A visitor who reaches a restricted share but is NOT an allowed recipient
-- can submit an access request (email + optional message) at the public
-- gateway. The share owner inspects pending requests and approves or denies
-- them. Approval is NOT authorization: it adds (or reactivates) the requester
-- as a normal recipient under the share's existing restricted policy and mints
-- a passcode the owner transmits out-of-band — exactly like every other
-- recipient. The requester must then complete the normal passcode -> claim ->
-- (optional OTP) -> delivery flow. Restricted shares never become bearer links.
--
-- share_access_requests is MUTABLE (status transitions + decision metadata),
-- mirroring share_recipients — NOT append-only. The full decision history
-- lives in the append-only audit_events ledger; this row holds current state.
-- A request is not verification, not a claim, and not authorization by itself.
--
-- recipient_id is set on approval to the recipient row that was created or
-- reactivated, so the request -> recipient -> challenges/accesses chain stays
-- queryable. ON DELETE SET NULL keeps the FK sound when a recipient row is
-- hard-deleted during a share purge (the same convention migration 016 uses
-- for share_access_events.recipient_id).

CREATE TABLE IF NOT EXISTS share_access_requests (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  requester_email TEXT NOT NULL,
  requester_email_normalized TEXT NOT NULL,
  requester_domain TEXT NOT NULL,
  message TEXT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','denied','expired','superseded')),
  recipient_id TEXT NULL REFERENCES share_recipients(id) ON DELETE SET NULL,
  decided_by TEXT NULL,
  decided_at TIMESTAMPTZ NULL,
  decision_reason TEXT NULL,
  expires_at TIMESTAMPTZ NULL,
  remote_ip INET NULL,
  user_agent TEXT NULL,
  referer TEXT NULL,
  risk_score SMALLINT NOT NULL DEFAULT 0,
  country_code TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- At most one OPEN (pending) request per (share, email). Terminal rows
-- (approved/denied/expired/superseded) are kept as history, so a partial
-- unique index over status='pending' dedupes without blocking a legitimate
-- re-request after a terminal decision. This is also the race backstop:
-- two simultaneous submits collapse to one pending row + a duplicate audit.
CREATE UNIQUE INDEX IF NOT EXISTS uq_share_access_requests_pending
  ON share_access_requests(share_id, requester_email_normalized)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_share_access_requests_share
  ON share_access_requests(share_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_share_access_requests_pending
  ON share_access_requests(status)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_share_access_requests_recipient
  ON share_access_requests(recipient_id)
  WHERE recipient_id IS NOT NULL;
