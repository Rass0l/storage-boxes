# Audit subsystem

Audit records are append-only rows in `audit_events`, plus — for
public share accesses — `share_access_events`, plus — for elevated-risk
events — `risk_signals`. Triggers in migration 007 block UPDATE/DELETE
on the two append-only tables; tampering would require the superuser
role and would be visible in `pg_audit` (if configured).

## Producers

Audit is emitted by:

- `internal/identity/app/identity_service.go` → `identity.login_succeeded`,
  `identity.login_failed`, `identity.logout` via the `AuditSink` hook
  installed by `identityapi.AttachAudit`.
- `internal/vault/app/service_impl.go` → `vault.box_created`,
  `vault.box_delete_requested` (soft-delete), `vault.box_deleted`
  (worker finalize, emitted exactly once), `vault.box_unlocked`,
  `vault.box_unlock_failed` via the hook installed by
  `vaultapi.AttachAudit`.
- `internal/vault/app/file_ops.go` → `vault.file_uploaded`,
  `vault.file_read`, `vault.file_deleted`. `file_read` fires only
  after the blob actually opened; a read that errored before
  streaming never produces an audit row.
- `internal/shares/app/service.go` → `shares.created`,
  `shares.accessed`, `shares.access_denied`, `shares.revoked`,
  `shares.expired`, `shares.purged`.
- `internal/jobs/app/share_jobs.go` → `shares.expired` /
  `shares.purged` when a worker job drives the transition.

## Emission timing

Terminal audit events fire AFTER the stored model has actually
converged — never before. Each tear-down path stamps
`purge_requested_at` first (so `IsDeliverable` rejects immediately),
flips status second, and only then emits the terminal record:

- `shares.revoked` — after `MarkPurgeRequested` + `UpdateStatus(revoked)`.
- `shares.expired` — after `MarkPurgeRequested` + `UpdateStatus(expired)`.
- `shares.purged` — after `Stage.Delete` + `UpdateStatus(purged)`.
- `vault.box_deleted` — after engine wipe + metadata `FinalizeDelete`.
  Emitted exactly once, from `vault.FinalizeBox`; `BoxPurgeJob` does
  NOT re-emit.

Failures surface as distinct non-terminal records
(`shares.purge_partial`, `vault.box_finalize_partial`,
`vault.box_deletion_partial`) so operators can see stuck work without
an emission claiming convergence that never happened.

## Enrichment

`internal/audit/enrichment/request_context.go` extracts
`remote_ip` / `user_agent` / `referer` / `request_id` from a request,
honoring `TRUSTED_PROXIES` for `X-Forwarded-For`. The
`HeuristicRiskScorer` in `risk.go` produces a 0–100 score and a
severity bucket from those attributes plus per-share signals
(`new_ip_for_subject`, `near_download_cap`). Scores ≥ 40 also emit a
`risk_signal` row joined to the share.

`CountryLookup` in `country.go` populates
`share_access_events.country_code` for every public access. The
default implementation classifies reserved ranges (loopback → `LO`,
RFC1918/link-local/private → `PR`, public → empty) so the column is
populated honestly without shipping a GeoIP database. Production
deployments wire a real provider (MaxMind, ip2location,
Cloudflare's `CF-IPCountry` header) by supplying their own
`CountryLookup` in the gateway's `sharesapi.Deps`.

## Public-download accounting

`CountDownload` and the `shares.accessed` success record are only
written AFTER `io.Copy` finishes cleanly AND the stream delivered the
expected byte count. A mid-stream failure (client disconnect, stage
read error, short write) produces a `succeeded=false` access row
with a concrete `reason` (`stream_interrupted`, `short_write`,
etc.) and does NOT bump the counter — so a share that disconnects
halfway through doesn't look like a completed delivery in the
access log or in the max-download accounting.

## Outbox dispatch

Every `audit.Service.Record` call also enqueues a `domain_outbox` row
within the same tx. `internal/jobs/app/share_jobs.go:OutboxDispatchJob`
claims pending rows with `FOR UPDATE SKIP LOCKED`, calls the injected
`Deliver` function (no-op by default), and marks the row
dispatched. Failed deliveries are backed off via
`MarkFailed(id, backoff)`. The outbox is the seam where a SIEM /
Kafka / Slack projector plugs in.

## Query surface

`GET /api/v1/audit/events` accepts `subject_type`, `subject_id`,
`event_type`, `actor_id`, `since` (RFC3339), and `limit`. Non-admin
callers are implicitly scoped to `actor_id = <their-user-id>`.
`GET /api/v1/shares/{id}/access` returns per-share access rows.

### Restricted-share events

Migration 015 adds a recipient-scoped lifecycle with its own audit
events, all in the `shares.` namespace so existing filters still
match:

| Event                         | Subject type      | When emitted                                    |
|-------------------------------|-------------------|-------------------------------------------------|
| `shares.recipient_added`      | `share_recipient` | A recipient is provisioned (create or add).     |
| `shares.recipient_revoked`    | `share_recipient` | Creator revokes a recipient.                    |
| `shares.passcode_rotated`     | `share_recipient` | Passcode rotated (existing claims invalidated). |
| `shares.challenge_issued`     | `share_recipient` | OTP challenge issued after passcode success.    |
| `shares.challenge_succeeded`  | `share_recipient`/`share_claim` | Passcode or OTP verified.          |
| `shares.challenge_failed`     | `share`           | Any failed verification attempt. `reason` covers `passcode_mismatch`, `recipient_revoked`, `recipient_unknown`, `domain_not_allowed`, `otp_mismatch`, `otp_expired`, `rate_limited`, `share_not_available`. |
| `shares.claim_issued`         | `share_claim`     | Claim becomes active (including post-OTP).      |
| `shares.claim_revoked`        | `share_claim`     | Claim revoked (user, creator, or reconciliation).|
| `shares.claim_expired`        | `share_claim`     | `ClaimExpiryJob` stamps a claim past TTL.       |
| `shares.reconciled`           | `share`           | `ShareReconciliationJob` finishes a sweep, with `claims_revoked` / `shares_scanned` in metadata. |

Migration 017 adds the owner-approved access-request lifecycle, also in
the `shares.` namespace. An access request is **not** verification, a
claim, or authorization — these events record the request lifecycle and
how a decision affected the recipient policy. The downstream verify /
delivery events above continue to cover what happens after approval,
attributed to the recipient the approval created or reactivated:

| Event                              | Subject type           | When emitted                                                                 |
|------------------------------------|------------------------|------------------------------------------------------------------------------|
| `shares.access_requested`          | `share_access_request` | A visitor submits a pending access request (actor empty — admin-visible).    |
| `shares.access_request_duplicate`  | `share_access_request` | A submission collapses to an existing pending row or an active recipient.    |
| `shares.access_request_blocked`    | `share`                | Submit or approve blocked. `phase` (`submit`\|`approve`) + `reason` (`share_unavailable`, `domain_not_allowed`, `file_not_found`, `object_missing`, `rate_limited`). Approve-phase blocks carry the owner `actor_id`. |
| `shares.access_request_approved`   | `share_access_request` | Owner approves; carries `recipient_id`, `recipient_mode` (`new`\|`reactivate`\|`link`), `reactivated`, plus the self-explaining fields below. |
| `shares.access_request_denied`     | `share_access_request` | Owner denies; delivery stays blocked.                                        |
| `shares.access_request_expired`    | `share_access_request` | A pending request past its TTL is expired — by `AccessRequestCleanupJob`, or immediately by an owner's approve attempt on a stale request (`via=approve`). |
| `shares.access_request_superseded` | `share_access_request` | Cleanup supersedes a pending request whose recipient is already active, or an approved request whose recipient went missing (`reason=recipient_missing`). |
| `shares.access_requests_reconciled`| `share`                | `AccessRequestCleanupJob` finishes a sweep, with `expired` / `superseded` / `orphaned_approvals` counts. |
| `shares.recipient_reactivated`     | `share_recipient`      | A revoked recipient is brought back to life by an access-request approval.   |

Decision and expiry events are written to **stand alone as the
explanation** — the single event answers who requested
(`requester_email` / `requester_domain`), from where
(`requester_remote_ip` / `requester_country`, when the submission
captured it), **how old** the request was when decided (`requested_at`),
who decided (`actor_id`), and — for approvals — **how the decision
changed recipient policy** (`recipient_mode` = a new recipient created /
a revoked one reactivated / an already-active one linked, plus
`recipient_id`). So an auditor never has to join back to the request row
to understand a decision.

The owner's window into request history is the
`GET /api/v1/shares/{id}/access-requests` endpoint, not the audit API:
submit/expiry/supersede/reconcile events carry an empty `actor_id` (a
TTL expiry surfaced by an owner's approve attempt is the exception — it
records the owner), so a non-admin owner's actor-scoped audit query won't
surface the system ones (admins see everything). Approve/deny carry the
owner's `actor_id` and are owner-visible.

All events carry `recipient_id`, `share_id`, `remote_ip`, `user_agent`,
`risk_score`, and `country_code` in metadata when applicable. Denied
verification attempts also land in `share_challenges` (append-only),
so the recipient activity view can interleave challenge rows with the
existing `share_access_events` timeline for a complete recipient-level
history.

### Durable recipient attribution on delivery rows (migration 016)

Restricted-share deliveries — success, denial, and stream-interrupted
— are recorded in `share_access_events` with the row's new
`recipient_id` column populated. The audit pipeline mirrors this:
`shares.accessed` and `shares.access_denied` metadata now carries a
`recipient_id` field for restricted shares, so an auditor filtering
the audit log by recipient sees both the verification attempts
(`shares.challenge_*`) and the actual delivery outcomes under the
same key.

Public-share rows leave `recipient_id` NULL. The append-only trigger
(migration 007) continues to forbid UPDATE / DELETE on
`share_access_events`, so recipient attribution is as immutable as
the rest of the access log.

Every turned-away GET on a restricted share lands in
`share_access_events` + emits a `shares.access_denied` audit event,
so the audit trail reflects the full denial lifecycle:

| Cookie state                                          | `reason`          | `recipient_id` |
|-------------------------------------------------------|-------------------|----------------|
| absent                                                | `claim_required`  | empty          |
| present, claim row unknown (tampered or purged)       | `claim_missing`   | empty          |
| present, claim revoked                                | `claim_revoked`   | populated      |
| present, claim expired                                | `claim_expired`   | populated      |
| present, claim OTP-pending                            | `otp_required`    | populated      |

HEAD requests stay silent per RFC 9110 § 9.3.2.
