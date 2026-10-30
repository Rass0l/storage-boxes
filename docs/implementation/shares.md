# Shares subsystem

Shares stage an encrypted copy of a vault file, tie a one-shot public
token to that copy, and serve it from an isolated `share-gateway` process.
The vault file is not touched by public download — revocation, expiry,
and max-download caps operate purely on the staged object.

## Lifecycle

```
active ──► (revoked | expired)
  │                │
  │                ▼
  │            purge_requested_at = now()
  │                │
  ▼                ▼
  └───────────► purged  (share_objects row + stage blob deleted)
```

## Components

- `internal/shares/domain/*` — `Share`, `ShareObject`, `AccessEvent`,
  token hashing (`HashShareToken`).
- `internal/shares/app/service.go` — `ShareService` (authenticated
  CRUD + access log) and `PublicDelivery` (open-by-token, download
  counter, access recorder).
- `internal/shares/infra/pg_repo.go` — Postgres-backed repositories
  for `shares`, `share_objects`, `share_access_events`.
- `internal/shares/infra/stage_engine.go` — file-backed stager that
  reads the vault blob under the caller's unlock BMK, re-encrypts
  under a fresh 32-byte share key, wraps that key under
  `SERVER_MASTER_KEY`, and writes the result to `SHARE_STAGE_ROOT`.
- `internal/shares/api/routes.go` —
  `POST /api/v1/shares`, `GET /api/v1/shares` (list),
  `GET /api/v1/shares/{id}`, `PATCH /api/v1/shares/{id}` (settings),
  `DELETE /api/v1/shares/{id}` (revoke), `GET /api/v1/shares/{id}/access`,
  and `RegisterPublicRoutes` for `GET/HEAD /s/{token}`.
- `cmd/share-gateway/main.go` — wires the public routes only; no
  identity, no vault service, no CSRF.

## Crypto model

Staging derives a fresh 32-byte share key per share. The gateway never
holds any other share's key, and revocation is terminal: once the
staged blob is gone, the ciphertext on disk cannot be recovered even
with the master key. The `wrapped_share_key` column stores
`wrap_nonce || wrapped_share_key || content_type || original_name`
packed as length-prefixed segments so the gateway can serve a
recognizable Content-Type and Content-Disposition without a schema
migration.

## Worker jobs

- `ShareExpiryJob` — transitions active shares past `expires_at` to
  `expired` and stamps `purge_requested_at`.
- `SharePurgeJob` — for any share with `purge_requested_at` set,
  deletes the stage blob, the `share_objects` row, and transitions
  the share to `purged`. Idempotent: rerunnable safely.

Both run on `WORKER_SHARE_INTERVAL` (default 1 minute). Download-count
exhaustion also triggers the same purge path inline from
`PublicDelivery.CountDownload`.

## Probe vs download

`GET /s/{token}` is the consuming path: it increments
`download_count`, writes a success row to `share_access_events`, and
streams the plaintext body. `HEAD /s/{token}` is side-effect-free:
same headers, no body, no counter bump, no success row. Denied
probes (expired, revoked, exhausted, wrong token) still write an
access row with `succeeded=false` so probe-style scrapers show up
in the audit view.

## Non-deliverability window

`purge_requested_at` is the authoritative "stop serving" flag. Every
tear-down path — `Revoke`, `ShareExpiryJob`, download-count
exhaustion, `Service.PurgeByBox` called from a box soft-delete —
stamps it first, before flipping status or touching stage bytes.
`Share.IsDeliverable` rejects any share with a non-nil
`PurgeRequestedAt`. Consequences:

- The public GET/HEAD paths on `/s/{token}` return 404 the instant a
  box DELETE returns, not on the next worker tick.
- The in-line stage-blob delete and the share status flip (revoked
  / expired / purged) can therefore fail without creating a
  delivery window: the stamp alone is sufficient to block access.

`TestSharesNonDeliverableImmediatelyAfterBoxDelete` pins this down:
DELETE returns 204 → immediate GET + HEAD against the raw token both
404 → a denied access row is appended to `share_access_events`, all
before any worker tick runs.

## Deletion workflow (two-phase, truthful under failure)

Box deletion is staged so that cross-subsystem cleanup actually gets
to finish before the row goes away. The earlier design — hard DELETE
on the box row immediately, rely on FK CASCADE, rely on the worker
to "retry" — was false on its face: once the cascade fired, there
were no share rows left for the worker to act on.

**Phase 1 (API).** `DELETE /api/v1/boxes/{id}` calls `VaultService.DeleteBox`:

1. Flip `boxes.status='deleting'`, stamp `deleted_at` +
   `purge_requested_at` (`BoxRepository.SoftDelete`).
2. Sweep the in-process `UnlockCache` for that box so a client
   holding an unlock-session can't keep reading plaintext between
   now and finalize (`UnlockCache.SweepBox`).
3. Fire the box-deletion hook. The shares subsystem's
   `Service.PurgeByBox` stamps `purge_requested_at` on every share
   of the box and best-effort-deletes stage blobs. A failure here
   does NOT abort the box delete — the share rows survive with
   `purge_requested_at` set, so the worker actually can retry.
   Partial failures are audited as `vault.box_deletion_partial` /
   `shares.purge_partial`.
4. Emit `vault.box_delete_requested`. API returns 204.

From here the box is hidden from listings (both pg and memory repos
filter `status='deleting'` out of `ListByOwner`; operators who need
to see in-flight deletions query `ListPurgeCandidates`), rejects
unlock/upload, and waits for the worker.

**Phase 2 (worker).** `BoxPurgeJob` runs on `WORKER_SHARE_INTERVAL`
(same tick as share purge so a freshly-purged share promptly unblocks
its parent box):

1. `ListPurgeCandidateBoxes` returns boxes in `status='deleting'`.
2. For each, pick up its shares, drive each through
   `SharePurgeJob.runOne` toward `status='purged'`. A stage-delete
   failure leaves `purge_requested_at` set and the share in its
   pre-purge state — next tick retries.
3. When every share of the box is `purged`, call `FinalizeBox`.
   The finalize ordering is **blobs first, metadata last**:
   - `Engine.DeleteBox` wipes the on-disk blob directory.
   - If that errors, FinalizeBox returns early with
     `vault.box_finalize_partial` audited; the box row stays in
     `status='deleting'` so the next tick retries.
   - Only after the wipe succeeds does the service issue the FK-
     cascading metadata DELETE and emit `vault.box_deleted`.

   The earlier order (metadata first, best-effort blob wipe) left
   plaintext blobs orphaned on disk with no metadata pointing at
   them, so no future tick could retry. `TestFinalizeBoxRetainsMetadataWhenBlobWipeFails`
   locks this down.

Share revocation is a smaller version of the same pattern:
`Revoke` stamps `purge_requested_at` *before* flipping the status
to `revoked`, so even when the status update fails the worker
still converges. The failure is surfaced to the API caller
(`persist_revoke_status`) instead of being swallowed.

Nothing here relies on FK CASCADE for eventual consistency — the
cascade is the *last* step, not the first.

## Restricted shares (migration 015)

A share carries an `access_mode` column (`public` | `restricted`).
`public` is the original temporary-link behavior — anyone with the raw
token can download until TTL or the download cap hits. `restricted`
gates delivery behind recipient verification.

Three new tables back the restricted flow:

| Table               | Shape                                                                     | Mutability |
|---------------------|---------------------------------------------------------------------------|------------|
| `share_recipients`  | One row per allowed recipient email. Stores `(salt, hash)` for the per-recipient passcode, verified/revoked timestamps, and a rolling `failed_attempts` counter. | rotate / revoke |
| `share_challenges`  | Append-only log of every verification attempt (passcode or OTP) with `succeeded`, `reason`, IP, UA, risk score. | **append-only** (trigger) |
| `share_claims`      | Short-lived recipient session. SHA-256 of the HttpOnly cookie the gateway sets. Also carries pending-OTP state. | revoke / complete-OTP only |

Lifecycle:

1. **Create.** API accepts `access_mode=restricted` with a list of
   recipient emails (optionally filtered by a domain allowlist), plus
   an optional `require_otp` flag. Per-recipient random passcodes are
   generated server-side and returned exactly once in the create
   response; only salt+hash persist. Duplicate recipient emails — both
   within one request and against rows that already exist on the share —
   are rejected with a `duplicate_recipient` / `recipient_exists` error
   rather than surfacing the database unique-constraint as a 500. When
   `require_otp` is set, the deployment must have an out-of-band OTP
   delivery channel (see **OTP delivery** below); creation is rejected
   with `otp_delivery_not_configured` otherwise, so there is never a
   live share whose second factor can't be delivered.
2. **Verify.** The gateway serves `GET /s/{token}/verify` (HTML form)
   and `POST /s/{token}/verify` (JSON or form). A correct passcode
   issues a `share_claim` row and sets the `sb_share_claim` cookie
   (`HttpOnly; SameSite=Strict; Path=/s/<token>`; `Secure` is added in
   production HTTPS deployments — see **Cookie behavior** below). When
   `require_otp` is set, the claim starts `OTPPending=true` and the
   recipient must complete `POST /s/{token}/otp` before the claim
   becomes active. Every attempt appends to `share_challenges`, carries
   enrichment fields, and emits audit.
3. **Download.** `GET /s/{token}` reads the claim cookie and calls
   `Service.OpenWithClaim`. An `ErrClaimRequired` sentinel triggers a
   303 redirect to the verify page (or a JSON 401 for non-HTML clients).
   `OpenWithClaim` checks, in order: the share is deliverable, the
   download cap is not hit, the claim resolves to this share and is
   active (not revoked / expired / OTP-pending), **and** the recipient
   row behind the claim is still active. The last check is defense in
   depth: revocation cascades a claim revoke inline, but re-reading the
   recipient here makes revocation effective immediately even if that
   cascade was interrupted — a revoked recipient can never redeem a
   stale-but-unrevoked claim.
4. **Revocation.** Recipient revocation (`DELETE
   /api/v1/shares/{id}/recipients/{rid}`) stamps `revoked_at` on the
   recipient row and revokes any outstanding claims. Passcode rotation
   (`POST /api/v1/shares/{id}/recipients/{rid}/rotate`) invalidates
   existing claims similarly. A single claim can also be revoked
   directly via `DELETE /api/v1/shares/{id}/claims/{cid}`; that endpoint
   verifies both that the caller owns `{id}` and that the claim belongs
   to it, so a claim cannot be revoked through an unrelated share the
   caller happens to own.
5. **Cleanup.** `ClaimExpiryJob` (worker) runs on
   `WORKER_SHARE_INTERVAL` and revokes claims past `expires_at`.
   `ShareReconciliationJob` runs on `WORKER_RECONCILE_INTERVAL` and at
   worker boot — it revokes (a) claims that point at a
   no-longer-deliverable share and (b) still-active claims whose
   recipient row has been revoked (the cascade-miss safety net), then
   emits a `shares.reconciled` audit record with counts.

### OTP delivery

`require_otp` adds a second factor that, by definition, must travel a
different channel from the passcode the recipient just submitted. The
service therefore never returns the code in the verify response in a
production-like environment:

- **Production / staging** (`APP_ENV` production-like): an
  `app.OTPDispatcher` delivers the code out-of-band. The repo ships an
  email implementation, `infra.SMTPOTPDispatcher`, wired by both the api
  and share-gateway when `SHARE_OTP_SMTP_ADDR` + `SHARE_OTP_SMTP_FROM`
  are set (optionally `SHARE_OTP_SMTP_USERNAME` / `_PASSWORD` for PLAIN
  auth). `VerifyPasscode` calls it; the code is delivered out-of-band and
  is absent from the response. The send is time-bounded (a dead or slow
  SMTP server can't stall the verify request — the dispatcher dials with
  a context deadline and sets a connection deadline, mirroring the
  database path's timeouts). A dispatch failure surfaces a generic error
  and the recipient retries — the code is never echoed as a fallback and
  never logged — and is recorded as a `shares.challenge_failed` audit
  event on the recipient (`reason=otp_dispatch_failed`) so the owner can
  see delivery, not the recipient, failed. It is deliberately NOT written
  to `share_challenges`, so a mail outage can't burn a recipient's
  per-IP rate-limit budget.
- **Local development / tests** (`APP_ENV` empty / `dev` / `test`): with
  no dispatcher, `DevModeOTPEcho` is set so the code is surfaced in the
  verify response and the dev HTML page, making the flow exercisable
  without external infra.
- With neither a dispatcher nor dev echo (a production-like env that has
  not configured SMTP), `require_otp` shares cannot be created
  (`otp_delivery_not_configured`) — there is no half-working state where
  codes leak into responses or logs. The api enforces this guard so it
  agrees with the gateway on whether OTP delivery is operable.

The OTP itself is stored only as a salted hash on the pending claim and
is never logged. The `shares.challenge_issued` audit record carries a
`channel` field (`dispatcher` | `dev_echo`) — no code material.

### Cookie behavior

The `sb_share_claim` cookie is always `HttpOnly`, `SameSite=Strict`, and
scoped `Path=/s/<token>` so one recipient's claim can't ride on another
share. The `Secure` attribute is environment-dependent: the
share-gateway sets it from `config.RequireTLS` (true for production-like
`APP_ENV`), so the cookie is marked `Secure` on HTTPS deployments and
left un-`Secure` for local HTTP development — otherwise browsers would
silently drop it over `http://localhost` and verification could never
complete.

Temporary-link behavior is unchanged for `access_mode=public` — both
the existing `TestSharesEndToEnd` integration and
`TestPublicShareStillWorks` unit locks that down.

### Recipient attribution on delivery rows

Migration 016 adds `share_access_events.recipient_id` (nullable,
FK → `share_recipients(id) ON DELETE SET NULL`). For restricted
shares the gateway resolves the `sb_share_claim` cookie back to its
`recipient_id` on every code path that writes an access row:

- success (GET body streamed cleanly) → row carries `recipient_id`;
- denial on open (share_not_available, share_exhausted) → row carries
  the recipient from the cookie when present, else `NULL`;
- stream-interrupted (client disconnect, short write) → row carries
  `recipient_id` because it came from `PublicPayload.RecipientID`
  which the service populated from the claim at open time.

The recipient activity timeline (`GET
/api/v1/shares/{id}/recipients/{rid}/activity`) merges
`share_challenges` and recipient-scoped `share_access_events` into a
single chronological stream. That endpoint is what the UI
`RecipientActivity` panel renders, and it is the contract that the
`TestRestrictedShareEndToEnd` and
`TestRestrictedDeliveryAttributesRecipientOnAccessRow` tests lock
down.

The audit pipeline receives the same attribution:
`shares.accessed` / `shares.access_denied` carry `recipient_id` in
metadata for restricted deliveries, so the audit page's filter by
subject / recipient returns the full restricted lifecycle, not just
the verification attempts.

### What "no-open" paths do and do not record

Not every restricted-share HTTP request reaches `OpenWithClaim`. The
contract for the paths that don't open the share at all is:

| HTTP request                                          | Share opens? | `share_access_events` row? | Audit event? |
|-------------------------------------------------------|:------------:|:--------------------------:|:------------:|
| `GET /s/{token}` (restricted) with no cookie          |       ✗      | ✓ (`recipient_id` empty; `reason=claim_required`)                                                                                                          | ✓ `shares.access_denied` |
| `GET /s/{token}` (restricted) with stale cookie (expired / revoked / otp-pending / tampered) | ✗ | ✓ (recipient-attributed when resolvable; `reason=claim_expired` / `claim_revoked` / `otp_required` / `claim_missing`) | ✓ `shares.access_denied` |
| `HEAD /s/{token}` (restricted), any cookie state      |       ✗      |              ✗             |       ✗      |
| `POST /s/{token}/verify` (any outcome)                |       ✗      |    via `share_challenges`  |  ✓ `shares.challenge_*` |
| `POST /s/{token}/otp` (any outcome)                   |       ✗      |    via `share_challenges`  |  ✓ `shares.challenge_*` |
| `POST /s/{token}/revoke-claim`                        |       ✗      |              ✗             |       ✗      |

Every turned-away GET on a restricted share lands in the access log
so the operator's `/access` view and per-recipient timeline see the
full pattern of attempts — including the first "I don't have a
cookie yet" navigation. The reason code distinguishes the
no-cookie case (`claim_required`) from stale-cookie classification
(`claim_revoked`, `claim_expired`, `otp_required`, `claim_missing`);
only the stale-cookie cases attribute to a specific recipient.

HEAD probes stay silent per RFC 9110 § 9.3.2 — an operator
investigating a denial will see the associated GET row.
`/revoke-claim` is a user-initiated cookie clear; it has no
semantic effect on the share and doesn't land in the access log.

### What the recipient activity timeline shows

`GET /api/v1/shares/{id}/recipients/{rid}/activity` merges three
durable sources into one newest-first stream, so the whole
recipient lifecycle is visible in a single table:

| `kind`       | Source                                                      | Typical operator reading                                   |
|--------------|-------------------------------------------------------------|------------------------------------------------------------|
| `challenge`  | `share_challenges`                                          | `verify / passcode` or `verify / otp` — verified or denied |
| `access`     | `share_access_events` with `recipient_id = {rid}`           | `download` — delivered or denied (reason on denial)        |
| `lifecycle`  | `audit_events` with `subject_type=share_recipient, subject_id={rid}` or `subject_type=share_claim, subject_id IN (claims this recipient holds)` | Events like `shares.recipient_added`, `_revoked`, `passcode_rotated`, `claim_issued`, `_revoked`, `_expired`, rendered as "recipient: revoked", "claim: expired", etc. |

The lifecycle rows carry `actor_id` (creator who did the revoke/
rotate) and no IP/UA enrichment — the event is a state transition,
not an incoming request. `succeeded=true` on a lifecycle row means
the event is a positive transition (`recipient_added`,
`recipient_reactivated`, `access_request_approved`,
`claim_issued`); everything else reads as "something was taken
away" and the UI tints those red alongside denials.

## Owner-approved recipient access requests (migration 017)

A visitor who reaches a restricted share but is NOT an allowed recipient
can ask the owner for access instead of being silently turned away. The
flow rides entirely on the existing restricted-share machinery — it is
**not** a parallel sharing model.

> An access request is **not** verification, **not** a claim, and **not**
> authorization by itself. Approval adds (or reactivates) the requester as
> a normal recipient under the share's existing policy and mints a
> passcode; the requester must then complete the **normal** passcode →
> claim → (optional OTP) → delivery flow. A restricted share never behaves
> like a bearer link, before or after a request.

One new table backs the flow:

| Table                    | Shape                                                                                  | Mutability |
|--------------------------|----------------------------------------------------------------------------------------|------------|
| `share_access_requests`  | One row per request: requester email/domain, optional message, status, decision metadata (`decided_by`, `decided_at`, `decision_reason`), `recipient_id` (set on approval), `expires_at`, and request-context enrichment (IP/UA/referer/risk/country). | status transition via `Decide` (mirrors `share_recipients`) |

The decision history lives in the append-only `audit_events` ledger; the
row holds current state. A PARTIAL UNIQUE INDEX on `(share_id,
requester_email_normalized) WHERE status='pending'` allows at most one
open request per email while keeping terminal history rows and permitting
a legitimate re-request after a terminal decision — it is also the race
backstop for concurrent submits.

Lifecycle:

1. **Submit.** `POST /s/{token}/request-access` (public, share-gateway)
   takes `{email, message?}`. It creates a PENDING row and returns only a
   coarse status — never file metadata, ids, owner data, or secrets.
   Public links reject it (`share_not_restricted`); a non-deliverable
   share returns `share_not_available` (audited as
   `shares.access_request_blocked`, `phase=submit`). A request from a
   domain outside the share's allowlist is rejected up front
   (`domain_not_allowed`) rather than parked as un-approvable. An email
   that's already an active recipient short-circuits to
   `recipient_active` ("just verify"). Submissions are rate-limited per
   `(share, IP)`; duplicate submissions while a request is pending return
   the existing status and emit `shares.access_request_duplicate` without
   creating a second row. The verify page links here ("Not on the list?
   Request access").
2. **Inspect.** `GET /api/v1/shares/{id}/access-requests[?status=]`
   (creator-only) returns full request detail so the owner can audit
   pending, approved, denied, expired, and superseded requests in one
   place. Each row also carries `recipient_state` (the CURRENT state of
   the linked recipient: `active` | `revoked` | `missing`) so an approval
   whose recipient was later revoked reads as `status=approved` +
   `recipient_state=revoked` — the historical decision is preserved while
   current access truth is visible, i.e. "approved" is never shown as
   permanent access. This — not the audit API — is the owner's window
   into request history (submit/expiry/supersede audit events carry an
   empty `actor_id`, so a non-admin owner's actor-scoped audit query
   won't show them; admins still see everything).
3. **Approve.** `POST /api/v1/shares/{id}/access-requests/{arid}/approve`
   first refuses a **stale** request: one past its TTL is converged to
   `expired` (`via=approve`) and rejected, so an old request the sweep
   hasn't reached yet can never be approved as if fresh — independent of
   worker timing. It then re-validates fulfillability at decision time
   (restricted, deliverable, domain allowed, file present, staged object
   present); on any block it leaves the request pending, emits
   `shares.access_request_blocked` (`phase=approve`, with a `reason`, and
   the owner `actor_id`), and returns a clear 4xx. Otherwise
   it executes the decision as **one reliable operation**: the repo's
   `ApproveAtomic` runs the recipient write (insert a new recipient /
   reactivate a revoked one with a fresh passcode / nothing for an
   already-active recipient) AND the status-guarded claim
   (`pending → approved`, recipient linked) in a **single transaction**
   (the same pattern as `PutBoxAtomic`). Either the request is approved
   AND the recipient exists+active+linked, or nothing persists — there is
   no "approved with no recipient" half-state. A lost race (a concurrent
   deny / worker expiry / worker supersede / second approve won first)
   returns `access_request_not_pending` having written nothing; any other
   failure rolls back, leaving the request pending and the approval
   retryable. Audit (`shares.recipient_added` / `_reactivated` +
   `shares.access_request_approved`) is emitted only after the commit. The
   minted passcode is returned exactly once for the owner to transmit
   out-of-band. **No claim is issued** — the requester verifies normally.
4. **Deny.** `POST /api/v1/shares/{id}/access-requests/{arid}/deny`
   (optional `{reason}`) flips the request to `denied`
   (`shares.access_request_denied`). The requester is never made a
   recipient, so a subsequent verify for that email fails as an unknown
   recipient and delivery stays blocked.
5. **Cleanup.** `AccessRequestCleanupJob` (worker, `WORKER_SHARE_INTERVAL`
   + boot) converges stale rows: pending past-TTL → `expired`
   (`expired_ttl`); pending on a non-deliverable share → `expired`
   (`share_unavailable`); pending already mapping to an active recipient →
   `superseded` (`recipient_active`); and **approved requests whose
   recipient state is missing** (recipient_id NULL — the spec's "approved
   request whose recipient state is missing or inconsistent") → `superseded`
   (`recipient_missing`). Atomic approval prevents the last case from a
   partial write, so it only catches restore / migration /
   out-of-band-deletion leftovers. Each transition is audited and the job
   emits a `shares.access_requests_reconciled` summary
   (`expired`/`superseded`/`orphaned_approvals` counts). The status-guarded
   transitions make it idempotent and resolve any owner-approve /
   worker-supersede race to a single terminal transition.

Public request endpoints and the status leak surface:
`GET /s/{token}/request-status?email=` returns only
`none|pending|approved|denied` for the named email. It is deliberately
minimal — a caller already holds the share token (a capability), and the
endpoint never returns decision metadata, the deciding owner, recipient
ids, the passcode, or file metadata. Crucially, `approved` reflects
CURRENT access, not the historical request status: it is returned only
while the email is an **active recipient**. Once the recipient is revoked
(or is missing after a restore of an approved row whose recipient is
gone) the status reverts to `none`, so the requester is never told they
still have access they've lost. Internal lifecycle states (`expired`,
`superseded`) collapse to `none`.

### Access requests and the no-open paths

A pending or approved-but-not-yet-verified requester who navigates to
`GET /s/{token}` is treated exactly like any other un-verified visitor:
the gateway redirects to `/verify` and records a `shares.access_denied`
row with `reason=claim_required`. Approval changes who *can* verify, not
whether verification is required — the "denied delivery before approval"
and "verification/delivery after approval" transitions are all visible in
the existing access log + recipient timeline, attributed to the recipient
the approval created.
