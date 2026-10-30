# ADR-006: Share staging model

## Status

Accepted.

## Context

Public share links must be revocable without touching the original
vault file. They also must survive restart, expire on a deadline, and
respect a download cap. If the gateway read bytes directly off the
vault file it would need the box master key at serve time, coupling
share delivery to the unlock lifecycle and exposing the vault blob
path to unauthenticated traffic.

## Decision

Every share stages a separate encrypted copy under `SHARE_STAGE_ROOT`.
Staging happens inside `ShareStageEngine.Stage`:

1. Read the vault blob under the caller's in-memory BMK.
2. Generate a fresh 32-byte `shareKey` via `crypto/rand`.
3. Seal the plaintext with `shareKey` (AES-256-GCM) and write it under
   a new storage key derived from randomness.
4. Wrap `shareKey` under `SERVER_MASTER_KEY` and persist
   `wrap_nonce || wrapped_key || content_type || original_name` in
   `share_objects.wrapped_share_key` (length-prefixed segments so the
   gateway can populate response headers without another schema
   migration).

Revocation and expiry delete the `share_objects` row and the stage
file. Vault data is never touched; the vault file's BMK never enters
the share-gateway process.

## Consequences

- Storage cost is ~2× the shared bytes until purge (acceptable for
  typical share sizes).
- A staged share survives an API restart without the BMK cached.
- Purge is terminal: once the stage file is gone, the ciphertext is
  unrecoverable even with `SERVER_MASTER_KEY`.
- Deprecating this approach would require a new ADR.
