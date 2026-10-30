# Unlock-session durability

This document pins down what "unlocking a box" persists — and what it
deliberately does not — so the behaviour around restarts, sweepers, and
cache misses is never surprising.

## What lives where

A box unlock has **three** pieces of state:

| Piece                              | Where it lives              | Survives API restart? | Survives Postgres restart? |
| ---------------------------------- | --------------------------- | --------------------- | -------------------------- |
| `box_unlock_sessions` row          | Postgres                    | ✅                    | ✅                         |
| Unwrapped box master key (BMK)     | In-process `UnlockCache`    | ❌                    | ❌                         |
| `sessions` row (auth cookie)       | Postgres                    | ✅                    | ✅                         |

The row proves the unlock was authorized by the right user and records a
sliding deadline (default 30 min). The BMK is the actual secret needed to
read or write any encrypted blob — it is never written to disk and never
leaves the process that unlocked the box.

## Contract

```
POST /api/v1/boxes/:id/sessions    → derives KEK from password, unwraps BMK,
                                     caches BMK in memory keyed by unlock id,
                                     persists an unlock row
DELETE /api/v1/boxes/:id/sessions/:sess
                                  → deletes the row + drops the BMK from cache;
                                     only the user who opened it may close it
```

File operations (`PUT /files`, `GET /files/:id/content`, `DELETE /files`,
`POST /folders`, `POST /files/move`) require **both** the auth cookie
**and** the `X-Unlock-Session` header. The middleware resolves the header
through `Service.ResolveUnlock`, which:

1. Looks up the `box_unlock_sessions` row.
2. Rejects if the row is missing or past its absolute `expires_at`.
3. Looks up the BMK in `UnlockCache`. A cache miss **deletes** the row and
   returns `unlock_expired` — the only way this happens is an API restart,
   an explicit cache sweep, or a stale unlock ID that outlived the cache
   entry. The client must re-unlock.

## Why it's deliberately not persisted

Persisting the BMK (even encrypted) would mean either:

- **Encrypting with the box password** → every file op would require the
  password client-side, which defeats the point of an unlock session.
- **Encrypting with the server master key** → any operator who can read
  Postgres and the server master key can read every box. The memory-only
  cache is the escape hatch: the KEK stays in the unlocking process, so
  compromising Postgres alone cannot decrypt blobs without also compromising
  a live API process that has recently served an unlock.

Losing the cache on restart is the trade-off. Users re-unlock; there is no
data loss. The durability test
(`test/e2e/compose_durability_test.go`) asserts this contract:

- After `docker compose restart api`, the auth session survives.
- The old unlock session ID is now refused (`unlock_expired`), the client
  re-unlocks with the box password, and the file content round-trips
  byte-for-byte.

## Lifecycle & sweepers

- On unlock: row written, BMK cached with `expires_at = now + 30m`.
- On `ResolveUnlock`: sliding refresh **is not** performed (unlock sessions
  are intentionally short-lived; if you're still working you re-unlock).
- On lock (`DELETE .../sessions/:sess`): row removed, BMK dropped.
- On restart: all BMKs discarded.
- Periodic sweep (`cmd/api/sweepers.go`) calls
  `PGUnlockSessionStore.Sweep` against the absolute deadline and
  `UnlockCache.Sweep` against the in-memory map. Both run from the API
  process today; will move to the worker when the worker takes ownership
  of shared-state sweepers.

## What the API returns in each failure mode

| Condition                                   | Code               | HTTP |
| ------------------------------------------- | ------------------ | ---- |
| Missing `X-Unlock-Session` header            | `unlock_required`   | 403  |
| Header value doesn't match a known row       | `unlock_invalid`    | 401  |
| Row exists, unlock owner ≠ caller            | `unlock_mismatch`   | 403  |
| Row exists but box ID in path mismatches     | `unlock_wrong_box`  | 403  |
| Row exists but past its deadline             | `unlock_expired`    | 401  |
| Row exists but BMK cache miss (e.g. restart) | `unlock_expired`    | 401  |

Callers should treat `unlock_expired` as a signal to re-prompt for the box
password, not for the auth password.
