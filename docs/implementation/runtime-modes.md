# Runtime Modes

Stage 1 establishes four runtime modes:

- `api`: authenticated product API
- `worker`: async orchestration and scheduled background work
- `migrate`: schema management
- `share-gateway`: public share delivery surface

The share gateway exists as a separate runtime because it has a different threat model. It should remain a narrow surface without administrative or vault-mutation endpoints.
