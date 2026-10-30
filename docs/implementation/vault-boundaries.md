# Vault Module Boundaries

The vault module is the central product core. It owns:
- boxes and box lifecycle
- unlock sessions
- file catalog metadata
- file and folder operations
- crypto orchestration for BMKs and FDKs
- box deletion lifecycle state

The crypto primitives package stays inside `internal/vault/crypto/` so it is cohesive with vault semantics while still remaining testable in isolation.
