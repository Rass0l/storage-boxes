# ADR-002: Metadata Visibility Without Unlock

## Status
Accepted for v1

## Context
The vault layer stores encrypted file content, but the platform still needs to list a tree, enforce uniqueness, surface content types, and process shares. The open question is which metadata remains queryable while a box is locked.

## Decision
Stage 1 keeps a limited set of operational metadata in cleartext at the database layer:
- file and folder identifiers
- logical paths
- file and folder names
- parent-child relationships
- content type
- size in bytes
- creation and update timestamps
- storage object keys and crypto-version metadata

Sensitive content remains encrypted:
- file bytes
- per-file data keys
- wrapped box master keys
- future indexed content or preview material

## Rationale
This choice keeps tree queries, uniqueness constraints, content-type handling, and share staging simple enough for early implementation. It also matches the Stage 1 goal of a strong platform skeleton instead of speculative privacy engineering.

## Alternatives considered
1. **Encrypt all file metadata**  
   Stronger privacy, but tree queries, conflict detection, and share workflows would all require unlock-time decryption and more invasive cache/session state.
2. **Encrypt only names and paths**  
   Better privacy posture than the chosen approach, but still complicates tree queries and repository contracts.

## Consequences
- database operators can infer directory structure and filenames
- the trust boundary must be explicit in product and enterprise documentation
- a future hardening stage may migrate selected metadata to an encrypted manifest if the threat model demands it
