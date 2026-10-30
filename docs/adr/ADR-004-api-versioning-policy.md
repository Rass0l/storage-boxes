# ADR-004: API Versioning Policy

## Status
Accepted

## Context
The platform needs a stable contract for the frontend, future CLI tools, and later partner integrations. The API will evolve as vault operations, sharing, and audit capabilities become real.

## Decision
All authenticated external endpoints live under `/api/v1/...`. Public share delivery remains outside that prefix at `/s/{token}` because it has a different security profile and should remain separable from authenticated API traffic.

Versioning rules:
- additive fields are allowed within a version
- breaking request or response changes require a new versioned path family
- domain error codes must remain stable within a version even when wording changes

## Consequences
- Stage 1 route and OpenAPI skeletons must already reflect `/api/v1`
- a future dedicated share gateway can keep `/s/{token}` without disturbing authenticated clients
