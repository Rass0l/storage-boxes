# API Contract Notes

Stage 1 keeps route handlers shallow, but contracts should already reflect the future domain surface:
- typed DTO placeholders for identity, vault, shares, and audit
- `/api/v1/...` for authenticated endpoints
- `/s/{token}` for public share delivery
- stable domain error codes
- readiness and health endpoints per runtime

OpenAPI artifacts are intentionally incomplete in behavior, but should remain specific enough to guide frontend integration work.
