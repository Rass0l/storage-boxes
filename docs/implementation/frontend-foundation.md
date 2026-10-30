# Frontend Foundation

The frontend is a routed React shell with enough structure to receive real auth, vault, share, and audit work without major reshaping.

Stage 1 expectations:
- explicit app routes
- protected-route wrapper
- session state abstraction
- API client helpers for GET/POST/PUT/DELETE
- a minimal interception point for 401 and 429 handling
