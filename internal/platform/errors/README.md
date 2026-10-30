# Platform Error Model

Domain modules return structured `DomainError` values instead of raw transport errors.

Stage 1 taxonomy:
- `auth`
- `authz`
- `vault`
- `share`
- `crypto`
- `quota`
- `rate_limit`
- `validation`
- `conflict`
- `not_found`
- `internal`

Rules:
1. application services return domain errors
2. API handlers map domain errors to HTTP status codes
3. internal causes may be wrapped for logging, but raw causes must not be exposed to clients
4. rate limiting has its own category so login and unlock throttling can stabilize without ad hoc string matching
