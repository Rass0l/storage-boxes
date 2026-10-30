# Identity Module Boundaries

The identity module owns:
- users
- password credentials
- server-side sessions
- role bindings

It does not own:
- vault unlock sessions
- share tokens
- box-level authorization decisions beyond coarse role evaluation

Stage 2 should add:
- password hashing with Argon2id
- login throttling and lockout policy
- session persistence backed by PostgreSQL
- API DTO validation and consistent error responses
