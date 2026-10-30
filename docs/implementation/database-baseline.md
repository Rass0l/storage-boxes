# Database Baseline

The Stage 1 schema establishes:
- identity tables
- vault tables
- shares tables
- audit and outbox tables
- future-reserved tables for memberships, versions, policies, and SSO

The database boot path should fail fast on invalid DSNs and unreachable endpoints. Stage 1 validates TCP reachability; Stage 2 should switch to a vendored PostgreSQL driver for real query execution.
