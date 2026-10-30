# Platform Database Baseline

Stage 1 keeps the runtime buildable on a fresh server without requiring vendored Go database drivers.

Current behavior:
- parse and validate PostgreSQL DSNs
- establish a real TCP connection to the configured PostgreSQL host and port during startup
- expose a `Connection` boundary with `PingContext()` so runtimes can fail readiness when PostgreSQL is unreachable
- keep the migration runtime separate and drive migrations through `psql`

Why this is a Stage 1 deployment baseline:
- API, worker, and share-gateway need reliable startup and readiness checks more than full query execution
- the migrate runtime is responsible for applying SQL files and therefore shells out to the PostgreSQL client
- Stage 2 can still swap this boundary to `pgx/v5` without changing runtime entrypoints
