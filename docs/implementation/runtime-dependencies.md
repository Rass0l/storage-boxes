# Runtime Dependencies

Stage 1 runtime dependencies are intentionally modest:
- Go stdlib
- React + Vite toolchain on the frontend
- PostgreSQL in Compose
- Nginx-style static frontend container

The next dependency wave should be deliberate and documented. Avoid pulling in frameworks that bypass the current module seams.
