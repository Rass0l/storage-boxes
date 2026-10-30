# Compose Development Workflow

Compose is the default local topology:
- `postgres`
- `api`
- `worker`
- `frontend`
- `share-gateway`

The API and worker share box-storage and share-stage mounts only where required. The share gateway should mount share-stage data only, preserving a narrower trust boundary.
