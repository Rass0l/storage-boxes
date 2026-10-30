# Stage 1 File Manifest

This manifest gives the Stage 1 file-count requirement a visible shape.

| Area | Target | Actual |
|---|---:|---:|
| `cmd/` | 16 | 16 |
| `internal/` | 90 | 174 |
| `migrations/` | 20 | 20 |
| `api/` | 12 | 20 |
| `web/` | 35 | 52 |
| `deployments/` | 6 | 7 |
| `scripts/` | 8 | 11 |
| `test/` | 20 | 20 |
| `docs/` | 10 | 34 |

**Total tracked files:** 368

Notes:
- counts intentionally reflect real module and runtime structure
- Stage 1 remediation replaced obvious padding with future-purpose stubs and fuller decision records
- first-party files remain well above the Stage 1 anti-padding floor
