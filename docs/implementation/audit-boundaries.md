# Audit Module Boundaries

The audit module owns append-only evidence and later enrichment:
- business audit records
- share access records
- risk signals
- export-oriented event surfaces

It is intentionally separate from operational logging. Observability tells operators what the process is doing. Audit tells the product what happened in domain terms.
