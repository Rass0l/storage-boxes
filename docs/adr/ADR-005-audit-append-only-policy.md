# ADR-005: Audit Append-Only Policy

## Status
Accepted

## Context
Audit events and share access logs are evidence-bearing records. The platform needs operational telemetry too, but compliance-relevant audit history must not be editable through normal application paths.

## Decision
Audit evidence is append-only at the storage boundary:
- application code inserts audit records but does not update or delete them
- PostgreSQL triggers reject `UPDATE` and `DELETE` against `audit_events`
- the same protection applies to `share_access_events`
- enrichment or risk-scoring writes must create adjacent records rather than mutate the original event

## Consequences
### Positive
- stronger evidence posture
- clearer separation between raw facts and interpreted enrichment
- simpler export model for future SIEM connectors

### Negative
- correction workflows require compensating records instead of in-place edits
- retention and deletion policies need explicit legal and product review before implementation
