# ADR-007: Audit outbox dispatch

## Status

Accepted.

## Context

Downstream projections (SIEM, Slack alerts, data warehouse) must
receive every audit event, even when the projection target is down.
A synchronous call to any external system from the Record path would
tie audit availability to those systems and make Record the critical
path for every mutating business operation.

## Decision

`audit.Service.Record` writes to `audit_events` and enqueues a row in
`domain_outbox` (topic, payload, attempts, available_at,
dispatched_at) inside the same logical operation. A worker-owned
dispatcher (`OutboxDispatchJob`) claims pending rows via
`FOR UPDATE SKIP LOCKED`, calls an injected `Deliver` function, and
either marks the row dispatched or bumps `available_at` with a
backoff.

This keeps audit writes fast and makes outbound delivery a separate,
retryable concern. The claim pattern is safe under multiple worker
replicas.

## Consequences

- Any new audit sink plugs into the outbox; no service-code changes.
- Bursts of events don't slow down the business path; the dispatcher
  drains on its own schedule.
- Poisonous payloads accumulate `attempts` and can be inspected (or
  dead-lettered via an operator query). No automatic dead-letter yet;
  that's reserved for a later ADR when a real sink is plugged in.
