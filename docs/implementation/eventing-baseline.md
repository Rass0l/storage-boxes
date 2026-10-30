# Eventing Baseline

The domain outbox table is present in Stage 1 even though handlers are still placeholders.

This is deliberate:
- lifecycle actions such as share expiry and box deletion will need idempotent async follow-up
- SIEM export and notifications should consume domain events instead of coupling directly to core application services
