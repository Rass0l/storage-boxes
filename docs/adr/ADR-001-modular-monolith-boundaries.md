# ADR-001: Modular Monolith Boundaries

## Status
Accepted

## Context
The platform coordinates identity, vault lifecycle, file catalog state, share generation, and append-only audit recording. Those concerns are tightly coupled at the data and workflow level. Splitting them into networked services in Stage 1 would introduce distributed transactions, duplicate authorization checks, and key-lifecycle coordination problems before the product has stable behavior.

## Decision
Stage 1 keeps a modular monolith with six first-class modules:
- `platform`
- `identity`
- `vault`
- `shares`
- `audit`
- `jobs`

Each module owns its domain types, application interfaces, infrastructure adapters, and API layer. Cross-module workflows must cross a service boundary inside the monolith or use domain events. Modules must not reach directly into another module's tables or repositories.

## Consequences
### Positive
- fewer moving pieces during initial implementation
- one schema migration stream
- cleaner refactor path once real traffic and scale pressures are known
- strong seams for future extraction of a share gateway or async workers

### Negative
- runtime blast radius is larger than with hard service isolation
- module boundaries must be enforced by code review and package design, not by the network
