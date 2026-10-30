# Stage 2 Preparation

Identity work can begin once the Stage 1 baseline is stable.

Carry-forward requirements:
- server-side sessions only
- no JWT-centric auth design in v1
- add login and session persistence before broad UI state work
- add `rate_limit` errors and middleware consistently across auth and unlock flows
