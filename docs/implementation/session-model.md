# Session Model

The product uses server-side sessions, not JWT-based self-contained auth tokens, for v1.

Identity sessions:
- authenticate the user to the platform
- are stored server-side
- use opaque session identifiers in client cookies or headers

Vault unlock sessions:
- are separate from identity sessions
- are volatile capabilities tied to a box unlock operation
- can expire independently of the identity session
- should never be modeled as long-lived bearer JWTs

This split keeps vault key lifecycle decisions inside server memory and storage boundaries instead of pushing them into self-contained tokens.
