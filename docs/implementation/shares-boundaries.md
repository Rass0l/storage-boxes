# Shares Module Boundaries

The shares module owns:
- share records
- share staging objects
- public token resolution
- download limits and expiry
- share access event emission
- restricted-share recipients, verification challenges, and claims
- owner-approved recipient access requests (request lifecycle +
  decisions). Approval mutates recipient policy through the existing
  recipient path; it never grants delivery on its own — verification and
  the claim/session lifecycle still gate every download.

Stage 1 stores only `token_hash` in persistence-facing structures. Raw tokens are public capabilities and must not be stored at rest once share creation becomes real.
