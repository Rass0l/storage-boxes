# Server Master Key

The server master key is a platform bootstrap secret used by runtimes that initialize crypto-sensitive services.

Stage 1 rules:
- read from environment at process startup
- validate format and minimum length before boot continues
- fail closed if absent or malformed
- never log the raw value
- keep migration runtime exempt only if it does not initialize crypto-sensitive services

Future stages should move this from simple environment bootstrap to a more formal secret-management workflow without changing the runtime contract.
