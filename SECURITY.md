# Security

Storage Boxes 0.5.0 is an initial repository baseline. It has no published
release support window or security certification. Known correctness and
recovery work is tracked in [project status](docs/project-status.md).

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/Rass0l/storage-boxes/security/advisories/new)
to report suspected vulnerabilities. Private reporting is enabled for this
repository. Do not post exploit details, credentials, or affected user data
in public issues. No dedicated project security email address is published.

Reports should include the affected version/commit, configuration, impact,
and a minimal reproduction using synthetic data. Remove tokens, passwords,
master keys, live share links, cookies, and private file content. Responses
are best effort; no response or fix deadline is promised.

## Deployment boundary

- The server decrypts file content. This is not end-to-end encryption.
- Names, paths, account information, and audit metadata are server-visible.
- Protect PostgreSQL, vault blobs, staged share content, backups, and the
  server master key. Losing the key can make encrypted content unrecoverable.
- Local mode includes OTP echo; Windows setup uses a computer-specific local CA.
  Its private key must remain private and must never be copied to another machine.
  Shared deployment needs
  production configuration, trusted certificates, and SMTP for OTP.
- A clean secret scan does not prove the absence of all secrets or defects.
  Review exported source and scan Git history before publishing existing history.

This guidance does not change the permissions or conditions in [LICENSE](LICENSE).
