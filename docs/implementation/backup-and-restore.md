# Backup and Restore

> **Superseded.** This file is retained so existing links don't break.
> The authoritative runbook is
> [`backup-restore.md`](./backup-restore.md).

The platform stores encrypted objects on disk and metadata in
PostgreSQL. Neither half is sufficient alone — every backup must
coordinate both, and every restore must run them in the order the
scripts enforce.

Read `backup-restore.md` for:

- what is captured by `scripts/backup.sh` (Postgres dump, stage tar,
  vault tar, manifest);
- the restore ordering enforced by `scripts/restore.sh`
  (schema → stage → vault → verify);
- the post-restore worker boot requirement
  (`ShareReconciliationJob` runs once before API/gateway come up);
- RPO / RTO / consistency guarantees, maintenance-mode expectations,
  and the SQL operators may run to invalidate all outstanding
  claims after a restore for extra caution.
