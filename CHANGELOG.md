# Changelog

All notable changes to this project are documented here.

## [2026.08.10-2] - 2026-08-10

### Added

- GitHub-ready repository metadata, issue template, pull-request template, CI workflow, release checklist, and bilingual publishing guide.
- Automated smoke tests for both languages, Admin's PC dry-run, invalid input, recovery-manifest path validation, and checksums.
- Windows PowerShell parser validation in CI.

### Fixed

- Admin's PC `--dry-run` now makes no SSH key/profile or network changes.
- Public-key copying is idempotent and no longer appends duplicate key lines.
- Rollback rejects symlinked, non-root-owned, writable, or path-traversal recovery manifests.
- Fail2Ban restores its previous generated jail automatically if validation or restart fails.
- Audit and concurrent dry-run logs use unique names; audit logs stay under `/tmp`.
- Windows helper validates SSH targets and handles a key filename without an explicit parent directory.
- Server mode rejects unsafe administrator-home/`.ssh` symlinks and replaces managed files without following destination symlinks.

## [2026.08.10-1] - 2026-08-10

- Initial bilingual wizard, Windows helper, staged SSH hardening, firewall/Fail2Ban/update/journald/sysctl baseline, audit, logs, and rollback.
