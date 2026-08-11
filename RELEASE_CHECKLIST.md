# Release checklist / Чек-лист релиза

- [ ] Update `SCRIPT_VERSION` in both executable helpers and package versions in both detailed guides.
- [ ] Update `CHANGELOG.md`.
- [ ] Run `bash tests/smoke.sh` as an ordinary user with `sudo` available, or as root in an isolated CI runner.
- [ ] Run ShellCheck with warning severity or stricter.
- [ ] Parse `secure-linux-admin.ps1` with Windows PowerShell 5.1 and PowerShell 7.
- [ ] Perform a real test only on a disposable Ubuntu/Debian VPS with a snapshot and recovery console.
- [ ] Verify a second key login before finalizing SSH.
- [ ] Verify rollback preview using `--rollback DIR --dry-run`.
- [ ] Regenerate `SHA256SUMS.txt` after every source change.
- [ ] Build the source/release archive with a single top-level directory.
- [ ] Verify the archive with `unzip -t` and verify its external SHA-256 file.
- [ ] Create a signed or annotated Git tag such as `v2026.08.10-2`.
- [ ] Upload the release ZIP and `.sha256` file to GitHub Releases.
