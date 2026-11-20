# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-20

### Added

- `--backend auto|resolved|file` to choose where the resolver configuration is
  written instead of relying on detection alone.
- Automatic fallback to the plain-file backend when `systemd-resolved` runs
  with `DNSStubListener=no` (no stub `resolv.conf`), instead of failing the
  whole apply.
- `--dry-run` (`-n`): prints the plan (backend, upstream, files, service
  actions) and changes nothing; does not require root.
- `--health`: exit code 0 (healthy), 1 (unhealthy), 2 (not managed), suitable
  for monitoring and configuration management.
- `--json` for `--status` and `--health`.
- `--uninstall` and `--purge` to remove the service, drop-ins and state and
  restore the resolver (the `dnsproxy` binary is kept unless `--purge`).
- `--force` to restart services even when the configuration is unchanged.
- `--verify-timeout` to tune the post-apply DNS check.
- `tests/run.sh`: POSIX test harness with fake `dig`, `ss` and `systemctl`,
  runnable without root, systemd or network.
- GitHub Actions workflow running `dash -n`, ShellCheck and the test suite on
  Ubuntu, Debian 12 and Alpine 3.20 (busybox).

### Changed

- Apply is now idempotent: files are rendered to a temporary file, compared
  with the target and only moved into place when they differ; services are
  only restarted when something actually changed.
- Generated files no longer contain a timestamp, which makes the output
  deterministic and comparable.
- The post-apply DNS check queries the local resolver directly (in proxy mode)
  before checking the system resolver, so a stale cache cannot hide a dead
  upstream.
- `--restore` and the rollback path verify name resolution and warn when the
  files were restored but DNS still fails.
- `resolv.conf` handling now reports bind-mounted, read-only and immutable
  files explicitly (typical container failure) instead of a bare shell error.
- The systemd unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`,
  capability bounding to `CAP_NET_BIND_SERVICE`, `Restart=always`,
  start rate limiting).
- `--status` shows the effective backend and the requested one.

### Fixed

- The systemd unit declared both `After=` and `Before=` for
  `nss-lookup.target`, an ordering cycle that systemd resolves by dropping
  start jobs.
- `SIGINT`/`SIGTERM`/`SIGHUP` during an apply now run the rollback via the
  `EXIT` trap instead of leaving a half-configured resolver behind.
- Dead PID-file handling in `svc_stop` (the file was never written) was
  removed; stop/disable is left to the service manager.

## [1.0.0]

- Initial single-file release: provider database, plain/DoT/DoH/DoQ/DNSCrypt
  transports, transactional apply with rollback, `--restore`, latency tests
  and provider ranking.
