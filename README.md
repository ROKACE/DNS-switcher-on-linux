# DNS-switcher-on-linux

A single-file POSIX shell script for switching, testing, and restoring the system DNS resolver on Linux desktops.

## How it works

- Detects the environment from package manager, `/etc/os-release`, init system, resolver backend, and IPv6 connectivity.
- Uses one of three resolver backends:
  - `systemd-resolved`
  - NetworkManager
  - direct `/etc/resolv.conf`
- Applies one transport:
  - `plain` - writes provider addresses directly
  - `dot` - native DoT through `systemd-resolved` where available
  - `doh`, `doq`, `dnscrypt` - served by a local AdGuard `dnsproxy` on `127.0.0.1:53`
  - `doh3` - HTTP/3 only, diagnostic, not shown in menus
- Configures IPv4 and IPv6 provider addresses together, but skips IPv6 automatically when the host has no global IPv6 address or default route.
- Applies changes transactionally: snapshots state first and rolls back on failure.
- Restores the original resolver configuration with `--restore`.

## Characteristics and limits

- Target users are ordinary desktop users, not servers or portfolio setups.
- Run as root for changes; read-only commands such as `--status`, `--list`, `--test`, and `--rank` do not need root.
- Plain DNS works everywhere. Encrypted transports require systemd or OpenRC; unsupported init systems fail closed instead of partially configuring the system.
- Port `53` must be free. The script refuses to take another port because resolver configuration cannot express a custom port.
- Encrypted mode refuses to proceed if `dnsproxy` cannot be safely installed or started.
- `dnsproxy` defaults to pinned release `v0.86.0`; releases are SHA-256 verified unless `DNSPROXY_SHA256` or `--allow-unverified` overrides that.
- This is not a VPN and does not route all traffic.
- IPv6 is enabled only when the machine actually has usable IPv6 connectivity.

## Files touched

```text
/etc/dns-switcher/state
/etc/dns-switcher/backup/resolv.conf.orig
/etc/dns-switcher/backup/resolv.conf.pre-resolved
/etc/dns-switcher/snapshot/
/etc/systemd/resolved.conf.d/99-dns-switcher.conf
/etc/systemd/system/dns-switcher.service
/etc/init.d/dns-switcher
/etc/NetworkManager/conf.d/99-dns-switcher.conf
/usr/local/bin/dnsproxy
```

## Usage

```sh
./dns-switcher.sh
./dns-switcher.sh --list
./dns-switcher.sh --status
./dns-switcher.sh -m doq -p adguard --apply
./dns-switcher.sh -m doh -p adguard:family --apply
./dns-switcher.sh -m dot -p cloudflare --apply
./dns-switcher.sh -m plain -p quad9 -y --apply
./dns-switcher.sh --test adguard
./dns-switcher.sh --rank doh
./dns-switcher.sh --restore
./dns-switcher.sh --self-test
```

## Environment

```text
DNSPROXY_VERSION      dnsproxy release tag to download (default: v0.86.0)
DNSPROXY_SHA256       expected SHA-256 of the dnsproxy archive
DNSPROXY_OVERRIDE     path to an existing dnsproxy binary
NO_COLOR              disable coloured output
```

## Troubleshooting

- If port `53` is occupied, stop the service holding it or use `--mode plain`.
- If encrypted mode is unavailable, check whether systemd or OpenRC is the active init system.
- If IPv6 is not used, verify that the host has a global IPv6 address and default route.
- Use `--restore` to return to the original resolver configuration.

## License

MIT.
