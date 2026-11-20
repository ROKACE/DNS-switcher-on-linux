# DNS-switcher-on-linux

A single-file POSIX shell script for switching, testing, and restoring the system DNS resolver on Linux desktops: [ROKACE/DNS-switcher-on-linux](https://github.com/ROKACE/DNS-switcher-on-linux).

## Quick start (copy and paste)

Linux only. Copy the line below, paste it into a terminal, enter your password —
the interactive menu opens:

```sh
curl -fsSL -o /tmp/dns-switcher.sh https://raw.githubusercontent.com/ROKACE/DNS-switcher-on-linux/main/dns-switcher.sh && sudo sh /tmp/dns-switcher.sh
```

No `curl`? Use `wget`:

```sh
wget -qO /tmp/dns-switcher.sh https://raw.githubusercontent.com/ROKACE/DNS-switcher-on-linux/main/dns-switcher.sh && sudo sh /tmp/dns-switcher.sh
```

Apply a profile without the menu (servers, scripts):

```sh
curl -fsSL -o /tmp/dns-switcher.sh https://raw.githubusercontent.com/ROKACE/DNS-switcher-on-linux/main/dns-switcher.sh && sudo sh /tmp/dns-switcher.sh -m doh -p quad9 -y --apply
```

Check what is currently configured (no changes, no root needed):

```sh
curl -fsSL -o /tmp/dns-switcher.sh https://raw.githubusercontent.com/ROKACE/DNS-switcher-on-linux/main/dns-switcher.sh && sh /tmp/dns-switcher.sh --status
```

Nothing is installed permanently: the script lives in `/tmp`, and `--restore` /
`--uninstall` undo everything it changed. If you want to read it before running
it as root: `less /tmp/dns-switcher.sh`.

> Do not pipe the script into a shell (`curl ... | sudo sh`): the interactive
> menu needs a terminal on stdin, and the pipe takes it away.

## How it works

- Detects the environment from package manager, `/etc/os-release`, init system, resolver backend, and IPv6 connectivity.
- Chooses where to write the resolver configuration:
  - `systemd-resolved` (when its stub listener is enabled)
  - `networkmanager` (management is disabled, `/etc/resolv.conf` is written directly)
  - direct `/etc/resolv.conf`
  - `--backend auto|resolved|file` overrides the choice; `auto` falls back to the file when `systemd-resolved` runs with `DNSStubListener=no`.
- Applies one transport:
  - `plain` - writes provider addresses directly
  - `dot` - native DoT through `systemd-resolved` where available
  - `doh`, `doq`, `dnscrypt` - served by a local AdGuard `dnsproxy` on `127.0.0.1:53`
  - `doh3` - HTTP/3 only, diagnostic, not shown in menus
- Configures IPv4 and IPv6 provider addresses together, but skips IPv6 automatically when the host has no global IPv6 address or default route.
- Applies changes transactionally: snapshots state first and rolls back on failure, including on `SIGINT`/`SIGTERM`.
- Is idempotent: files are compared before being replaced and services are only restarted when something changed, so repeated provisioning runs do not interrupt DNS.
- Restores the original resolver configuration with `--restore`.

## Characteristics and limits

- Target users are ordinary desktop users; server use is possible but limited (see "Running on a server").
- Run as root for changes; read-only commands such as `--status`, `--list`, `--test`, `--rank`, `--health` and `--dry-run` do not need root.
- Plain DNS works everywhere. Encrypted transports require systemd or OpenRC; unsupported init systems fail closed instead of partially configuring the system.
- Port `53` must be free. The script refuses to take another port because resolver configuration cannot express a custom port.
- Encrypted mode refuses to proceed if `dnsproxy` cannot be safely installed or started.
- `dnsproxy` defaults to pinned release `v0.86.0`; releases are SHA-256 verified unless `DNSPROXY_SHA256` or `--allow-unverified` overrides that.
- The generated systemd unit is hardened: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`/`PrivateDevices`, capability bounding to `CAP_NET_BIND_SERVICE`, `Restart=always` and start rate limiting.
- `--status --json` and `--health` provide machine readable state for monitoring and configuration management.
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
./dns-switcher.sh --status --json
./dns-switcher.sh -m doq -p adguard --apply
./dns-switcher.sh -m doh -p adguard:family --apply
./dns-switcher.sh -m dot -p cloudflare --apply
./dns-switcher.sh -m plain -p quad9 -y --apply
./dns-switcher.sh -m dot -p quad9 --backend file -y --apply
./dns-switcher.sh -m doh -p quad9 --dry-run
./dns-switcher.sh --test adguard
./dns-switcher.sh --rank doh
./dns-switcher.sh --health
./dns-switcher.sh --restore
./dns-switcher.sh --uninstall
./dns-switcher.sh --self-test
```

## Testing

`tests/run.sh` sources the script with `DNS_SWITCHER_NO_MAIN=1`, redirects every
path into a temporary directory and replaces `dig`, `ss` and `systemctl` with
small fakes, so the suite runs without root, systemd, network access or changes
to the host:

```sh
sh tests/run.sh
```

CI runs `dash -n`, ShellCheck and the suite on Ubuntu, Debian 12 and Alpine
3.20 (busybox).

## Environment

```text
DNSPROXY_VERSION      dnsproxy release tag to download (default: v0.86.0)
DNSPROXY_SHA256       expected SHA-256 of the dnsproxy archive
DNSPROXY_OVERRIDE     path to an existing dnsproxy binary
NO_COLOR              disable coloured output
```

## Running on a server

The script targets desktops, but the same mechanics work on any server that owns
its own resolver. What fits and what does not:

Works well:

- Plain DNS on any Linux with any init system (writes `/etc/resolv.conf` directly).
- Plain, DoT, DoH, DoQ and DNSCrypt on systemd hosts (through `systemd-resolved`
  or the plain file) and on Alpine/OpenRC through `dnsproxy`.
- Fully non-interactive provisioning: `./dns-switcher.sh -m dot -p quad9 -y --apply`,
  plus `--status`, `--health`, `--dry-run` and `--restore`.
- Idempotent runs: re-applying the same profile does not restart the resolver
  or the proxy, so a configuration management run causes no DNS blip.
- POSIX `sh` only, no bashisms, so it runs on minimal images.

Does not fit:

- Containers (Docker/Podman/Kubernetes): no service manager, `/etc/resolv.conf`
  is bind-mounted and owned by the runtime, and the host resolver cannot be
  changed from inside a netns. The script now reports this explicitly instead
  of failing with a bare shell error.
- Hosts where port `53` is already taken by a local resolver (`unbound`,
  `dnsmasq`, `BIND`, PowerDNS). The script refuses instead of chaining, because
  `/etc/resolv.conf` cannot express an upstream port.
- Hosts where `/etc/resolv.conf` is rewritten by something other than
  NetworkManager: `systemd-networkd` without `systemd-resolved`, netplan,
  cloud-init, `dhclient`/`dhcpcd` hooks, `resolvconf`/`openresolv`, cloud
  provider agents. Changes can be reverted on reboot or DHCP renew.
- Hosts with `systemd-resolved` active but `DNSStubListener=no`: `auto` now
  falls back to the plain-file backend, and `--backend file` forces that path;
  `--backend resolved` still fails closed with an explanation.
- SysV-only / runit / s6 hosts: plain DNS only; encrypted transports fail closed.
- Hardened fleets: no config file and no SELinux policy; the systemd unit is
  hardened, but `dnsproxy` still runs as root with a bounded capability set.

For servers, `--mode dot` through `systemd-resolved` is the least invasive
option (no extra binary, no extra listening port); keep a second SSH session
open and `--restore` at hand while changing DNS over SSH.

## Troubleshooting

- If port `53` is occupied, stop the service holding it or use `--mode plain`.
- If encrypted mode is unavailable, check whether systemd or OpenRC is the active init system.
- If IPv6 is not used, verify that the host has a global IPv6 address and default route.
- Use `--dry-run` to see what an apply would change without touching anything.
- Use `--health` to check the current state; exit code 1 means DNS is broken.
- Use `--restore` to return to the original resolver configuration.

## License

MIT - see [LICENSE](LICENSE).

Copyright (c) 2026 DNS-switcher-on-linux contributors.
