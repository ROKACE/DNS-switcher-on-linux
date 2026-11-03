#!/bin/sh
# =============================================================================
#  dns-switcher.sh -- switch, test and restore the system DNS resolver
# =============================================================================
#
#  Distro detection is based on the *package manager* (apt/pacman/dnf/yum/
#  zypper/apk) plus /etc/os-release ID and ID_LIKE, never on a hardcoded list
#  of distribution names.  This makes the script work on derivative
#  distributions (Mint, Pop!_OS, Manjaro, EndeavourOS, Nobara, Bazzite, ...)
#  without knowing them in advance.
#
#  Supported DNS transports:
#      plain    - plain DNS (Do53, UDP/TCP port 53) written directly
#      dot      - DNS-over-TLS (native via systemd-resolved when available)
#      doh      - DNS-over-HTTPS (HTTP/2)
#      doh3     - DNS-over-HTTPS, HTTP/3 forced    [diagnostic only]
#      doq      - DNS-over-QUIC
#      dnscrypt - DNSCrypt v2                       [best effort]
#
#  Encrypted transports are served by a local AdGuard dnsproxy instance that
#  listens on 127.0.0.1:53; the system resolver is then pointed at it.
#  Plain DNS and DoT-via-resolved need no external binary.
#
#  IPv4 and IPv6 resolver addresses are always configured together whenever
#  the provider publishes them; IPv6 entries are skipped automatically on
#  hosts without IPv6 connectivity.
#
#  Run as root.  Usage: dns-switcher.sh [options]   (see --help)
#
#  License: MIT
# =============================================================================

APP="dns-switcher"
APP_VERSION="1.0.0"

# --- filesystem layout -------------------------------------------------------
STATE_DIR="/etc/$APP"
STATE_FILE="$STATE_DIR/state"
BACKUP_DIR="$STATE_DIR/backup"
RESOLV_CONF="/etc/resolv.conf"
RESOLV_BACKUP="$BACKUP_DIR/resolv.conf.orig"
RESOLVED_DROPIN_DIR="/etc/systemd/resolved.conf.d"
RESOLVED_DROPIN="$RESOLVED_DROPIN_DIR/99-$APP.conf"
SYSTEMD_UNIT="/etc/systemd/system/$APP.service"
OPENRC_INIT="/etc/init.d/$APP"
NM_CONF="/etc/NetworkManager/conf.d/99-$APP.conf"
DNSPROXY_BIN="/usr/local/bin/dnsproxy"
DNSPROXY_REPO="AdguardTeam/dnsproxy"
DNSPROXY_VERSION="${DNSPROXY_VERSION:-v0.86.0}"

PROXY_LISTEN="127.0.0.1"
PROXY_PORT="53"
PROBE_PORT="15353"
PROBE_PORT2="15354"
TEST_DOMAIN="one.one.one.one"
DEFAULT_TEST_COUNT="10"
PING_TARGET_V4="1.1.1.1"
PING_TARGET_V6="2606:4700:4700::1111"

# --- runtime state filled in by the detection helpers ------------------------
FAMILY="unknown"
PKG_MGR="unknown"
INIT_SYS="unknown"
RESOLVER="unknown"
HAS_IPV6="no"
IPV6_REASON="not detected"
OS_ID=""
OS_LIKE=""
OS_PRETTY="unknown"

# --- user selections / CLI flags ---------------------------------------------
MODE=""
P_KEY=""
PROV_KEY=""
PROV_PROFILE="base"
ASSUME_YES="no"
ALLOW_UNVERIFIED="no"
DO_STATUS=0
DO_RESTORE=0
DO_TEST=0
DO_RANK=""
DO_LIST=0
DO_SELFTEST=0
TEST_KEY=""
SNAPSHOT_ACTIVE="no"

# provider fields (set by provider_load)
P_NAME=""; P_PROFILE=""; P_V4=""; P_V6=""; P_DOT=""; P_DOH=""; P_DOQ=""; P_SDNS=""

# =============================================================================
#  Output helpers
# =============================================================================
# Deterministic parsing: C locale for the decimal point, sort order and the
# messages printed by the external tools we parse (dig, ping, ...).
LC_ALL=C
export LC_ALL

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET="$(printf '\033[0m')"
    C_BOLD="$(printf '\033[1m')"
    C_RED="$(printf '\033[31m')"
    C_GREEN="$(printf '\033[32m')"
    C_YELLOW="$(printf '\033[33m')"
    C_BLUE="$(printf '\033[34m')"
    C_CYAN="$(printf '\033[36m')"
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

msg()  { printf '%b%s%b\n' "$C_BLUE" "$1" "$C_RESET"; }
ok()   { printf '%b%s%b\n' "$C_GREEN" "$1" "$C_RESET"; }
warn() { printf '%b%s%b\n' "$C_YELLOW" "WARNING: $1" "$C_RESET" >&2; }
err()  { printf '%b%s%b\n' "$C_RED" "ERROR: $1" "$C_RESET" >&2; }
die()  { err "$1"; exit 1; }

confirm() {
    if [ "$ASSUME_YES" = "yes" ]; then return 0; fi
    printf '%b%s [y/N]: %b' "$C_BOLD" "$1" "$C_RESET"
    _ans=""
    read -r _ans || _ans=""
    case "$_ans" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u 2>/dev/null)" = "0" ]; }

require_root() {
    is_root && return 0
    if have sudo && [ -t 0 ] && [ "${_REEXEC:-}" != "1" ]; then
        msg "Root privileges are required, re-executing with sudo ..."
        _self=$(command -v "$0" 2>/dev/null || printf '%s' "$0")
        # sudo -E is not supported everywhere, pass the relevant variables
        # through env instead of preserving the whole environment.
        _REEXEC=1 exec sudo env _REEXEC=1 \
            DNSPROXY_VERSION="${DNSPROXY_VERSION:-}" \
            DNSPROXY_SHA256="${DNSPROXY_SHA256:-}" \
            DNSPROXY_OVERRIDE="${DNSPROXY_OVERRIDE:-}" \
            NO_COLOR="${NO_COLOR:-}" \
            "$_self" "$@"
    fi
    die "This script must be run as root (try: sudo $0)"
}

# =============================================================================
#  Detection: distro family, package manager, init system, resolver, IPv6
# =============================================================================
detect_os_release() {
    if [ -r /etc/os-release ]; then
        OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"')
        OS_LIKE=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | head -n1 | tr -d '"')
        OS_PRETTY=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n1 | tr -d '"')
    fi
    [ -n "$OS_PRETTY" ] || OS_PRETTY="${OS_ID:-unknown}"
}

# The family is decided by the package manager that is actually present.
# /etc/os-release is only used as a cross-check / fallback.
detect_family() {
    detect_os_release
    if have pacman; then
        FAMILY="arch"; PKG_MGR="pacman"
    elif have apt-get; then
        FAMILY="debian"; PKG_MGR="apt-get"
    elif have dnf; then
        FAMILY="fedora"; PKG_MGR="dnf"
    elif have yum; then
        FAMILY="fedora"; PKG_MGR="yum"
    elif have zypper; then
        FAMILY="suse"; PKG_MGR="zypper"
    elif have apk; then
        FAMILY="alpine"; PKG_MGR="apk"
    else
        FAMILY="unknown"; PKG_MGR="unknown"
    fi
}

pkg_update() {
    case "$PKG_MGR" in
        apt-get) apt-get update -qq ;;
        pacman)  return 0 ;;
        dnf)     dnf -q makecache ;;
        yum)     yum -q makecache ;;
        zypper)  zypper -q --non-interactive refresh ;;
        apk)     apk update ;;
        *) return 1 ;;
    esac
}

pkg_install() {
    [ $# -gt 0 ] || return 0
    case "$PKG_MGR" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        pacman)
            pacman -S --noconfirm --needed "$@" || {
                err "pacman failed. Run 'pacman -Syu' first, then retry."
                return 1
            }
            ;;
        dnf)     dnf install -y "$@" ;;
        yum)     yum install -y "$@" ;;
        zypper)  zypper --non-interactive install "$@" ;;
        apk)     apk add "$@" ;;
        *) return 1 ;;
    esac
}

dig_package_name() {
    case "$FAMILY" in
        debian) printf 'dnsutils' ;;
        arch)   printf 'bind' ;;
        fedora) printf 'bind-utils' ;;
        suse)   printf 'bind-utils' ;;
        alpine) printf 'bind-tools' ;;
        *)      printf '' ;;
    esac
}

detect_init() {
    if have systemctl && [ -d /run/systemd/system ]; then
        INIT_SYS="systemd"
    elif have rc-service || have openrc; then
        INIT_SYS="openrc"
    elif [ -d /etc/init.d ]; then
        INIT_SYS="sysvinit"
    else
        INIT_SYS="none"
    fi
}

service_supported() {
    case "$INIT_SYS" in
        systemd|openrc) return 0 ;;
        *) return 1 ;;
    esac
}

resolved_available() {
    have resolvectl && return 0
    have systemd-resolve && return 0
    [ -f /lib/systemd/system/systemd-resolved.service ] && return 0
    [ -f /usr/lib/systemd/system/systemd-resolved.service ] && return 0
    [ -e /run/systemd/resolve ] && return 0
    return 1
}

detect_resolver() {
    RESOLVER="file"
    if have systemctl && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        RESOLVER="resolved"
    elif [ -L "$RESOLV_CONF" ]; then
        case "$(readlink "$RESOLV_CONF" 2>/dev/null)" in
            *systemd/resolve*) RESOLVER="resolved" ;;
        esac
    fi
    if [ "$RESOLVER" = "file" ] && have nmcli; then
        if systemctl is-active --quiet NetworkManager 2>/dev/null; then
            RESOLVER="networkmanager"
        fi
    fi
}

detect_ipv6() {
    HAS_IPV6="no"
    if have ip; then
        if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
            if ip -6 route show default 2>/dev/null | grep -q .; then
                HAS_IPV6="yes"
                IPV6_REASON="ok"
                return 0
            fi
            IPV6_REASON="global address but no default route"
        else
            IPV6_REASON="no global IPv6 address"
        fi
    else
        IPV6_REASON="ip command not available"
    fi
    if have ping && ping -6 -c1 -W2 "$PING_TARGET_V6" >/dev/null 2>&1; then
        HAS_IPV6="yes"
        IPV6_REASON="ok"
    fi
}

detect_all() {
    detect_family
    detect_init
    detect_resolver
    detect_ipv6
}

# =============================================================================
#  Provider database
# =============================================================================
#  One row per provider *profile*.  Every provider has a "base" profile and
#  optionally several filtered variants, so the menu asks for the provider
#  first and only then for the filtering mode.
#
#  Fields (separated by '|'):
#    1 provider key  (cloudflare, google, quad9, adguard, ...)
#    2 provider name shown in the menu
#    3 profile: base | family | ads | security | unfiltered | safe
#    4 IPv4 addresses (comma separated)
#    5 IPv6 addresses (comma separated) -- filled whenever the provider
#      publishes them in its standard configuration
#    6 DoT hostname
#    7 DoH host + path (without the https:// prefix)
#    8 DoQ hostname
#    9 DNSCrypt DNS stamp (sdns://)
#
#  Every endpoint below was validated against the public documentation or by a
#  live query; the built-in test (menu option 2) lets you re-check them.
# =============================================================================
PROVIDER_DB='
cloudflare|Cloudflare|base|1.1.1.1,1.0.0.1|2606:4700:4700::1111,2606:4700:4700::1001|one.one.one.one|cloudflare-dns.com/dns-query||
cloudflare|Cloudflare|security|1.1.1.2,1.0.0.2|2606:4700:4700::1112,2606:4700:4700::1002|security.cloudflare-dns.com|security.cloudflare-dns.com/dns-query||
cloudflare|Cloudflare|family|1.1.1.3,1.0.0.3|2606:4700:4700::1113,2606:4700:4700::1003|family.cloudflare-dns.com|family.cloudflare-dns.com/dns-query||
google|Google Public DNS|base|8.8.8.8,8.8.4.4|2001:4860:4860::8888,2001:4860:4860::8844|dns.google|dns.google/dns-query||
quad9|Quad9|base|9.9.9.9,149.112.112.112|2620:fe::fe,2620:fe::9|dns.quad9.net|dns.quad9.net/dns-query|dns.quad9.net|
quad9|Quad9|unfiltered|9.9.9.10,149.112.112.10|2620:fe::10,2620:fe::fe:10|dns10.quad9.net|dns10.quad9.net/dns-query||
adguard|AdGuard DNS|base|94.140.14.14,94.140.15.15|2a10:50c0::ad1:ff,2a10:50c0::ad2:ff|dns.adguard-dns.com|dns.adguard-dns.com/dns-query|dns.adguard-dns.com|sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
adguard|AdGuard DNS|family|94.140.14.15,94.140.15.16|2a10:50c0::bad1:ff,2a10:50c0::bad2:ff|family.adguard-dns.com|family.adguard-dns.com/dns-query|family.adguard-dns.com|
adguard|AdGuard DNS|unfiltered|94.140.14.140,94.140.14.141|2a10:50c0::1:ff,2a10:50c0::2:ff|unfiltered.adguard-dns.com|unfiltered.adguard-dns.com/dns-query|unfiltered.adguard-dns.com|
dnssb|DNS.SB|base|185.222.222.222,45.11.45.11|2a09::,2a11::|dot.sb|doh.sb/dns-query||
opendns|OpenDNS|base|208.67.222.222,208.67.220.220|2620:119:35::35,2620:119:53::53||doh.opendns.com/dns-query||
opendns|OpenDNS|family|208.67.222.123,208.67.220.123|2620:119:35::123,2620:119:53::123||doh.familyshield.opendns.com/dns-query||
yandex|Yandex DNS|base|77.88.8.8,77.88.8.1|2a02:6b8::feed:0ff,2a02:6b8:0:1::feed:0ff|common.dot.dns.yandex.net|common.dot.dns.yandex.net/dns-query||
yandex|Yandex DNS|safe|77.88.8.88,77.88.8.2|2a02:6b8::feed:bad,2a02:6b8:0:1::feed:bad|safe.dot.dns.yandex.net|safe.dot.dns.yandex.net/dns-query||
controld|Control D|base|76.76.2.0,76.76.10.0|2606:1a40::,2606:1a40:1::|p0.freedns.controld.com|freedns.controld.com/p0|freedns.controld.com|
dnsforge|dnsforge.de|ads|176.9.93.198,176.9.1.117|2a01:4f8:151:34aa::198,2a01:4f8:141:316d::117|dnsforge.de|dnsforge.de/dns-query|dnsforge.de|
'

provider_keys() {
    printf '%s\n' "$PROVIDER_DB" | awk -F'|' 'NF>1 && $1!="" && !seen[$1]++ { print $1 }'
}

provider_title() {
    printf '%s\n' "$PROVIDER_DB" | awk -F'|' -v k="$1" 'NF>1 && $1==k { print $2; exit }'
}

profile_keys() {
    printf '%s\n' "$PROVIDER_DB" | awk -F'|' -v k="$1" 'NF>1 && $1==k { print $3 }'
}

profile_label() {
    case "$1" in
        base)       printf 'provider default' ;;
        ads)        printf 'ad / tracker blocking' ;;
        security)   printf 'malware blocking' ;;
        family)     printf 'family protection + safe search' ;;
        unfiltered) printf 'unfiltered (no blocking at all)' ;;
        safe)       printf 'phishing protection (safe)' ;;
        *)          printf '%s' "$1" ;;
    esac
}

# Describes what the "base" profile of the loaded provider actually does.
provider_default_desc() {
    case "$P_KEY" in
        adguard)  printf 'default: ads, trackers and phishing are blocked' ;;
        dnsforge) printf 'default: ads and trackers are blocked' ;;
        quad9)    printf 'default: malware and phishing are blocked' ;;
        controld) printf 'default: Control D free profile' ;;
        *)        printf 'no filtering (plain recursive resolver)' ;;
    esac
}

# Human readable description of one profile of a provider (without loading it).
# $1 = provider key, $2 = profile
profile_label_at() {
    if [ "$2" = "base" ]; then
        _saved_key="$P_KEY"
        P_KEY="$1"
        printf '%s - %s' "$(profile_label base)" "$(provider_default_desc)"
        P_KEY="$_saved_key"
    else
        printf '%s' "$(profile_label "$2")"
    fi
}

# $1 = provider key, $2 = profile -> fills the P_* variables
provider_load() {
    _prov="$1"; _prof="${2:-base}"; _req_prof="$_prof"
    [ -n "$_prov" ] || return 1
    _line=$(printf '%s\n' "$PROVIDER_DB" | awk -F'|' -v k="$_prov" -v p="$_prof" \
        'NF>1 && $1==k && $3==p { print; exit }')
    # Fall back to the base profile when the requested one does not exist.
    if [ -z "$_line" ] && [ "$_prof" != "base" ]; then
        _line=$(printf '%s\n' "$PROVIDER_DB" | awk -F'|' -v k="$_prov" \
            'NF>1 && $1==k && $3=="base" { print; exit }')
    fi
    # A provider without a base profile (for example dnsforge) uses its first
    # profile when the caller asked for base.
    if [ -z "$_line" ] && [ "$_req_prof" = "base" ]; then
        _line=$(printf '%s\n' "$PROVIDER_DB" | awk -F'|' -v k="$_prov" \
            'NF>1 && $1==k { print; exit }')
    fi
    [ -n "$_line" ] || return 1
    _prof=$(printf '%s' "$_line" | cut -d'|' -f3)
    P_KEY="$_prov"
    P_PROFILE="$_prof"
    P_NAME=$(printf '%s' "$_line" | cut -d'|' -f2)
    P_V4=$(printf '%s' "$_line" | cut -d'|' -f4)
    P_V6=$(printf '%s' "$_line" | cut -d'|' -f5)
    P_DOT=$(printf '%s' "$_line" | cut -d'|' -f6)
    P_DOH=$(printf '%s' "$_line" | cut -d'|' -f7)
    P_DOQ=$(printf '%s' "$_line" | cut -d'|' -f8)
    P_SDNS=$(printf '%s' "$_line" | cut -d'|' -f9)
    return 0
}

# "Cloudflare [family]" - the full name of the selected profile.
provider_label() {
    if [ "$P_PROFILE" = "base" ]; then
        printf '%s' "$P_NAME"
    else
        printf '%s [%s]' "$P_NAME" "$P_PROFILE"
    fi
}

# Legacy flat keys from earlier versions, mapped to provider:profile.
legacy_key_profile() {
    case "$1" in
        quad9-unsecured)  printf 'unfiltered' ;;
        quad9)            printf 'base' ;;
        cloudflare-security) printf 'security' ;;
        cloudflare-family)   printf 'family' ;;
        adguard-family)      printf 'family' ;;
        adguard-unfiltered)  printf 'unfiltered' ;;
        opendns-family)      printf 'family' ;;
        yandex-safe)         printf 'safe' ;;
        *)                   return 1 ;;
    esac
}

# Loads a provider from a CLI/state key.  Accepts "adguard", "adguard:family"
# and legacy flat keys such as "adguard-family".
provider_parse_key() {
    _k="$1"
    _prov="$_k"; _prof="base"
    case "$_k" in
        *:*) _prov="${_k%%:*}"; _prof="${_k#*:}" ;;
        *)
            if provider_has "$_k"; then
                _prov="$_k"; _prof="base"
            elif _lp=$(legacy_key_profile "$_k"); then
                _prov="${_k%%-*}"; _prof="$_lp"
            fi
            ;;
    esac
    provider_load "$_prov" "$_prof"
}

provider_has() {
    case " $(provider_keys | tr '\n' ' ') " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

profile_has() {
    case " $(profile_keys "$1" | tr '\n' ' ') " in
        *" $2 "*) return 0 ;;
        *) return 1 ;;
    esac
}

# Turn a comma separated list into space separated words.
csv() { printf '%s' "$1" | tr ',' ' '; }

# =============================================================================
#  Dependency management
# =============================================================================
download_file() {
    # $1 url, $2 destination
    if have curl; then
        curl -fL --connect-timeout 15 --retry 2 --retry-delay 1 -o "$2" "$1"
    elif have wget; then
        wget -q -O "$2" "$1"
    else
        return 1
    fi
}

ensure_download_tool() {
    if have curl || have wget; then return 0; fi
    warn "Neither curl nor wget is available."
    if confirm "Install curl using $PKG_MGR?"; then
        pkg_update >/dev/null 2>&1
        pkg_install curl ca-certificates >/dev/null 2>&1 || pkg_install curl wget >/dev/null 2>&1
    fi
    have curl || have wget
}

dnsproxy_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   printf 'amd64' ;;
        i[3-6]86)       printf '386' ;;
        aarch64|arm64)  printf 'arm64' ;;
        armv7l|armv7)   printf 'arm7' ;;
        armv6l|armv6)   printf 'arm6' ;;
        armv5l|armv5)   printf 'arm5' ;;
        ppc64le)        printf 'ppc64le' ;;
        mips64el)       printf 'mips64le' ;;
        mipsel)         printf 'mipsle' ;;
        mips64)         printf 'mips64' ;;
        mips)           printf 'mips' ;;
        *)              return 1 ;;
    esac
}

sha256_file() {
    if have sha256sum; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    elif have openssl; then
        openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    else
        return 1
    fi
}

dnsproxy_expected_sha256() {
    case "$DNSPROXY_VERSION:$1" in
        v0.86.0:386)      printf '%s' '29942608cc9af1583c64f5e7ce6c3b9cfd762c351f10981e2f0655d93d78eeea' ;;
        v0.86.0:amd64)    printf '%s' '17ac43f76ebfcedf547c663f6f31aa70e68b8eb6fc41d2fc37d3bfe21a2ced66' ;;
        v0.86.0:arm5)     printf '%s' '034bfe2e0cf90ea1b8017bfa6aa846e0102790e43f9fff43dbd97c39be3bed91' ;;
        v0.86.0:arm6)     printf '%s' 'c681c3c75eee9a70533eee3aa7f8dc745714adafef2b3b5f4d84faf36567ed5f' ;;
        v0.86.0:arm64)    printf '%s' 'eda840d39da0c2777ea2431d3d73407e813e3fc0e411bfe256a9fb4b97d08247' ;;
        v0.86.0:arm7)     printf '%s' '927ead9df72528d6f54bac14e6eb07873a712d0d5deee14d4770bf9d64661102' ;;
        v0.86.0:mips)     printf '%s' '7f992f2fb2b8babec9cc94930fef2a8ad8c6cbb977ababea86bffba149a74ae1' ;;
        v0.86.0:mips64)   printf '%s' 'b0f81b1cbe3aaef39d071cab242518e3ff69f08a142f661d8591b43fa0c521bb' ;;
        v0.86.0:mips64le) printf '%s' '94d38bb46011b5e8897e63ffebe98d360981892488ec44c8d5c4437fc4a29f0f' ;;
        v0.86.0:mipsle)   printf '%s' '2af9a8946c04200957841a31431689336d52d32417d5025ba589ebb1fb8de76e' ;;
        v0.86.0:ppc64le)  printf '%s' '5397021331f380b6b301dd73d3a19a79d8f8458234e3412172f2f9bcfb19dde2' ;;
        *) return 1 ;;
    esac
}

install_dnsproxy_binary() {
    _arch=$(dnsproxy_arch) || { err "Unsupported CPU architecture: $(uname -m)"; return 1; }
    _bindir=$(dirname "$DNSPROXY_BIN")
    mkdir -p "$_bindir" 2>/dev/null
    if [ ! -w "$_bindir" ]; then
        DNSPROXY_BIN="${XDG_DATA_HOME:-${HOME:-/tmp}/.local/share}/$APP/dnsproxy"
        mkdir -p "$(dirname "$DNSPROXY_BIN")" 2>/dev/null
    fi
    ensure_download_tool || { err "A download tool (curl/wget) is required."; return 1; }
    have tar || pkg_install tar >/dev/null 2>&1

    _tmp=$(mktemp -d 2>/dev/null) || _tmp="/tmp/$APP.$$"
    mkdir -p "$_tmp" || return 1
    _url="https://github.com/$DNSPROXY_REPO/releases/download/$DNSPROXY_VERSION/dnsproxy-linux-$_arch-$DNSPROXY_VERSION.tar.gz"
    msg "Downloading dnsproxy $DNSPROXY_VERSION (linux-$_arch) ..."
    if ! download_file "$_url" "$_tmp/dnsproxy.tar.gz"; then
        err "Download failed: $_url"
        rm -rf "$_tmp"
        return 1
    fi
    _expected="${DNSPROXY_SHA256:-}"
    if [ -z "$_expected" ]; then
        _expected=$(dnsproxy_expected_sha256 "$_arch") || _expected=""
    fi
    if [ -z "$_expected" ]; then
        if [ "$ALLOW_UNVERIFIED" != "yes" ]; then
            err "No pinned checksum for dnsproxy $DNSPROXY_VERSION ($_arch)."
            err "Set DNSPROXY_SHA256=<sha256> or pass --allow-unverified."
            rm -rf "$_tmp"
            return 1
        fi
        warn "Skipping dnsproxy checksum verification (--allow-unverified)."
    else
        _actual=$(sha256_file "$_tmp/dnsproxy.tar.gz") || _actual=""
        if [ -z "$_actual" ]; then
            if [ "$ALLOW_UNVERIFIED" != "yes" ]; then
                err "No sha256 tool available (sha256sum, shasum or openssl)."
                rm -rf "$_tmp"
                return 1
            fi
            warn "Cannot compute sha256; continuing because --allow-unverified."
        elif [ "$_actual" != "$_expected" ]; then
            err "Checksum mismatch for $_url"
            err "expected: $_expected"
            err "actual:   $_actual"
            rm -rf "$_tmp"
            return 1
        fi
    fi
    tar -xzf "$_tmp/dnsproxy.tar.gz" -C "$_tmp" 2>/dev/null || { err "Cannot extract archive."; rm -rf "$_tmp"; return 1; }
    _bin=$(find "$_tmp" -type f -name dnsproxy 2>/dev/null | head -n1)
    [ -n "$_bin" ] || { err "dnsproxy binary not found inside the archive."; rm -rf "$_tmp"; return 1; }
    if have install; then
        install -m 0755 "$_bin" "$DNSPROXY_BIN"
    else
        cp "$_bin" "$DNSPROXY_BIN" && chmod 0755 "$DNSPROXY_BIN"
    fi
    _rc=$?
    rm -rf "$_tmp"
    [ "$_rc" -eq 0 ] || { err "Cannot install $DNSPROXY_BIN"; return 1; }
    DNSPROXY_RESOLVED="$DNSPROXY_BIN"
    ok "Installed $DNSPROXY_BIN"
    return 0
}

ensure_dnsproxy() {
    if [ -n "${DNSPROXY_OVERRIDE:-}" ] && [ -x "$DNSPROXY_OVERRIDE" ]; then
        DNSPROXY_RESOLVED="$DNSPROXY_OVERRIDE"; return 0
    fi
    if [ -x "$DNSPROXY_BIN" ]; then
        DNSPROXY_RESOLVED="$DNSPROXY_BIN"; return 0
    fi
    if have dnsproxy; then
        DNSPROXY_RESOLVED=$(command -v dnsproxy); return 0
    fi
    if [ ! -t 0 ] && [ "$ASSUME_YES" != "yes" ]; then
        die "dnsproxy is not installed. Install it or run with --yes."
    fi
    warn "dnsproxy is not installed."
    confirm "Download dnsproxy $DNSPROXY_VERSION from GitHub to $DNSPROXY_BIN?" \
        || die "dnsproxy is required for encrypted transports."
    install_dnsproxy_binary || die "Could not install dnsproxy."
    return 0
}

ensure_dig() {
    have dig && return 0
    warn "The 'dig' tool is not installed (needed for latency/stability tests)."
    if [ ! -t 0 ] && [ "$ASSUME_YES" != "yes" ]; then
        return 1
    fi
    _pkg=$(dig_package_name)
    if [ -n "$_pkg" ] && confirm "Install '$_pkg' using $PKG_MGR?"; then
        pkg_update >/dev/null 2>&1
        pkg_install "$_pkg" >/dev/null 2>&1
    fi
    have dig && return 0
    return 1
}

# =============================================================================
#  State / backup helpers
# =============================================================================
ensure_dirs() {
    if mkdir -p "$STATE_DIR" "$BACKUP_DIR" 2>/dev/null && [ -w "$STATE_DIR" ]; then
        return 0
    fi
    # Fallback for unprivileged runs (latency tests do not need root).
    STATE_DIR="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/$APP"
    BACKUP_DIR="$STATE_DIR/backup"
    STATE_FILE="$STATE_DIR/state"
    RESOLV_BACKUP="$BACKUP_DIR/resolv.conf.orig"
    mkdir -p "$STATE_DIR" "$BACKUP_DIR" 2>/dev/null
}

save_state() {
    ensure_dirs
    {
        printf '# %s state file, written automatically\n' "$APP"
        printf 'MODE=%s\n' "$MODE_USED"
        printf 'PROVIDER=%s\n' "$P_KEY"
        printf 'PROFILE=%s\n' "$P_PROFILE"
        printf 'PROVIDER_NAME=%s\n' "$(provider_label)"
        printf 'RESOLVER=%s\n' "$RESOLVER"
        printf 'UPDATED=%s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)"
    } > "$STATE_FILE" || return 1
    return 0
}

state_file_path() {
    if [ -r "/etc/$APP/state" ]; then
        printf '/etc/%s/state' "$APP"
    else
        printf '%s/state' "$STATE_DIR"
    fi
}

state_get() {
    _sf=$(state_file_path)
    [ -f "$_sf" ] || return 1
    sed -n "s/^$1=//p" "$_sf" | head -n1
}

snapshot_save_path() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        cp -a "$1" "$SNAPSHOT_DIR/$2" 2>/dev/null || return 1
        : > "$SNAPSHOT_DIR/$2.present"
    else
        : > "$SNAPSHOT_DIR/$2.absent"
    fi
    return 0
}

snapshot_restore_path() {
    [ -d "$SNAPSHOT_DIR" ] || return 0
    if [ -f "$SNAPSHOT_DIR/$2.present" ]; then
        rm -rf "$1"
        cp -a "$SNAPSHOT_DIR/$2" "$1" 2>/dev/null
    elif [ -f "$SNAPSHOT_DIR/$2.absent" ]; then
        rm -rf "$1"
    fi
    return 0
}

snapshot_save() {
    ensure_dirs
    SNAPSHOT_DIR="$STATE_DIR/snapshot"
    rm -rf "$SNAPSHOT_DIR"
    mkdir -p "$SNAPSHOT_DIR" || return 1
    snapshot_save_path "$RESOLV_CONF" resolv.conf || return 1
    snapshot_save_path "$RESOLV_BACKUP" resolv-orig || return 1
    snapshot_save_path "$BACKUP_DIR/resolv.conf.pre-resolved" pre-resolved || return 1
    snapshot_save_path "$RESOLVED_DROPIN" resolved-dropin || return 1
    snapshot_save_path "$NM_CONF" nm-conf || return 1
    snapshot_save_path "$SYSTEMD_UNIT" systemd-unit || return 1
    snapshot_save_path "$OPENRC_INIT" openrc-init || return 1
    SNAPSHOT_ACTIVE="yes"
    return 0
}

snapshot_drop() {
    [ -n "$SNAPSHOT_DIR" ] && rm -rf "$SNAPSHOT_DIR" 2>/dev/null
    SNAPSHOT_ACTIVE="no"
}

snapshot_restore() {
    [ "$SNAPSHOT_ACTIVE" = "yes" ] || return 0
    if [ ! -d "$SNAPSHOT_DIR" ]; then
        SNAPSHOT_ACTIVE="no"
        return 0
    fi
    warn "Rolling back to the previous DNS configuration ..."
    svc_stop
    snapshot_restore_path "$RESOLV_CONF" resolv.conf
    snapshot_restore_path "$RESOLV_BACKUP" resolv-orig
    snapshot_restore_path "$BACKUP_DIR/resolv.conf.pre-resolved" pre-resolved
    snapshot_restore_path "$RESOLVED_DROPIN" resolved-dropin
    snapshot_restore_path "$NM_CONF" nm-conf
    snapshot_restore_path "$SYSTEMD_UNIT" systemd-unit
    snapshot_restore_path "$OPENRC_INIT" openrc-init
    if [ -f "$SNAPSHOT_DIR/systemd-unit.present" ]; then
        have systemctl && systemctl daemon-reload >/dev/null 2>&1
        have systemctl && systemctl enable "$APP" >/dev/null 2>&1
        have systemctl && systemctl restart "$APP" >/dev/null 2>&1
    elif [ -f "$SNAPSHOT_DIR/openrc-init.present" ]; then
        have rc-update && rc-update add "$APP" default >/dev/null 2>&1
        have rc-service && rc-service "$APP" restart >/dev/null 2>&1
    fi
    if [ -f "$SNAPSHOT_DIR/resolved-dropin.present" ] \
        || [ -f "$SNAPSHOT_DIR/resolved-dropin.absent" ]; then
        have systemctl && systemctl try-restart systemd-resolved >/dev/null 2>&1
        have resolvectl && resolvectl flush-caches >/dev/null 2>&1
    fi
    if [ -f "$SNAPSHOT_DIR/nm-conf.present" ] \
        || [ -f "$SNAPSHOT_DIR/nm-conf.absent" ]; then
        have systemctl && systemctl reload-or-try-restart NetworkManager >/dev/null 2>&1
    fi
    SNAPSHOT_ACTIVE="no"
    warn "Previous DNS configuration restored."
    return 0
}

rollback_on_exit() {
    [ "$SNAPSHOT_ACTIVE" = "yes" ] && snapshot_restore
    return 0
}

# =============================================================================
#  systemd-resolved backend
# =============================================================================
resolved_ensure_running() {
    if have systemctl && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        return 0
    fi
    if have systemctl; then
        systemctl enable --now systemd-resolved >/dev/null 2>&1
        systemctl is-active --quiet systemd-resolved 2>/dev/null && return 0
    fi
    return 1
}

# Point /etc/resolv.conf at the resolved stub resolver so that everything
# goes through systemd-resolved (the previous file is preserved).
resolved_ensure_stub_symlink() {
    _stub="/run/systemd/resolve/stub-resolv.conf"
    if [ ! -e "$_stub" ]; then
        warn "systemd-resolved stub resolver not found at $_stub."
        return 1
    fi
    ensure_dirs
    if { [ -e "$RESOLV_CONF" ] || [ -L "$RESOLV_CONF" ]; } \
        && [ ! -e "$BACKUP_DIR/resolv.conf.pre-resolved" ]; then
        cp -a "$RESOLV_CONF" "$BACKUP_DIR/resolv.conf.pre-resolved" 2>/dev/null
    fi
    if [ -L "$RESOLV_CONF" ] \
        && [ "$(readlink "$RESOLV_CONF" 2>/dev/null)" = "$_stub" ]; then
        return 0
    fi
    rm -f "$RESOLV_CONF"
    ln -s "$_stub" "$RESOLV_CONF" 2>/dev/null || return 1
    return 0
}

# $1 = DNS server list, $2 = yes/no for DNSOverTLS
resolved_write() {
    mkdir -p "$RESOLVED_DROPIN_DIR" 2>/dev/null || return 1
    resolved_ensure_stub_symlink || return 1
    {
        printf '# Generated by %s on %s. Do not edit manually.\n' "$APP" "$(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)"
        printf '[Resolve]\n'
        printf 'DNS=%s\n' "$1"
        printf 'DNSOverTLS=%s\n' "$2"
        printf 'Domains=~.\n'
        printf 'FallbackDNS=\n'
    } > "$RESOLVED_DROPIN" || return 1
    systemctl restart systemd-resolved >/dev/null 2>&1 || {
        err "Cannot restart systemd-resolved."
        return 1
    }
    systemctl is-active --quiet systemd-resolved 2>/dev/null || {
        err "systemd-resolved is not active after restart."
        return 1
    }
    have resolvectl && resolvectl flush-caches >/dev/null 2>&1
    RESOLVER="resolved"
    return 0
}

resolved_clear() {
    if [ -f "$RESOLVED_DROPIN" ]; then
        rm -f "$RESOLVED_DROPIN"
        systemctl restart systemd-resolved >/dev/null 2>&1
        have resolvectl && resolvectl flush-caches >/dev/null 2>&1
    fi
}

# =============================================================================
#  NetworkManager / plain file backend
# =============================================================================
file_backup_resolv() {
    ensure_dirs
    if [ ! -e "$RESOLV_BACKUP" ] && [ ! -L "$RESOLV_BACKUP" ] \
        && { [ -e "$RESOLV_CONF" ] || [ -L "$RESOLV_CONF" ]; }; then
        cp -a "$RESOLV_CONF" "$RESOLV_BACKUP" 2>/dev/null
    fi
}

nm_disable_management() {
    have nmcli || return 0
    case "$RESOLVER" in
        networkmanager|file) : ;;
        *) return 0 ;;
    esac
    mkdir -p "$(dirname "$NM_CONF")" 2>/dev/null
    {
        printf '# Generated by %s: keep NetworkManager from overwriting %s\n' "$APP" "$RESOLV_CONF"
        printf '[main]\n'
        printf 'dns=none\n'
        printf 'rc-manager=unmanaged\n'
    } > "$NM_CONF"
    systemctl reload NetworkManager >/dev/null 2>&1
}

nm_restore_management() {
    [ -f "$NM_CONF" ] && rm -f "$NM_CONF"
    have systemctl && systemctl reload NetworkManager >/dev/null 2>&1
}

# $@ = nameserver addresses
file_write_resolv() {
    file_backup_resolv
    # Drop a symlink (e.g. the resolved stub) so our content actually sticks.
    if [ -L "$RESOLV_CONF" ]; then
        rm -f "$RESOLV_CONF"
    fi
    {
        printf '# Generated by %s on %s\n' "$APP" "$(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)"
        for _ns in "$@"; do
            [ -n "$_ns" ] && printf 'nameserver %s\n' "$_ns"
        done
        printf 'options timeout:2 attempts:2\n'
    } > "$RESOLV_CONF" || return 1
    chmod 0644 "$RESOLV_CONF" 2>/dev/null
    return 0
}

# =============================================================================
#  Local proxy service management (systemd / OpenRC / background fallback)
# =============================================================================
svc_stop() {
    case "$INIT_SYS" in
        systemd)
            systemctl stop "$APP" >/dev/null 2>&1
            systemctl disable "$APP" >/dev/null 2>&1
            ;;
        openrc)
            rc-service "$APP" stop >/dev/null 2>&1
            rc-update del "$APP" default >/dev/null 2>&1
            ;;
    esac
    if [ -f "$STATE_DIR/pid" ]; then
        _p=$(cat "$STATE_DIR/pid" 2>/dev/null)
        if [ -n "$_p" ]; then
            kill "$_p" >/dev/null 2>&1
        fi
        rm -f "$STATE_DIR/pid"
    fi
}

svc_write_systemd_unit() {
    # $1 = arguments (without the binary path)
    {
        printf '[Unit]\n'
        printf 'Description=%s local DNS proxy (AdGuard dnsproxy)\n' "$APP"
        printf 'After=network-online.target nss-lookup.target\n'
        printf 'Wants=network-online.target\n'
        printf 'Before=nss-lookup.target\n\n'
        printf '[Service]\n'
        printf 'Type=simple\n'
        printf 'ExecStart=%s %s\n' "$DNSPROXY_RESOLVED" "$1"
        printf 'Restart=on-failure\n'
        printf 'RestartSec=2\n'
        printf 'LimitNOFILE=8192\n\n'
        printf '[Install]\n'
        printf 'WantedBy=multi-user.target\n'
    } > "$SYSTEMD_UNIT" || return 1
    systemctl daemon-reload >/dev/null 2>&1
    return 0
}

svc_write_openrc_script() {
    # $1 = arguments (without the binary path)
    {
        printf '#!/sbin/openrc-run\n'
        printf 'name="%s"\n' "$APP"
        printf 'description="Local DNS proxy (AdGuard dnsproxy)"\n'
        printf 'command="%s"\n' "$DNSPROXY_RESOLVED"
        printf 'command_args="%s"\n' "$1"
        printf 'command_background="yes"\n'
        printf 'pidfile="/run/%s.pid"\n' "$APP"
        printf 'depend() { need net; after firewall; use dns logger; }\n'
    } > "$OPENRC_INIT" || return 1
    chmod 0755 "$OPENRC_INIT"
    return 0
}

# Install and (re)start the proxy with the given dnsproxy arguments.
svc_install_and_start() {
    _args="$1"
    case "$INIT_SYS" in
        systemd)
            svc_write_systemd_unit "$_args" || return 1
            systemctl enable "$APP" >/dev/null 2>&1
            if ! systemctl restart "$APP" >/dev/null 2>&1; then
                systemctl status "$APP" --no-pager -l 2>&1 | tail -n 12 >&2
                systemctl disable "$APP" >/dev/null 2>&1
                rm -f "$SYSTEMD_UNIT" 2>/dev/null
                systemctl daemon-reload >/dev/null 2>&1
                return 1
            fi
            ;;
        openrc)
            svc_write_openrc_script "$_args" || return 1
            rc-update add "$APP" default >/dev/null 2>&1
            if ! rc-service "$APP" restart >/dev/null 2>&1; then
                rc-update del "$APP" default >/dev/null 2>&1
                rm -f "$OPENRC_INIT" 2>/dev/null
                return 1
            fi
            ;;
        *)
            err "No supported service manager (systemd or OpenRC)."
            return 1
            ;;
    esac
    return 0
}

svc_remove_unit() {
    svc_stop
    rm -f "$SYSTEMD_UNIT" "$OPENRC_INIT" 2>/dev/null
    have systemctl && systemctl daemon-reload >/dev/null 2>&1
}

# =============================================================================
#  Transport selection helpers
# =============================================================================
mode_label() {
    case "$1" in
        plain)    printf 'Plain DNS (Do53, UDP/TCP 53)' ;;
        dot)      printf 'DNS-over-TLS (DoT, port 853)' ;;
        doh)      printf 'DNS-over-HTTPS (DoH, HTTP/2 + HTTP/3 auto)' ;;
        doh3)     printf 'DNS-over-HTTPS, HTTP/3 forced (no fallback, diagnostic only)' ;;
        doq)      printf 'DNS-over-QUIC (DoQ, port 853)' ;;
        dnscrypt) printf 'DNSCrypt v2 [best effort]' ;;
        *)        printf '%s' "$1" ;;
    esac
}

# Transports offered in the interactive menus.  HTTP/2 and HTTP/3 are two
# modes of one DoH transport, so they are not listed separately: 'doh' asks
# the proxy for HTTP/3 and lets it fall back to HTTP/2 where UDP/443 is
# blocked.  'doh3' exists only as an explicit CLI switch for diagnostics.
MENU_MODES="plain dot doh doq dnscrypt"
ALL_MODES="plain dot doh doh3 doq dnscrypt"

# Returns success when the currently loaded provider supports the transport.
mode_available() {
    case "$1" in
        plain)    [ -n "$P_V4" ] || [ -n "$P_V6" ] ;;
        dot)      [ -n "$P_DOT" ] ;;
        doh|doh3) [ -n "$P_DOH" ] ;;
        doq)      [ -n "$P_DOQ" ] ;;
        dnscrypt) [ -n "$P_SDNS" ] ;;
        *)        return 1 ;;
    esac
}

bootstrap_args() {
    _out=""
    for _ip in $(csv "$P_V4"); do _out="$_out -b $_ip"; done
    if [ "$HAS_IPV6" = "yes" ]; then
        for _ip in $(csv "$P_V6"); do _out="$_out -b $_ip"; done
    fi
    if [ -z "$_out" ]; then
        _out=" -b $PING_TARGET_V4 -b 8.8.8.8"
    fi
    printf '%s' "$_out"
}

sleep_short() {
    sleep 0.2 2>/dev/null || sleep 1
}

port53_busy() {
    _holders=""
    if have ss; then
        _holders=$(
            { ss -H -lunp 2>/dev/null; ss -H -ltnp 2>/dev/null; } |
            awk '$4=="0.0.0.0:53" || $4=="127.0.0.1:53" || $4=="[::]:53" || $4=="*:53"'
        )
    elif have lsof; then
        _holders=$(lsof -nP -iUDP:53 -iTCP:53 2>/dev/null | grep -E ' (0\.0\.0\.0|127\.0\.0\.1|\[::\]|\*):53( |$)')
    elif have netstat; then
        _holders=$(netstat -lunpt 2>/dev/null | awk '$4=="0.0.0.0:53" || $4=="127.0.0.1:53" || $4=="[::]:53" || $4=="*:53"')
    elif [ -r /proc/net/udp ] || [ -r /proc/net/tcp ]; then
        _holders=$(awk 'NR>1 { split($2,a,":"); if (a[2]=="0035" && (a[1]=="00000000" || a[1]=="0100007F")) print $2 }' /proc/net/udp /proc/net/tcp 2>/dev/null)
    fi
    [ -n "$_holders" ] || return 1
    printf '%s\n' "$_holders" | head -n 5
    return 0
}

wait_proxy() {
    if ! have dig; then
        warn "dig is not available - skipping the direct proxy check."
        sleep 1
        return 0
    fi
    _tries=0
    while [ "$_tries" -lt 20 ]; do
        _r=$(dig +time=1 +tries=1 +short -p "$PROXY_PORT" "@$PROXY_LISTEN" "$TEST_DOMAIN" A 2>/dev/null | grep -E '^[0-9]' | head -n1)
        [ -n "$_r" ] && return 0
        _tries=$((_tries + 1))
        sleep_short
    done
    return 1
}

# =============================================================================
#  Applying the configuration
# =============================================================================
apply_plain() {
    _list=""
    for _ip in $(csv "$P_V4"); do _list="$_list $_ip"; done
    if [ "$HAS_IPV6" = "yes" ]; then
        for _ip in $(csv "$P_V6"); do _list="$_list $_ip"; done
    elif [ -n "$P_V6" ]; then
        warn "No IPv6 connectivity detected - IPv6 resolver addresses are skipped."
    fi
    _list=$(printf '%s' "$_list" | sed 's/^ *//; s/  */ /g')
    [ -n "$_list" ] || die "Provider '$P_KEY' does not publish plain DNS addresses."

    svc_remove_unit
    msg "Configuring plain DNS: $_list"
    case "$RESOLVER" in
        resolved)
            resolved_ensure_running || die "systemd-resolved is not available."
            resolved_write "$_list" "no" || return 1
            ;;
        *)
            nm_disable_management
            # shellcheck disable=SC2086
            file_write_resolv $_list || return 1
            ;;
    esac
    MODE_USED="plain"
    return 0
}

apply_dot() {
    [ -n "$P_DOT" ] || die "Provider '$P_KEY' does not publish a DoT hostname."
    if [ "$INIT_SYS" = "systemd" ] && resolved_available && resolved_ensure_running; then
        _list=""
        for _ip in $(csv "$P_V4"); do _list="$_list $_ip#$P_DOT"; done
        if [ "$HAS_IPV6" = "yes" ]; then
            for _ip in $(csv "$P_V6"); do _list="$_list $_ip#$P_DOT"; done
        fi
        if [ -z "$_list" ]; then
            _list="$P_DOT"
        else
            _list=$(printf '%s' "$_list" | sed 's/^ *//; s/  */ /g')
        fi
        svc_remove_unit
        msg "Enabling DNS-over-TLS through systemd-resolved (strict): $P_DOT"
        resolved_write "$_list" "yes" || return 1
    else
        service_supported || die "DNS-over-TLS via dnsproxy requires systemd or OpenRC; plain DNS still works."
        msg "systemd-resolved is unavailable - DoT will be provided by dnsproxy."
        apply_proxy "tls://$P_DOT" || return 1
    fi
    MODE_USED="dot"
    return 0
}

# $1 = complete upstream specifier understood by dnsproxy
# $2 = optional extra dnsproxy flags
apply_proxy() {
    _up="$1"
    _extra="${2:-}"
    service_supported || die "Encrypted DNS requires systemd or OpenRC. Plain DNS (--mode plain) still works."
    ensure_dnsproxy
    svc_remove_unit
    if _holders=$(port53_busy); then
        err "Port 53 is already in use:"
        printf '%s\n' "$_holders" >&2
        die "Stop the service that holds port 53, or use --mode plain."
    fi
    _bs=$(bootstrap_args)
    _args="-l $PROXY_LISTEN -p $PROXY_PORT -u $_up$_bs --cache --timeout=5s"
    [ -n "$_extra" ] && _args="$_args $_extra"
    msg "Starting the local DNS proxy on $PROXY_LISTEN:$PROXY_PORT ..."
    if ! svc_install_and_start "$_args"; then
        err "Failed to start the local DNS proxy (see: journalctl -u $APP)."
        return 1
    fi
    if ! wait_proxy; then
        warn "The DNS proxy did not answer within the timeout - the upstream may be blocked."
        return 1
    fi
    if [ "$RESOLVER" = "resolved" ] && resolved_ensure_running; then
        resolved_write "$PROXY_LISTEN" "no" || return 1
    else
        nm_disable_management
        file_write_resolv "$PROXY_LISTEN" || return 1
    fi
    return 0
}

# systemd-resolved is internally bypassed for DoH/DoQ: the proxy listens on
# 127.0.0.1:53 and becomes the only resolver the system talks to.
apply_doh() {
    [ -n "$P_DOH" ] || die "Provider '$P_KEY' does not publish a DoH endpoint."
    msg "Configuring DNS-over-HTTPS: https://$P_DOH"
    msg "(HTTP/3 is tried first and HTTP/2 is used automatically where UDP/443 is blocked)"
    apply_proxy "https://$P_DOH" "--http3" || return 1
    MODE_USED="doh"
    return 0
}

# Explicit HTTP/3-only mode for diagnostics.  If the upstream does not answer
# over QUIC the configuration falls back to regular DoH so that the machine is
# never left without a working resolver.
apply_doh3() {
    [ -n "$P_DOH" ] || die "Provider '$P_KEY' does not publish a DoH endpoint."
    warn "DoH3 forces HTTP/3 without fallback and needs reachable UDP/443."
    msg "Trying DNS-over-HTTPS with forced HTTP/3: h3://$P_DOH"
    if apply_proxy "h3://$P_DOH" ""; then
        MODE_USED="doh3"
        return 0
    fi
    warn "No answer over HTTP/3 - falling back to DoH (HTTP/3 preferred, HTTP/2 allowed)."
    apply_proxy "https://$P_DOH" "--http3" || return 1
    MODE_USED="doh"
    return 0
}

apply_doq() {
    [ -n "$P_DOQ" ] || die "Provider '$P_KEY' does not publish a DoQ hostname."
    msg "Configuring DNS-over-QUIC: quic://$P_DOQ"
    apply_proxy "quic://$P_DOQ" || return 1
    MODE_USED="doq"
    return 0
}

apply_dnscrypt() {
    [ -n "$P_SDNS" ] || die "Provider '$P_KEY' does not publish a DNSCrypt stamp."
    warn "DNSCrypt uses ports 5443/443 over UDP+TCP and is blocked by some networks."
    msg "Configuring DNSCrypt ..."
    apply_proxy "$P_SDNS" || return 1
    MODE_USED="dnscrypt"
    return 0
}

verify_resolution() {
    msg "Verifying name resolution ..."
    _tries=0
    _res=""
    while [ "$_tries" -lt 8 ]; do
        if have dig; then
            _res=$(dig +time=2 +tries=1 +short "$TEST_DOMAIN" A 2>/dev/null | grep -E '^[0-9]' | head -n1)
        elif have getent; then
            _res=$(getent ahostsv4 "$TEST_DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')
        fi
        [ -n "$_res" ] && break
        _tries=$((_tries + 1))
        sleep 1
    done
    if [ -n "$_res" ]; then
        ok "Resolution works: $TEST_DOMAIN -> $_res"
        return 0
    fi
    warn "Resolution check failed - run '$APP --test' or restore the defaults."
    return 1
}

validate_selection() {
    case "$MODE" in
        plain|dot|doh|doh3|doq|dnscrypt) : ;;
        *) die "Unknown transport '$MODE'. Valid values: plain dot doh doq dnscrypt (plus doh3 for diagnostics)" ;;
    esac
    provider_has "$PROV_KEY" || die "Unknown provider '$PROV_KEY'. Run '$APP --list'."
    if [ "${PROV_PROFILE:-base}" != "base" ] && ! profile_has "$PROV_KEY" "$PROV_PROFILE"; then
        die "Provider '$PROV_KEY' has no '$PROV_PROFILE' profile. Available: $(profile_keys "$PROV_KEY" | tr '\n' ' ')"
    fi
    provider_load "$PROV_KEY" "${PROV_PROFILE:-base}" || die "Cannot load '$PROV_KEY'."
    mode_available "$MODE" || die "Provider '$(provider_label)' does not support the '$MODE' transport."
}

apply_mode() {
    provider_load "$P_KEY" "$P_PROFILE" || die "Cannot load provider '$P_KEY'."
    mode_available "$MODE" || die "Provider '$(provider_label)' does not support the '$MODE' transport."
    case "$MODE" in
        plain) : ;;
        *) service_supported || die "Encrypted DNS requires systemd or OpenRC. Plain DNS (--mode plain) still works." ;;
    esac
    snapshot_save || die "Cannot create the rollback snapshot."
    case "$MODE" in
        plain)    apply_plain || { snapshot_restore; return 1; } ;;
        dot)      apply_dot || { snapshot_restore; return 1; } ;;
        doh)      apply_doh || { snapshot_restore; return 1; } ;;
        doh3)     apply_doh3 || { snapshot_restore; return 1; } ;;
        doq)      apply_doq || { snapshot_restore; return 1; } ;;
        dnscrypt) apply_dnscrypt || { snapshot_restore; return 1; } ;;
        *)        die "Unknown transport: $MODE" ;;
    esac
    if ! verify_resolution; then
        snapshot_restore
        die "Resolution check failed; the previous configuration was restored."
    fi
    if ! save_state; then
        snapshot_restore
        return 1
    fi
    SNAPSHOT_ACTIVE="no"
    snapshot_drop
    ok "Done: $(provider_label) via $(mode_label "$MODE")"
    return 0
}

# =============================================================================
#  DNS latency / stability testing
# =============================================================================
# Prints the query time in milliseconds, "FAIL" on timeout/error or "NO-DIG".
query_ms() {
    _srv="$1"; _port="$2"; _name="$3"; _type="$4"
    if have dig; then
        _out=$(dig +time=2 +tries=1 +stats -p "$_port" "@$_srv" "$_name" "$_type" 2>/dev/null)
    elif have kdig; then
        _out=$(kdig +timeout=2 -p "$_port" "@$_srv" "$_name" "$_type" 2>/dev/null)
    else
        printf 'NO-DIG\n'
        return 0
    fi
    case "$_out" in
        *"status: NOERROR"*|*"status: NXDOMAIN"*) : ;;
        *) printf 'FAIL\n'; return 0 ;;
    esac
    _ms=$(printf '%s\n' "$_out" | sed -n 's/.*Query time: \([0-9][0-9]*\) *msec.*/\1/p' | head -n1)
    if [ -n "$_ms" ]; then printf '%s\n' "$_ms"; else printf 'FAIL\n'; fi
}

# Reads one result per line from stdin and prints aggregated statistics.
stats_of() {
    awk 'BEGIN{n=0;f=0;min=0;max=0;s=0;j=0;jc=0;prev=""}
    {
        if ($1 ~ /^[0-9]+$/) {
            v=$1+0; n++; s+=v
            if (n==1 || v<min) min=v
            if (n==1 || v>max) max=v
            if (prev!="") { d=v-prev; if (d<0) d=-d; j+=d; jc++ }
            prev=v
        } else if ($1=="FAIL") { f++ }
    }
    END{
        if (n==0) { printf("no responses (failures=%d)\n", f); exit }
        printf("ok=%d failures=%d min=%dms avg=%.1fms max=%dms jitter=%.1fms\n", n, f, min, s/n, max, (jc ? j/jc : 0))
    }'
}

ping_probe() {
    _ip="$1"
    have ping || return 0
    case "$_ip" in *:*) _f="-6" ;; *) _f="-4" ;; esac
    _out=$(ping $_f -c 3 -W 1 -q "$_ip" 2>/dev/null)
    if [ -z "$_out" ]; then
        printf '  ICMP  : no reply\n'
        return 0
    fi
    _loss=$(printf '%s\n' "$_out" | sed -n 's/.*, \([0-9][0-9]*\)% packet loss.*/\1/p' | head -n1)
    _rtt=$(printf '%s\n' "$_out" | sed -n 's|.*= [0-9.]*/\([0-9.]*\)/.*|\1|p' | head -n1)
    printf '  ICMP  : rtt_avg=%sms loss=%s%%\n' "${_rtt:-?}" "${_loss:-?}"
}

probe_plain_ip() {
    _ip="$1"; _n="${2:-$DEFAULT_TEST_COUNT}"
    printf '%s\n' "${C_BOLD}Plain DNS via $_ip${C_RESET}"
    ping_probe "$_ip"
    ( _i=0; while [ "$_i" -lt "$_n" ]; do query_ms "$_ip" 53 "$TEST_DOMAIN" A; _i=$((_i + 1)); done ) \
        | stats_of | sed 's/^/  DNS   : /'
}

# Core encrypted-upstream probe. Sets PROBE_SUM and PROBE_N.
# $1 = upstream, $2 = queries, $3 = port, $4 = "verbose" to print statistics
# $5 = optional extra dnsproxy flags (e.g. --http3)
probe_upstream_core() {
    _url="$1"; _n="${2:-$DEFAULT_TEST_COUNT}"; _port="$3"; _verbose="$4"; _extra="${5:-}"
    PROBE_SUM=0; PROBE_N=0
    ensure_dnsproxy || return 1
    ensure_dirs
    # shellcheck disable=SC2086
    "$DNSPROXY_RESOLVED" -l "$PROXY_LISTEN" -p "$_port" -u "$_url" \
        -b "$PING_TARGET_V4" -b 8.8.8.8 --timeout=5s $_extra >"$STATE_DIR/probe.log" 2>&1 &
    _pid=$!
    _w=0
    while [ "$_w" -lt 25 ]; do
        _r=$(query_ms "$PROXY_LISTEN" "$_port" "$TEST_DOMAIN" A)
        case "$_r" in ''|FAIL) _w=$((_w + 1)); sleep_short ;; *) break ;; esac
    done
    if [ "$_verbose" = "verbose" ]; then
        ( _i=0; while [ "$_i" -lt "$_n" ]; do query_ms "$PROXY_LISTEN" "$_port" "$TEST_DOMAIN" A; _i=$((_i + 1)); done ) \
            | stats_of | sed 's/^/  DNS   : /'
    else
        _i=0
        while [ "$_i" -lt "$_n" ]; do
            _r=$(query_ms "$PROXY_LISTEN" "$_port" "$TEST_DOMAIN" A)
            case "$_r" in ''|FAIL|NO-DIG) : ;; *) PROBE_SUM=$((PROBE_SUM + _r)); PROBE_N=$((PROBE_N + 1)) ;; esac
            _i=$((_i + 1))
        done
    fi
    kill "$_pid" >/dev/null 2>&1
    wait "$_pid" 2>/dev/null
    return 0
}

# $1 = upstream, $2 = queries, $3 = human readable label, $4 = extra flags
probe_upstream() {
    _url="$1"; _n="${2:-$DEFAULT_TEST_COUNT}"; _label="${3:-$_url}"; _extra="${4:-}"
    printf '%s\n' "${C_BOLD}Encrypted DNS: $_label${C_RESET}"
    probe_upstream_core "$_url" "$_n" "$PROBE_PORT" verbose "$_extra"
}

test_provider_all() {
    _key="$1"
    provider_parse_key "$_key" || { err "Unknown provider: $_key"; return 1; }
    _sel_prov="$P_KEY"; _sel_prof="$P_PROFILE"
    printf '\n%s\n' "${C_BOLD}Testing provider: $(provider_label)${C_RESET}"
    for _m in $ALL_MODES; do
        mode_available "$_m" || continue
        case "$_m" in
            plain)
                _ip=$(csv "$P_V4" | awk '{print $1}')
                [ -n "$_ip" ] && probe_plain_ip "$_ip" 5
                if [ "$HAS_IPV6" = "yes" ]; then
                    _ip=$(csv "$P_V6" | awk '{print $1}')
                    [ -n "$_ip" ] && probe_plain_ip "$_ip" 5
                fi
                ;;
            dot)      probe_upstream "tls://$P_DOT" 5 "DoT tls://$P_DOT" ;;
            doh)      probe_upstream "https://$P_DOH" 5 "DoH https://$P_DOH (HTTP/3 preferred, HTTP/2 fallback)" "--http3" ;;
            doh3)     probe_upstream "h3://$P_DOH" 5 "DoH3 h3://$P_DOH (HTTP/3 only, no fallback)" ;;
            doq)      probe_upstream "quic://$P_DOQ" 5 "DoQ quic://$P_DOQ" ;;
            dnscrypt) probe_upstream "$P_SDNS" 5 "DNSCrypt (sdns://...)" ;;
        esac
    done
    provider_load "$_sel_prov" "$_sel_prof" >/dev/null 2>&1
}

current_nameservers() {
    [ -r "$RESOLV_CONF" ] || return 0
    awk '/^[[:space:]]*nameserver[[:space:]]/{print $2}' "$RESOLV_CONF" 2>/dev/null | head -n 3
}

test_current() {
    printf '\n%s\n' "${C_BOLD}Currently configured DNS${C_RESET}"
    _m=$(state_get MODE); _p=$(state_get PROVIDER_NAME)
    if [ -n "$_m" ]; then
        printf '  managed by %s: %s / %s\n' "$APP" "${_p:-?}" "${_m:-?}"
    else
        printf '  not managed by %s\n' "$APP"
    fi
    if [ "$RESOLVER" = "resolved" ] && have resolvectl; then
        resolvectl status 2>/dev/null | sed -n '/^Global$/,/^Link /p' \
            | grep -E 'DNS Servers|DNS Domain|DNS-over-TLS|DNSSEC' | sed 's/^[[:space:]]*/  /' | head -n 6
        resolvectl dns 2>/dev/null | sed 's/^/  /' | head -n 6
    fi
    printf '  %s:\n' "$RESOLV_CONF"
    grep -v '^#' "$RESOLV_CONF" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^/    /'

    for _s in $(current_nameservers); do
        case "$_s" in
            127.0.0.1|::1)
                printf '\n%s\n' "${C_BOLD}Local proxy $_s${C_RESET}"
                ( _i=0; while [ "$_i" -lt "$DEFAULT_TEST_COUNT" ]; do query_ms "$_s" 53 "$TEST_DOMAIN" A; _i=$((_i + 1)); done ) \
                    | stats_of | sed 's/^/  DNS   : /'
                ;;
            127.0.0.53)
                printf '\n%s\n' "${C_BOLD}systemd-resolved stub $_s${C_RESET}"
                ( _i=0; while [ "$_i" -lt "$DEFAULT_TEST_COUNT" ]; do query_ms "$_s" 53 "$TEST_DOMAIN" A; _i=$((_i + 1)); done ) \
                    | stats_of | sed 's/^/  DNS   : /'
                ;;
            *)
                probe_plain_ip "$_s" 5
                ;;
        esac
    done
}

rank_providers() {
    _mode="$1"
    case "$_mode" in
        plain|dot|doh|doh3|doq) : ;;
        *) err "Unknown transport for ranking: '$_mode' (plain dot doh doh3 doq)"; return 1 ;;
    esac
    ensure_dig || { err "Latency ranking needs dig."; return 1; }
    printf '\n%s\n' "${C_BOLD}Latency ranking, 3 probes per provider ($(mode_label "$_mode"))${C_RESET}"
    ensure_dirs
    _tmp="$STATE_DIR/rank.$$"
    : > "$_tmp"
    for _k in $(provider_keys); do
        _prof="${PROFILE_FILTER:-$(profile_keys "$_k" | head -n1)}"
        provider_load "$_k" "$_prof" || continue
        _sum=""; _n=0
        case "$_mode" in
            plain)
                _ip=$(csv "$P_V4" | awk '{print $1}')
                if [ -z "$_ip" ] && [ "$HAS_IPV6" = "yes" ]; then
                    _ip=$(csv "$P_V6" | awk '{print $1}')
                fi
                [ -n "$_ip" ] || continue
                _sum=0
                _i=0
                while [ "$_i" -lt 3 ]; do
                    _r=$(query_ms "$_ip" 53 "$TEST_DOMAIN" A)
                    case "$_r" in ''|FAIL|NO-DIG) : ;; *) _sum=$((_sum + _r)); _n=$((_n + 1)) ;; esac
                    _i=$((_i + 1))
                done
                ;;
            *)
                _url=""; _extra=""
                case "$_mode" in
                    dot)  [ -n "$P_DOT" ] && _url="tls://$P_DOT" ;;
                    doh)  [ -n "$P_DOH" ] && _url="https://$P_DOH" && _extra="--http3" ;;
                    doh3) [ -n "$P_DOH" ] && _url="h3://$P_DOH" ;;
                    doq)  [ -n "$P_DOQ" ] && _url="quic://$P_DOQ" ;;
                esac
                [ -n "$_url" ] || continue
                if probe_upstream_core "$_url" 3 "$PROBE_PORT2" quiet "$_extra"; then
                    _sum="$PROBE_SUM"; _n="$PROBE_N"
                fi
                ;;
        esac
        if [ -n "$_sum" ] && [ "$_n" -gt 0 ] 2>/dev/null; then
            printf '%s %s\n' "$((_sum / _n))" "$(provider_label)" >> "$_tmp"
        else
            printf '99999 %s (~unreachable)\n' "$(provider_label)" >> "$_tmp"
        fi
    done
    sort -n "$_tmp" | awk '{ if ($1>=99999) tag="  unreachable"; else tag=""; printf("  %6s ms  %s%s\n", ($1>=99999 ? "-" : $1), substr($0, index($0," ")+1), tag) }'
    rm -f "$_tmp"
}

# =============================================================================
#  Status / restore / listing
# =============================================================================
dnsproxy_path_display() {
    if [ -n "${DNSPROXY_OVERRIDE:-}" ] && [ -x "$DNSPROXY_OVERRIDE" ]; then
        printf '%s' "$DNSPROXY_OVERRIDE"
    elif [ -x "$DNSPROXY_BIN" ]; then
        printf '%s' "$DNSPROXY_BIN"
    elif have dnsproxy; then
        command -v dnsproxy
    else
        printf '(not installed)'
    fi
}

show_status() {
    printf '\n%s\n' "${C_BOLD}${APP} ${APP_VERSION} - status${C_RESET}"
    printf '  Distribution : %s\n' "$OS_PRETTY"
    printf '  Family       : %s-based (detected through %s)\n' "$FAMILY" "$PKG_MGR"
    [ -n "$OS_LIKE" ] && printf '  ID_LIKE      : %s\n' "$OS_LIKE"
    printf '  Init system  : %s\n' "$INIT_SYS"
    printf '  Resolver     : %s\n' "$RESOLVER"
    if [ "$HAS_IPV6" = "yes" ]; then
        printf '  IPv6         : yes\n'
    else
        printf '  IPv6         : no (%s)\n' "$IPV6_REASON"
    fi
    printf '  dnsproxy     : %s\n' "$(dnsproxy_path_display)"
    _m=$(state_get MODE)
    _p=$(state_get PROVIDER_NAME)
    _u=$(state_get UPDATED)
    if [ -n "$_m" ] || [ -n "$_p" ]; then
        printf '  Applied      : %s / %s (%s)\n' "${_p:-?}" "${_m:-?}" "${_u:-?}"
    else
        printf '  Applied      : (nothing, defaults in use)\n'
    fi
    printf '  %s:\n' "$RESOLV_CONF"
    grep -v '^#' "$RESOLV_CONF" 2>/dev/null | grep -v '^[[:space:]]*$' | sed 's/^/      /'
    if [ -f "$RESOLVED_DROPIN" ]; then
        printf '  %s:\n' "$RESOLVED_DROPIN"
        sed 's/^/      /' "$RESOLVED_DROPIN"
    fi
    if [ "$INIT_SYS" = "systemd" ] && [ -f "$SYSTEMD_UNIT" ]; then
        printf '  Service      : %s (%s)\n' "$APP" "$(systemctl is-active "$APP" 2>/dev/null)"
        sed -n 's/^ExecStart=/      ExecStart: /p' "$SYSTEMD_UNIT"
    elif [ -f "$OPENRC_INIT" ]; then
        printf '  Service      : %s (openrc)\n' "$APP"
    fi
    printf '\n'
}

restore_all() {
    msg "Restoring the previous DNS configuration ..."
    svc_remove_unit
    resolved_clear
    nm_restore_management
    if [ -e "$RESOLV_BACKUP" ]; then
        rm -f "$RESOLV_CONF"
        cp -a "$RESOLV_BACKUP" "$RESOLV_CONF"
        ok "Restored $RESOLV_CONF from $RESOLV_BACKUP"
    elif [ -e "$BACKUP_DIR/resolv.conf.pre-resolved" ]; then
        rm -f "$RESOLV_CONF"
        cp -a "$BACKUP_DIR/resolv.conf.pre-resolved" "$RESOLV_CONF"
        ok "Restored $RESOLV_CONF from the pre-resolved backup"
    else
        msg "No $RESOLV_CONF backup found - keeping the current file."
    fi
    rm -f "$STATE_FILE"
    ok "System DNS defaults restored."
}

list_all() {
    printf '\nTransports (interactive menu):\n'
    for _m in $MENU_MODES; do
        printf '  %-9s %s\n' "$_m" "$(mode_label "$_m")"
    done
    printf 'Diagnostic-only transports (CLI -m):\n'
    printf '  %-9s %s\n' "doh3" "$(mode_label doh3)"
    printf '\nProviders (choose provider -> filtering -> transport):\n'
    for _k in $(provider_keys); do
        printf '  %s\n' "$(provider_title "$_k")"
        for _p in $(profile_keys "$_k"); do
            provider_load "$_k" "$_p" || continue
            _caps=""
            for _m in $MENU_MODES; do
                mode_available "$_m" && _caps="$_caps $_m"
            done
            printf '    %-12s %-38s ipv4=%-38s ipv6=%-40s supports:%s\n' \
                "[$_p]" "$(profile_label "$_p")" "${P_V4:--}" "${P_V6:--}" "$_caps"
        done
    done
}

# =============================================================================
#  Interactive menus
# =============================================================================
choose_provider() {
    printf '\n%s\n' "${C_BOLD}Choose a DNS provider${C_RESET}"
    _i=0
    _keys=""
    for _k in $(provider_keys); do
        _i=$((_i + 1))
        _keys="$_keys $_k"
        printf '  %2d) %s\n' "$_i" "$(provider_title "$_k")"
    done
    printf '   0) Back\n'
    printf 'Select provider [1-%d]: ' "$_i"
    _sel=""
    read -r _sel || return 1
    [ "$_sel" = "0" ] && return 1
    case "$_sel" in ''|*[!0-9]*) warn "Invalid selection."; return 1 ;; esac
    _i=0
    for _k in $_keys; do
        _i=$((_i + 1))
        if [ "$_i" = "$_sel" ]; then
            provider_load "$_k" base || return 1
            ok "Provider: $P_NAME"
            return 0
        fi
    done
    warn "Invalid selection."
    return 1
}

# Second step: pick the filtering mode of the already chosen provider.  When a
# provider has a single profile the step is skipped silently.
choose_profile() {
    set --
    for _p in $(profile_keys "$P_KEY"); do
        set -- "$@" "$_p"
    done
    [ $# -gt 0 ] || { err "Provider '$P_KEY' has no profiles."; return 1; }
    if [ $# -eq 1 ]; then
        provider_load "$P_KEY" "$1" || return 1
        return 0
    fi
    printf '\n%s\n' "${C_BOLD}Choose filtering for $P_NAME${C_RESET}"
    _i=0
    for _p in "$@"; do
        _i=$((_i + 1))
        printf '  %2d) %s\n' "$_i" "$(profile_label_at "$P_KEY" "$_p")"
    done
    printf '   0) Back\n'
    printf 'Select filtering [1-%d]: ' "$_i"
    _sel=""
    read -r _sel || return 1
    [ "$_sel" = "0" ] && return 1
    case "$_sel" in ''|*[!0-9]*) warn "Invalid selection."; return 1 ;; esac
    _i=0
    for _p in "$@"; do
        _i=$((_i + 1))
        if [ "$_i" = "$_sel" ]; then
            provider_load "$P_KEY" "$_p" || return 1
            ok "Filtering: $(profile_label "$P_PROFILE")"
            return 0
        fi
    done
    warn "Invalid selection."
    return 1
}

choose_mode() {
    set --
    for _m in $MENU_MODES; do
        mode_available "$_m" && set -- "$@" "$_m"
    done
    if [ $# -eq 0 ]; then
        err "Provider '$P_NAME' publishes no usable transport."
        return 1
    fi
    printf '\n%s\n' "${C_BOLD}Choose a DNS transport for $P_NAME${C_RESET}"
    _i=0
    for _m in "$@"; do
        _i=$((_i + 1))
        printf '  %2d) %s\n' "$_i" "$(mode_label "$_m")"
    done
    printf '   0) Back\n'
    printf 'Select transport [1-%d]: ' "$_i"
    _sel=""
    read -r _sel || return 1
    [ "$_sel" = "0" ] && return 1
    case "$_sel" in ''|*[!0-9]*) warn "Invalid selection."; return 1 ;; esac
    _i=0
    for _m in "$@"; do
        _i=$((_i + 1))
        if [ "$_i" = "$_sel" ]; then
            MODE="$_m"
            ok "Transport: $(mode_label "$MODE")"
            return 0
        fi
    done
    warn "Invalid selection."
    return 1
}

change_dns_flow() {
    choose_provider || return 0
    choose_profile || return 0
    choose_mode || return 0
    if ! confirm "Apply $(mode_label "$MODE") using $(provider_label)?"; then
        warn "Cancelled."
        return 0
    fi
    apply_mode
}

test_menu() {
    while :; do
        printf '\n%s\n' "${C_BOLD}DNS test${C_RESET}"
        printf '  1) Test the currently configured DNS\n'
        printf '  2) Test one provider (all its transports)\n'
        printf '  3) Latency ranking of all providers (plain DNS)\n'
        printf '  4) Latency ranking of all providers (DoH)\n'
        printf '  5) Latency ranking of all providers (DoQ)\n'
        printf '  0) Back\n'
        printf 'Choose [0-5]: '
        _c=""
        read -r _c || return 0
        case "$_c" in
            1) test_current ;;
            2) if choose_provider && choose_profile; then test_provider_all "$P_KEY:$P_PROFILE"; fi ;;
            3) rank_providers plain ;;
            4) rank_providers doh ;;
            5) rank_providers doq ;;
            0) return 0 ;;
            *) warn "Invalid choice." ;;
        esac
    done
}

main_menu() {
    while :; do
        printf '\n'
        printf '%s\n' "${C_BOLD}${APP} ${APP_VERSION}${C_RESET}"
        printf '  Distribution : %s\n' "$OS_PRETTY"
        printf '  Family       : %s-based (via %s)\n' "$FAMILY" "$PKG_MGR"
        printf '  Init/Resolver: %s / %s\n' "$INIT_SYS" "$RESOLVER"
        if [ "$HAS_IPV6" = "yes" ]; then
            printf '  IPv6         : yes\n'
        else
            printf '  IPv6         : no (%s)\n' "$IPV6_REASON"
        fi
        _m=$(state_get MODE)
        _p=$(state_get PROVIDER_NAME)
        if [ -n "$_m" ]; then
            printf '  Applied      : %s / %s\n' "${_p:-?}" "${_m:-?}"
        else
            printf '  Applied      : (defaults)\n'
        fi
        printf '\n  1) Change DNS\n'
        printf '  2) Test DNS (latency / stability)\n'
        printf '  3) Show current status\n'
        printf '  4) Restore system defaults\n'
        printf '  0) Exit\n'
        printf 'Choose [0-4]: '
        _c=""
        read -r _c || return 0
        case "$_c" in
            1) change_dns_flow ;;
            2) test_menu ;;
            3) show_status ;;
            4) confirm "Restore system DNS defaults?" && restore_all ;;
            0) return 0 ;;
            *) warn "Invalid choice." ;;
        esac
    done
}

# =============================================================================
#  CLI
# =============================================================================
self_test() {
    _fail=0
    _pairs=$(printf '%s\n' "$PROVIDER_DB" | awk -F'|' 'NF>1 && $1!="" { print $1"|"$3 }')
    _dups=$(printf '%s\n' "$_pairs" | sort | uniq -d)
    if [ -n "$_dups" ]; then
        err "Duplicate provider profiles:"
        printf '%s\n' "$_dups" >&2
        _fail=1
    fi
    for _k in $(provider_keys); do
        _count=0
        for _p in $(profile_keys "$_k"); do
            _count=$((_count + 1))
            provider_load "$_k" "$_p" || {
                err "Cannot load '$_k:$_p'."
                _fail=1
                continue
            }
            _has_mode=0
            for _m in $ALL_MODES; do
                mode_available "$_m" && _has_mode=1
            done
            [ "$_has_mode" = "1" ] || {
                err "Provider '$_k:$_p' has no usable transport."
                _fail=1
            }
            for _ip in $(csv "$P_V4"); do
                if ! printf '%s\n' "$_ip" | awk -F. '
                    NF==4 { for (i=1;i<=4;i++) { if ($i !~ /^[0-9]+$/ || $i+0>255) exit 1 } exit 0 }
                    { exit 1 }'; then
                    err "Invalid IPv4 '$_ip' in '$_k:$_p'."
                    _fail=1
                fi
            done
            for _ip in $(csv "$P_V6"); do
                case "$_ip" in
                    *:*)
                        case "$_ip" in
                            *[!0-9a-fA-F:]*) err "Invalid IPv6 '$_ip' in '$_k:$_p'."; _fail=1 ;;
                        esac
                        ;;
                    *) err "Invalid IPv6 '$_ip' in '$_k:$_p'."; _fail=1 ;;
                esac
            done
            case "$P_DOT" in *://*|*" "*) err "Invalid DoT host in '$_k:$_p'."; _fail=1 ;; esac
            case "$P_DOH" in *://*|*" "*) err "Invalid DoH endpoint in '$_k:$_p'."; _fail=1 ;; esac
            case "$P_DOQ" in *://*|*" "*) err "Invalid DoQ host in '$_k:$_p'."; _fail=1 ;; esac
            case "$P_SDNS" in
                "") : ;;
                sdns://*) : ;;
                *) err "Invalid DNSCrypt stamp in '$_k:$_p'."; _fail=1 ;;
            esac
        done
        [ "$_count" -gt 0 ] || { err "Provider '$_k' has no profiles."; _fail=1; }
    done
    if provider_has mullvad; then
        err "Provider 'mullvad' should have been removed."
        _fail=1
    fi
    if provider_load dnsforge base >/dev/null 2>&1; then
        if [ "$P_PROFILE" != "ads" ]; then
            err "dnsforge base fallback selected '$P_PROFILE' instead of 'ads'."
            _fail=1
        fi
    else
        err "dnsforge is not selectable."
        _fail=1
    fi
    if [ "$_fail" -eq 0 ]; then
        ok "Provider database looks consistent."
        return 0
    fi
    err "Provider database self-test failed."
    return 1
}

usage() {
    cat <<EOF
$APP $APP_VERSION - switch and test the system DNS resolver

Usage: $0 [options]

Options:
  -m, --mode MODE       transport: plain | dot | doh | doq | dnscrypt
                        (doh = HTTP/3 preferred with automatic HTTP/2 fallback;
                         doh3 = HTTP/3 only, diagnostic, not offered in menus)
  -p, --provider KEY    provider key, optionally with a profile:
                          -p cloudflare            (no filtering, "base")
                          -p cloudflare:family     (family protection)
                          -p adguard:unfiltered    (no blocking at all)
                        Profiles are shown by --list.
  -y, --yes             assume "yes", never ask for confirmation
      --apply           apply -m/-p without showing the menu (default for CLI)
      --allow-unverified
                        install dnsproxy without verifying its sha256
      --list            list transports and providers
      --status          show the current configuration
      --restore         restore the system defaults
      --test [KEY]      run a latency/stability test (optionally for a provider)
      --rank MODE       latency ranking of all providers for MODE
      --self-test       validate the built-in provider database (no changes)
  -h, --help            this help

Encrypted transports (dot, doh, doh3, doq, dnscrypt) require systemd or
OpenRC. Plain DNS works everywhere.

Examples:
  $0                                                   interactive menu
  $0 --list
  $0 -m doq -p adguard --apply                         set AdGuard DoQ
  $0 -m doh -p adguard:family --apply                  AdGuard family protection via DoH
  $0 -m dot -p cloudflare --apply                      set Cloudflare DoT
  $0 -m plain -p quad9 -y --apply                      plain Quad9, no prompts
  $0 --test adguard
  $0 --rank doh
  $0 --status
  $0 --restore

Environment:
  DNSPROXY_VERSION      dnsproxy release tag to download (default: $DNSPROXY_VERSION)
  DNSPROXY_SHA256       expected sha256 of the dnsproxy archive (overrides pinned)
  DNSPROXY_OVERRIDE     path to an existing dnsproxy binary
  NO_COLOR              disable coloured output
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -m|--mode)
                [ $# -ge 2 ] || die "Option $1 needs an argument"
                MODE="$2"; shift 2 ;;
            -p|--provider)
                [ $# -ge 2 ] || die "Option $1 needs an argument"
                P_KEY="$2"
                case "$2" in
                    *:*) PROV_KEY="${2%%:*}"; PROV_PROFILE="${2#*:}" ;;
                    *)
                        PROV_KEY="$2"; PROV_PROFILE="base"
                        _b="${2%%-*}"
                        if [ "$_b" != "$2" ] && provider_has "$_b"; then
                            _c="${2#*-}"
                            if profile_has "$_b" "$_c"; then
                                PROV_KEY="$_b"; PROV_PROFILE="$_c"
                            fi
                        fi
                        ;;
                esac
                shift 2
                ;;
            -y|--yes)      ASSUME_YES="yes"; shift ;;
            --apply)       shift ;;
            --allow-unverified) ALLOW_UNVERIFIED="yes"; shift ;;
            --self-test)   DO_SELFTEST=1; shift ;;
            --list)        DO_LIST=1; shift ;;
            --status)      DO_STATUS=1; shift ;;
            --restore)     DO_RESTORE=1; shift ;;
            --test)
                DO_TEST=1; shift
                if [ $# -gt 0 ]; then
                    case "$1" in
                        -*) : ;;
                        *) TEST_KEY="$1"; shift ;;
                    esac
                fi
                ;;
            --rank)
                [ $# -ge 2 ] || die "Option $1 needs an argument"
                DO_RANK="$2"; shift 2 ;;
            -h|--help)     usage; exit 0 ;;
            *) err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

main() {
    trap rollback_on_exit EXIT
    parse_args "$@"
    detect_all

    # Read-only or unprivileged actions.
    if [ "$DO_SELFTEST" = "1" ]; then self_test; exit $?; fi
    if [ "$DO_LIST" = "1" ]; then list_all; exit 0; fi
    if [ "$DO_STATUS" = "1" ]; then show_status; exit 0; fi
    if [ -n "$DO_RANK" ]; then
        rank_providers "$DO_RANK" || exit 1
        exit 0
    fi
    if [ "$DO_TEST" = "1" ]; then
        _rc=0
        if [ -n "$TEST_KEY" ]; then
            test_provider_all "$TEST_KEY" || _rc=1
        else
            test_current
        fi
        exit "$_rc"
    fi

    # Actions that modify the system need root.
    if [ "$DO_RESTORE" = "1" ]; then
        require_root "$@"
        restore_all
        exit 0
    fi
    if [ -n "$MODE" ] || [ -n "$P_KEY" ]; then
        [ -n "$MODE" ] || die "Please pass both --mode and --provider."
        [ -n "$P_KEY" ] || die "Please pass both --mode and --provider."
        validate_selection
        require_root "$@"
        apply_mode || exit 1
        exit 0
    fi

    if [ ! -t 0 ]; then
        die "The interactive menu needs a terminal. Use --help to see the options."
    fi
    require_root "$@"
    main_menu
}

if [ "${DNS_SWITCHER_NO_MAIN:-}" != "1" ]; then
    main "$@"
fi
