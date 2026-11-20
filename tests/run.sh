#!/bin/sh
# ---------------------------------------------------------------------------
#  tests/run.sh -- POSIX test harness for dns-switcher.sh
#
#  Runs without root, without systemd and without network access:
#    * the script is sourced with DNS_SWITCHER_NO_MAIN=1, so only its
#      functions are loaded;
#    * every path the script writes to is redirected into a temporary
#      directory;
#    * external tools it calls (dig, ss, systemctl) are replaced by small
#      fakes that are first in PATH.
#
#  Usage: sh tests/run.sh
# ---------------------------------------------------------------------------

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
APP_SH="$ROOT/dns-switcher.sh"
if [ ! -f "$APP_SH" ]; then
    printf 'cannot find %s\n' "$APP_SH" >&2
    exit 1
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/dns-switcher-test.XXXXXX") || exit 1
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf 'ok   - %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL - %s\n' "$1"; }

# check <description> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1"
        printf '       expected: [%s]\n' "$2"
        printf '       actual  : [%s]\n' "$3"
    fi
}

# check_contains <description> <needle> <haystack>
check_contains() {
    case "$3" in
        *"$2"*) pass "$1" ;;
        *) fail "$1"; printf '       missing: [%s]\n' "$2" ;;
    esac
}

# check_rc <description> <expected code> <actual code>
check_rc() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1"
        printf '       expected code: %s, actual: %s\n' "$2" "$3"
    fi
}

# ---------------------------------------------------------------------------
#  Fake external tools
# ---------------------------------------------------------------------------
BIN="$TMP/bin"
mkdir -p "$BIN"

cat > "$BIN/dig" <<'EOS'
#!/bin/sh
case " $* " in
    *" +short "*) printf '1.2.3.4\n'; exit 0 ;;
esac
if [ -n "${DIG_FIXTURE:-}" ] && [ -f "$DIG_FIXTURE" ]; then
    cat "$DIG_FIXTURE"
    exit 0
fi
printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
printf ';; Query time: 12 msec\n'
printf ';; SERVER: 127.0.0.1#53(127.0.0.1)\n'
EOS

cat > "$BIN/ss" <<'EOS'
#!/bin/sh
if [ -n "${SS_FIXTURE:-}" ] && [ -f "$SS_FIXTURE" ]; then
    cat "$SS_FIXTURE"
fi
exit 0
EOS

cat > "$BIN/systemctl" <<'EOS'
#!/bin/sh
case "$1" in
    is-active) [ "${SYSTEMCTL_ACTIVE:-1}" = "0" ] && exit 0 || exit 1 ;;
    *) exit 0 ;;
esac
EOS

chmod +x "$BIN/dig" "$BIN/ss" "$BIN/systemctl" 2>/dev/null
PATH="$BIN:$PATH"
export PATH

# ---------------------------------------------------------------------------
#  Load the script under test
# ---------------------------------------------------------------------------
DNS_SWITCHER_NO_MAIN=1
export DNS_SWITCHER_NO_MAIN
. "$APP_SH"

# Deterministic state location: never read the real /etc of the test host.
state_file_path() { printf '%s/state' "$STATE_DIR"; }
# The CI host has no /run/systemd/resolve/stub-resolv.conf; make that explicit.
resolved_stub_available() { return 1; }

reset_env() {
    STATE_DIR="$TMP/etc/dns-switcher"
    STATE_FILE="$STATE_DIR/state"
    BACKUP_DIR="$STATE_DIR/backup"
    RESOLV_CONF="$TMP/etc/resolv.conf"
    RESOLV_BACKUP="$BACKUP_DIR/resolv.conf.orig"
    RESOLVED_DROPIN_DIR="$TMP/etc/systemd/resolved.conf.d"
    RESOLVED_DROPIN="$RESOLVED_DROPIN_DIR/99-dns-switcher.conf"
    SYSTEMD_UNIT="$TMP/etc/systemd/system/dns-switcher.service"
    OPENRC_INIT="$TMP/etc/init.d/dns-switcher"
    NM_CONF="$TMP/etc/NetworkManager/conf.d/99-dns-switcher.conf"
    DNSPROXY_BIN="$TMP/usr/local/bin/dnsproxy"
    DRY_RUN="no"
    FORCE="no"
    PURGE="no"
    FILE_CHANGED="no"
    SNAPSHOT_ACTIVE="no"
    ASSUME_YES="yes"
    APPLIED_VIA=""
    BACKEND="file"
    BACKEND_REQ="auto"
    VERIFY_TIMEOUT="2"
    HAS_IPV6="no"
    INIT_SYS="none"
    RESOLVER="file"
    MODE=""
    P_KEY=""
    P_PROFILE=""
    P_NAME=""
    P_V4=""
    P_V6=""
    P_DOT=""
    P_DOH=""
    P_DOQ=""
    P_SDNS=""
    rm -rf "$TMP/etc"
    mkdir -p "$TMP/etc"
}

# ---------------------------------------------------------------------------
#  Provider database
# ---------------------------------------------------------------------------
reset_env

if self_test >"$TMP/selftest.log" 2>&1; then
    pass "provider database self-test"
else
    fail "provider database self-test"
    sed 's/^/       /' "$TMP/selftest.log"
fi

check "provider count" "9" "$(provider_keys | wc -l | tr -d ' ')"
check "provider title" "Cloudflare" "$(provider_title cloudflare)"
check "profile list" "base security family" "$(profile_keys cloudflare | tr '\n' ' ' | sed 's/ $//')"

provider_load dnsforge base
check "dnsforge base falls back to ads" "ads" "$P_PROFILE"

provider_parse_key adguard-family
check "legacy key -> provider" "adguard" "$P_KEY"
check "legacy key -> profile" "family" "$P_PROFILE"

provider_parse_key quad9:unfiltered
check "explicit profile key" "unfiltered" "$P_PROFILE"

provider_load cloudflare base
check "provider label (base)" "Cloudflare" "$(provider_label)"
provider_load cloudflare family
check "provider label (profile)" "Cloudflare [family]" "$(provider_label)"

( provider_parse_key no-such-provider ) >/dev/null 2>&1
check_rc "unknown provider is rejected" 1 "$?"

check "csv helper" "1.1.1.1 1.0.0.1" "$(csv '1.1.1.1,1.0.0.1')"
check "legacy profile mapping" "unfiltered" "$(legacy_key_profile quad9-unsecured)"

# ---------------------------------------------------------------------------
#  Transport selection / bootstrap
# ---------------------------------------------------------------------------
reset_env
provider_load quad9 base
HAS_IPV6="yes"
check "bootstrap with IPv6" \
    " -b 9.9.9.9 -b 149.112.112.112 -b 2620:fe::fe -b 2620:fe::9" \
    "$(bootstrap_args)"

HAS_IPV6="no"
check "bootstrap without IPv6" \
    " -b 9.9.9.9 -b 149.112.112.112" \
    "$(bootstrap_args)"

provider_load cloudflare base
if mode_available plain && mode_available dot && mode_available doh; then
    pass "cloudflare offers plain/dot/doh"
else
    fail "cloudflare offers plain/dot/doh"
fi
if mode_available doq || mode_available dnscrypt; then
    fail "cloudflare has no DoQ/DNSCrypt"
else
    pass "cloudflare has no DoQ/DNSCrypt"
fi

# ---------------------------------------------------------------------------
#  Rendered files
# ---------------------------------------------------------------------------
reset_env
_expected=$(printf '# Generated by %s\nnameserver 1.1.1.1\nnameserver 1.0.0.1\noptions timeout:2 attempts:2\n' "$APP")
check "resolv.conf content" "$_expected" "$(file_resolv_content 1.1.1.1 1.0.0.1)"

RESOLV_CONF="$TMP/etc/resolv.conf"
printf 'nameserver 127.0.0.53\n' > "$RESOLV_CONF"
file_write_resolv 1.1.1.1 1.0.0.1
check "resolv.conf written" "$_expected" "$(cat "$RESOLV_CONF")"
check "resolv.conf first write changed" "yes" "$FILE_CHANGED"
file_write_resolv 1.1.1.1 1.0.0.1
check "resolv.conf rewrite is a no-op" "no" "$FILE_CHANGED"

# dry run never touches the target
reset_env
DRY_RUN="yes"
RESOLV_CONF="$TMP/etc/dry-resolv.conf"
_out=$(file_write_resolv 9.9.9.9 2>&1)
if [ -e "$RESOLV_CONF" ]; then
    fail "dry-run does not create resolv.conf"
else
    pass "dry-run does not create resolv.conf"
fi
check_contains "dry-run prints the plan" "would write" "$_out"

# systemd unit rendering and idempotency
reset_env
DNSPROXY_RESOLVED="$TMP/usr/local/bin/dnsproxy"
mkdir -p "$(dirname "$SYSTEMD_UNIT")"
unit_content "-l 127.0.0.1 -p 53 -u https://example.test/dns-query" > "$TMP/unit.txt"
check "unit mentions nss-lookup once" "1" "$(grep -c 'nss-lookup.target' "$TMP/unit.txt")"
check "unit has no DynamicUser" "0" "$(grep -c 'DynamicUser' "$TMP/unit.txt")"
check_contains "unit is hardened" "ProtectSystem=strict" "$(cat "$TMP/unit.txt")"
check_contains "unit keeps only net-bind" "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" "$(cat "$TMP/unit.txt")"
check_contains "unit restarts always" "Restart=always" "$(cat "$TMP/unit.txt")"

svc_write_systemd_unit "-l 127.0.0.1 -p 53 -u https://example.test/dns-query"
check "unit written" "yes" "$FILE_CHANGED"
svc_write_systemd_unit "-l 127.0.0.1 -p 53 -u https://example.test/dns-query"
check "unit rewrite is a no-op" "no" "$FILE_CHANGED"

# an identical unit on a running service must not be restarted
SYSTEMCTL_ACTIVE=0
export SYSTEMCTL_ACTIVE
if proxy_already_running "-l 127.0.0.1 -p 53 -u https://example.test/dns-query"; then
    pass "identical proxy configuration is detected as running"
else
    fail "identical proxy configuration is detected as running"
fi
if proxy_already_running "-l 127.0.0.1 -p 53 -u https://other.test/dns-query"; then
    fail "different upstream is not treated as running"
else
    pass "different upstream is not treated as running"
fi
unset SYSTEMCTL_ACTIVE

# dry-run start plan
reset_env
DRY_RUN="yes"
INIT_SYS="systemd"
DNSPROXY_RESOLVED="$TMP/usr/local/bin/dnsproxy"
mkdir -p "$(dirname "$SYSTEMD_UNIT")"
_out=$(svc_install_and_start "-l 127.0.0.1 -p 53" 2>&1)
check_contains "dry-run plans the restart" "would enable and restart" "$_out"
check "dry-run did not start the unit" "no" "$([ -f "$SYSTEMD_UNIT" ] && printf yes || printf no)"

# ---------------------------------------------------------------------------
#  Snapshot / rollback and restore
# ---------------------------------------------------------------------------
reset_env
RESOLV_CONF="$TMP/etc/resolv.conf"
printf 'nameserver 8.8.8.8\n' > "$RESOLV_CONF"
snapshot_save
printf 'nameserver 127.0.0.1\n' > "$RESOLV_CONF"
SNAPSHOT_ACTIVE="yes"
snapshot_restore >/dev/null 2>&1
check "snapshot rollback restores resolv.conf" \
    "nameserver 8.8.8.8" "$(head -n 1 "$RESOLV_CONF")"
check "snapshot deactivated after rollback" "no" "$SNAPSHOT_ACTIVE"

reset_env
RESOLV_CONF="$TMP/etc/resolv.conf"
mkdir -p "$BACKUP_DIR"
printf 'nameserver 9.9.9.9\n' > "$RESOLV_BACKUP"
printf 'nameserver 127.0.0.1\n' > "$RESOLV_CONF"
restore_all >/dev/null 2>&1
check "restore_all brings the backup back" "nameserver 9.9.9.9" "$(head -n 1 "$RESOLV_CONF")"

# ---------------------------------------------------------------------------
#  Backend selection
# ---------------------------------------------------------------------------
reset_env
RESOLVER="file"
BACKEND_REQ="auto"
resolve_backend
check "auto backend without resolved" "file" "$BACKEND"

RESOLVER="resolved"
resolve_backend
check "auto backend downgrades without the stub listener" "file" "$BACKEND"

( BACKEND_REQ="resolved"; RESOLVER="file"; resolve_backend ) >/dev/null 2>&1
check_rc "forced resolved backend fails on a file host" 1 "$?"

resolved_stub_available() { return 0; }
_out=$(
    BACKEND_REQ="resolved"
    RESOLVER="resolved"
    resolve_backend
    printf '%s' "$BACKEND"
)
check "forced resolved backend with stub" "resolved" "$_out"
resolved_stub_available() { return 1; }

( BACKEND_REQ="bogus"; RESOLVER="file"; resolve_backend ) >/dev/null 2>&1
check_rc "unknown backend is rejected" 1 "$?"

# ---------------------------------------------------------------------------
#  Port and latency helpers
# ---------------------------------------------------------------------------
reset_env
SS_FIXTURE="$TMP/ss-busy"
printf 'UNCONN 0 0 127.0.0.1:53 0.0.0.0:* 0 0 users:(("dnsproxy",pid=1,fd=3))\n' > "$SS_FIXTURE"
export SS_FIXTURE
check_contains "port 53 holder is detected" "127.0.0.1:53" "$(port53_busy)"

SS_FIXTURE="$TMP/ss-free"
printf 'UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n' > "$SS_FIXTURE"
export SS_FIXTURE
( port53_busy ) >/dev/null 2>&1
check_rc "systemd-resolved stub on 127.0.0.53 is not a conflict" 1 "$?"
unset SS_FIXTURE

DIG_FIXTURE="$TMP/dig-stats"
{
    printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
    printf ';; Query time: 12 msec\n'
    printf ';; SERVER: 1.1.1.1#53(1.1.1.1)\n'
} > "$DIG_FIXTURE"
export DIG_FIXTURE
check "query_ms parses the latency" "12" "$(query_ms 1.1.1.1 53 example.com A)"
unset DIG_FIXTURE

check "stats_of aggregates results" \
    "ok=2 failures=1 min=10ms avg=15.0ms max=20ms jitter=10.0ms" \
    "$(printf '10\n20\nFAIL\n' | stats_of)"
check "dig_answer with the system resolver" "1.2.3.4" "$(dig_answer '' example.com A)"

# ---------------------------------------------------------------------------
#  CLI parsing and read-only commands
# ---------------------------------------------------------------------------
reset_env
parse_args -m doh -p quad9 --dry-run --backend file --verify-timeout 5 --force
check "parse -m" "doh" "$MODE"
check "parse -p" "quad9" "$P_KEY"
check "parse --dry-run" "yes" "$DRY_RUN"
check "parse --backend" "file" "$BACKEND_REQ"
check "parse --verify-timeout" "5" "$VERIFY_TIMEOUT"
check "parse --force" "yes" "$FORCE"

( parse_args --bogus ) >/dev/null 2>&1
check_rc "unknown option is rejected" 1 "$?"

( parse_args -m ) >/dev/null 2>&1
check_rc "missing option argument is rejected" 1 "$?"

reset_env
_out=$(json_status)
check_contains "json status has the app name" '"app":"dns-switcher"' "$_out"
check_contains "json status is an object" '{' "$_out"
case "$_out" in
    *'}') pass "json status ends with }" ;;
    *) fail "json status ends with }" ;;
esac

reset_env
SYSTEMD_UNIT="$TMP/absent.service"
OPENRC_INIT="$TMP/absent-init"
( health_check ) >/dev/null 2>&1
check_rc "health reports 'not managed' as 2" 2 "$?"

# ---------------------------------------------------------------------------
#  apply_plain dry run
# ---------------------------------------------------------------------------
reset_env
provider_load cloudflare base
BACKEND="file"
DRY_RUN="yes"
HAS_IPV6="no"
RESOLV_CONF="$TMP/etc/apply-dry.conf"
_out=$(apply_plain 2>&1)
check_contains "apply_plain dry run prints the nameservers" "1.1.1.1" "$_out"
check "apply_plain dry run writes nothing" "no" "$([ -e "$RESOLV_CONF" ] && printf yes || printf no)"
check "apply_plain records the mode" "plain" "$MODE_USED"

# ---------------------------------------------------------------------------
#  Summary
# ---------------------------------------------------------------------------
printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
