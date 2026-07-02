#!/usr/bin/env bash
# P6 manager-ops smoke: a detached container's logs are captured, and exec runs a
# command inside its namespaces. Needs root. Build first:
#   sudo DN7CRUN=.../dn7crun ./scripts/ops_smoke.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/dn7ctr-ops}"; ROOTFS="$WORK/bundle/rootfs"
log()  { printf '\033[36m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; "$BIN" delete opsc --force 2>/dev/null || true; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v nsenter >/dev/null || fail "need util-linux (nsenter)"
if [ -n "${DN7CRUN:-}" ] && [ -x "${DN7CRUN}" ]; then BIN="$DN7CRUN"; else
  ( cd "$HERE" && cargo build --quiet --bin dn7crun ); BIN="${CARGO_TARGET_DIR:-$HERE/target}/debug/dn7crun"; fi
[ -x "$BIN" ] || fail "dn7crun not found"

DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends busybox-static >/dev/null 2>&1 || true
rm -rf "$WORK"; mkdir -p "$ROOTFS"/{bin,proc,sys,dev,etc,tmp}
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
for a in sh sleep echo hostname cat; do ln -sf busybox "$ROOTFS/bin/$a"; done

cat > "$WORK/bundle/config.json" <<'JSON'
{ "ociVersion":"1.0.2","hostname":"opsbox",
  "process":{"user":{"uid":0,"gid":0},
    "args":["/bin/sh","-c","echo BOOTLOG_MARKER; exec sleep 100"],"env":["PATH=/bin"],"cwd":"/"},
  "root":{"path":"rootfs","readonly":false},
  "linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"},{"type":"network"}]} }
JSON

log "create + start (logs to console.log, stays alive)"
"$BIN" create opsc "$WORK/bundle"; "$BIN" start opsc; sleep 0.3

log "logs"
"$BIN" logs opsc | grep -q "BOOTLOG_MARKER" || fail "logs did not capture container stdout"
log "logs OK"

log "exec (enters the container's uts + pid namespaces)"
OUT="$("$BIN" exec opsc /bin/sh -c 'echo EXEC_MARKER; hostname; cat /proc/1/comm')"
echo "$OUT" | grep -q "EXEC_MARKER" || fail "exec produced no output"
echo "$OUT" | grep -q "opsbox"      || fail "exec not in container UTS ns (hostname)"
echo "$OUT" | grep -q "sleep"       || fail "exec not in container PID ns (pid 1 != sleep)"
log "exec OK (uts + pid ns confirmed)"

log "stats (cgroup v2 counters)"
"$BIN" stats opsc | grep -qE '"pids_current": [1-9]' || fail "stats shows no live pids"
"$BIN" stats opsc | grep -qE '"memory_current": [1-9]' || fail "stats shows no memory use"
log "stats OK"

"$BIN" delete opsc --force

# --- named volume persistence (via run-image) --------------------------------
log "named volume persistence"
rm -rf /var/lib/dn7-container/volumes/opsvol
"$BIN" run-image volw alpine -v opsvol:/data -- /bin/sh -c 'echo VOLMARK > /data/m' >/dev/null 2>&1
OUT="$("$BIN" run-image volr alpine -v opsvol:/data -- /bin/sh -c 'cat /data/m' 2>/dev/null || true)"
echo "$OUT" | grep -q "VOLMARK" || fail "named volume did not persist across containers"
rm -rf /var/lib/dn7-container/bundles/volw /var/lib/dn7-container/bundles/volr \
       /var/lib/dn7-container/volumes/opsvol
log "volume OK (persisted across containers)"

printf '\033[32m\nALL OPS SMOKE CHECKS PASSED (P6: logs + exec + stats + volumes)\033[0m\n'
