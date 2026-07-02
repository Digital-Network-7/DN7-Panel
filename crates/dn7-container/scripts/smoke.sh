#!/usr/bin/env bash
# P1 smoke test: build a minimal busybox bundle and exercise the runtime via
# dn7crun. Must run on Linux as root (it creates namespaces + cgroups). Verifies
# isolation (hostname, PID-1 view) and the create/start/state/kill/delete cycle.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/dn7ctr-smoke}"
BUNDLE="$WORK/bundle"
ROOTFS="$BUNDLE/rootfs"

log() { printf '\033[36m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root (namespaces/cgroups)"

# --- deps: a statically-linked busybox so the rootfs needs no shared libs -----
log "ensuring busybox-static"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends busybox-static >/dev/null 2>&1 || true
BB="$(command -v busybox || echo /bin/busybox)"
[ -x "$BB" ] || fail "busybox not found (install busybox-static)"
log "busybox: $BB"

# --- build the rootfs ---------------------------------------------------------
log "building rootfs at $ROOTFS"
rm -rf "$WORK"
mkdir -p "$ROOTFS"/{bin,proc,sys,dev,etc,tmp,root}
cp "$BB" "$ROOTFS/bin/busybox"
for a in sh ls cat echo id hostname ps sleep mount grep head true dd awk wc chmod; do
  ln -sf busybox "$ROOTFS/bin/$a"
done

# --- the in-container test program -------------------------------------------
cat > "$ROOTFS/bin/probe" <<'PROBE'
#!/bin/sh
echo "DN7_HOSTNAME=$(hostname)"
echo "DN7_UID=$(id -u)"
echo "DN7_PID1_COMM=$(cat /proc/1/comm)"
echo "DN7_PROC_PIDS=$(ls /proc | grep -E '^[0-9]+$' | tr '\n' ' ')"
echo "DN7_KCORE=$(dd if=/proc/kcore bs=1 count=1 2>/dev/null | wc -c)"
echo "DN7_SYSOPTS=$(awk '$2=="/proc/sys"{print $4}' /proc/mounts)"
echo "DN7_NOFILE=$(ulimit -n)"
echo "DN7_CAPBND=$(awk '/^CapBnd/{print $2}' /proc/self/status)"
if mount -t tmpfs none /tmp 2>/dev/null; then echo "DN7_SYSADMIN=present"; else echo "DN7_SYSADMIN=dropped"; fi
if chmod 700 /root 2>/dev/null; then echo "DN7_SECCOMP=allowed"; else echo "DN7_SECCOMP=blocked"; fi
echo "DN7_SMOKE_OK"
PROBE
chmod +x "$ROOTFS/bin/probe"

# --- config.json: pid/mount/uts/ipc/net ns + a 64 MiB memory cap + 64 pids ----
cat > "$BUNDLE/config.json" <<'JSON'
{
  "ociVersion": "1.0.2",
  "hostname": "dn7box",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/probe"],
    "env": ["PATH=/bin", "HOME=/root"],
    "cwd": "/",
    "rlimits": [ { "type": "RLIMIT_NOFILE", "hard": 256, "soft": 256 } ],
    "capabilities": {
      "bounding": ["CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_KILL"],
      "effective": ["CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_KILL"],
      "permitted": ["CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_KILL"],
      "inheritable": [],
      "ambient": []
    }
  },
  "root": { "path": "rootfs", "readonly": false },
  "mounts": [],
  "linux": {
    "namespaces": [
      { "type": "pid" }, { "type": "mount" }, { "type": "uts" },
      { "type": "ipc" }, { "type": "network" }
    ],
    "maskedPaths": ["/proc/kcore"],
    "readonlyPaths": ["/proc/sys"],
    "seccomp": {
      "defaultAction": "SCMP_ACT_ALLOW",
      "syscalls": [
        { "names": ["chmod", "fchmodat", "fchmodat2"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1 }
      ]
    },
    "resources": {
      "memory": { "limit": 67108864 },
      "pids": { "limit": 64 }
    }
  }
}
JSON

# --- locate the runtime binary ------------------------------------------------
# Prefer a prebuilt binary (DN7CRUN=...): cargo isn't on root's PATH under sudo,
# so we build as the normal user and only run the privileged ops here as root.
if [ -n "${DN7CRUN:-}" ] && [ -x "${DN7CRUN}" ]; then
  BIN="$DN7CRUN"
else
  log "cargo build --bin dn7crun"
  ( cd "$HERE" && cargo build --quiet --bin dn7crun )
  BIN="${CARGO_TARGET_DIR:-$HERE/target}/debug/dn7crun"
fi
[ -x "$BIN" ] || fail "dn7crun binary not found (set DN7CRUN=/path/to/dn7crun)"
log "runtime: $BIN"

# --- 1) run (create+start+wait) ----------------------------------------------
log "dn7crun run"
OUT="$("$BIN" run smoke-run "$BUNDLE")"
echo "$OUT"
echo "$OUT" | grep -q "DN7_SMOKE_OK"            || fail "probe did not complete"
echo "$OUT" | grep -q "DN7_HOSTNAME=dn7box"     || fail "uts namespace / hostname not applied"
echo "$OUT" | grep -q "DN7_PID1_COMM=probe"     || fail "pid namespace: init is not PID 1"
PIDS="$(echo "$OUT" | sed -n 's/^DN7_PROC_PIDS=//p')"
# Isolation proof: a shared /proc would show the host's ~150 procs; a private pid
# ns shows only the container's handful (the probe + its transient sh/pipe forks).
# The decisive check is DN7_PID1_COMM=probe above; this guards against a leak.
[ "$(echo "$PIDS" | wc -w)" -le 15 ]            || fail "pid ns not isolated (saw $(echo "$PIDS" | wc -w) pids: $PIDS)"
log "run OK (isolated: hostname + pid-ns confirmed, $(echo "$PIDS" | wc -w) container pids)"

# P3a: masked path (/proc/kcore reads 0 bytes), readonly path (/proc/sys ro), rlimit.
echo "$OUT" | grep -q "DN7_KCORE=0"             || fail "/proc/kcore not masked"
echo "$OUT" | grep -qE "DN7_SYSOPTS=ro(,|$)"    || fail "/proc/sys not remounted read-only"
echo "$OUT" | grep -q "DN7_NOFILE=256"          || fail "RLIMIT_NOFILE not applied"
echo "$OUT" | grep -q "DN7_SYSADMIN=dropped"    || fail "CAP_SYS_ADMIN not dropped (mount succeeded)"
echo "$OUT" | grep -qE "DN7_CAPBND=000001ffffffffff" && fail "bounding set not reduced (still full)"
echo "$OUT" | grep -q "DN7_SECCOMP=blocked"     || fail "seccomp did not block chmod"
log "hardening OK (masked /proc/kcore, ro /proc/sys, NOFILE=256, caps=$(echo "$OUT" | sed -n 's/^DN7_CAPBND=//p'), seccomp blocks chmod)"

# --- 2) create / state / start / delete cycle --------------------------------
log "dn7crun create"
"$BIN" create smoke-cy "$BUNDLE"
ST="$("$BIN" state smoke-cy)"; echo "$ST"
echo "$ST" | grep -q '"status": "created"'      || fail "expected created"
log "dn7crun start"
"$BIN" start smoke-cy
sleep 0.3
"$BIN" state smoke-cy | grep -Eq '"status": "(running|stopped)"' || fail "expected running/stopped after start"
log "dn7crun delete"
"$BIN" delete smoke-cy
"$BIN" state smoke-cy 2>/dev/null && fail "state should be gone after delete" || true

# --- 3) delete --force on a parked (created, never started) container ---------
log "create (parked) + list + delete --force"
"$BIN" create smoke-pk "$BUNDLE"
"$BIN" list | grep -q smoke-pk                   || fail "list should show the parked container"
# Without --force, deleting a still-alive (parked) container must be refused.
if "$BIN" delete smoke-pk 2>/dev/null; then fail "delete without --force should refuse a live container"; fi
"$BIN" delete --force smoke-pk
"$BIN" state smoke-pk 2>/dev/null && fail "parked container should be gone after delete --force" || true
[ -d /sys/fs/cgroup/dn7/smoke-pk ] && fail "cgroup should be removed after delete --force" || true
log "delete --force OK (cgroup.kill drained + removed)"

# --- 4) read-only rootfs ------------------------------------------------------
log "read-only rootfs"
RO="$WORK/ro"; mkdir -p "$RO"; cp -a "$ROOTFS" "$RO/rootfs"
cat > "$RO/config.json" <<'JSON'
{
  "ociVersion": "1.0.2", "hostname": "robox",
  "process": { "user": {"uid":0,"gid":0},
    "args": ["/bin/sh","-c","touch /should_fail 2>/dev/null && echo RO_WRITE_OK || echo RO_WRITE_DENIED"],
    "env": ["PATH=/bin"], "cwd": "/" },
  "root": { "path": "rootfs", "readonly": true },
  "linux": { "namespaces": [ {"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"},{"type":"network"} ] }
}
JSON
OUT_RO="$("$BIN" run smoke-ro "$RO")"; echo "$OUT_RO"
echo "$OUT_RO" | grep -q "RO_WRITE_DENIED"       || fail "write to read-only rootfs should have been denied"
log "read-only rootfs OK (write to / rejected)"

printf '\033[32m\nALL SMOKE CHECKS PASSED (P1 + hardening)\033[0m\n'
