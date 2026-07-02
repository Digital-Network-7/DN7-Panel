#!/usr/bin/env bash
# P2 image smoke: pull a real image from Docker Hub and run it. Needs network
# (registry access) + root (namespaces/cgroups). Build the binary first as the
# normal user and pass it in:  sudo DN7CRUN=.../dn7crun ./scripts/image_smoke.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
log()  { printf '\033[36m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"

if [ -n "${DN7CRUN:-}" ] && [ -x "${DN7CRUN}" ]; then
  BIN="$DN7CRUN"
else
  ( cd "$HERE" && cargo build --quiet --bin dn7crun )
  BIN="${CARGO_TARGET_DIR:-$HERE/target}/debug/dn7crun"
fi
[ -x "$BIN" ] || fail "dn7crun not found (set DN7CRUN=…)"

# --- 1) single-layer image: alpine -------------------------------------------
log "pull + run alpine (single layer)"
OUT="$("$BIN" run-image img-alpine alpine -- /bin/sh -c 'cat /etc/os-release; echo MACH=$(uname -m)')"
echo "$OUT"
echo "$OUT" | grep -q "Alpine Linux"       || fail "alpine userland missing"
log "alpine OK"

# --- 2) multi-layer image: a python interpreter ------------------------------
log "pull + run python:3.12-alpine (multi-layer)"
OUT="$("$BIN" run-image img-py python:3.12-alpine -- python3 -c 'print("PYOK")')"
echo "$OUT"
echo "$OUT" | grep -q "PYOK"               || fail "python multi-layer image did not run"
log "multi-layer OK (layer ordering + content-store sharing)"

# --- 3) overlay copy-on-write: writes hit the upper, not the shared lower -----
log "overlay copy-on-write"
"$BIN" run-image img-cow alpine -- /bin/sh -c 'echo x > /cow_probe' >/dev/null
[ -f /var/lib/dn7-container/bundles/img-cow/upper/cow_probe ] || fail "COW write missing from container upper"
if find /var/lib/dn7-container/rootfs-cache -name cow_probe 2>/dev/null | grep -q .; then
  fail "COW write leaked into the shared image rootfs"
fi
log "overlay COW OK (write isolated to the container's upper; shared lower clean)"

# --- 4) networking by default: resolv.conf + DNS + outbound NAT + TLS ----------
log "run-image networking (DNS + NAT + TLS)"
OUT="$("$BIN" run-image img-net alpine -- /bin/sh -c \
  'wget -q -T8 -O /dev/null https://example.com && echo NETOK' 2>/dev/null || true)"
echo "$OUT" | grep -q NETOK || fail "container could not resolve + fetch https://example.com"
log "networking OK (resolv.conf + DNS + masquerade + TLS)"

# --- 5) save → load round-trip (registry-less image transfer) -----------------
log "save + load round-trip"
"$BIN" save alpine /tmp/img_smoke.tar >/dev/null 2>&1 || fail "save failed"
"$BIN" load /tmp/img_smoke.tar smoke-loaded >/dev/null 2>&1 || fail "load failed"
OUT="$("$BIN" run-image img-loaded smoke-loaded --net none -- /bin/sh -c 'echo LOADED_OK' 2>/dev/null || true)"
echo "$OUT" | grep -q "LOADED_OK" || fail "loaded image did not run"
rm -f /tmp/img_smoke.tar
log "save/load OK"

# --- 6) commit: container changes → new image --------------------------------
log "commit round-trip"
"$BIN" run-image cm1 alpine --net none -- /bin/sh -c 'echo CMARK > /committed' >/dev/null 2>&1
"$BIN" commit cm1 smoke-committed >/dev/null 2>&1 || fail "commit failed"
OUT="$("$BIN" run-image cm2 smoke-committed --net none -- /bin/sh -c 'cat /committed' 2>/dev/null || true)"
echo "$OUT" | grep -q "CMARK" || fail "committed file missing from new image"
rm -rf /var/lib/dn7-container/bundles/cm1 /var/lib/dn7-container/bundles/cm2
log "commit OK"

# --- cleanup bundles (run-image leaves no container state) --------------------
rm -rf /var/lib/dn7-container/bundles/img-alpine /var/lib/dn7-container/bundles/img-py \
       /var/lib/dn7-container/bundles/img-cow /var/lib/dn7-container/bundles/img-net \
       /var/lib/dn7-container/bundles/img-loaded

printf '\033[32m\nALL IMAGE SMOKE CHECKS PASSED (P2 + overlay + networking + save/load + commit)\033[0m\n'
