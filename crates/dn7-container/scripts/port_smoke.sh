#!/usr/bin/env bash
# P5e port-publishing smoke: a bridged container runs busybox httpd and publishes
# 8080→80; the host curls it via localhost and the VM IP; delete removes the DNAT.
# Needs root + network. Build first: sudo DN7CRUN=.../dn7crun ./scripts/port_smoke.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/dn7ctr-port}"; ROOTFS="$WORK/bundle/rootfs"
log()  { printf '\033[36m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; "$BIN" delete webc --force 2>/dev/null || true; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
if [ -n "${DN7CRUN:-}" ] && [ -x "${DN7CRUN}" ]; then BIN="$DN7CRUN"; else
  ( cd "$HERE" && cargo build --quiet --bin dn7crun ); BIN="${CARGO_TARGET_DIR:-$HERE/target}/debug/dn7crun"; fi
[ -x "$BIN" ] || fail "dn7crun not found (set DN7CRUN=…)"

DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends busybox-static >/dev/null 2>&1 || true
rm -rf "$WORK"; mkdir -p "$ROOTFS"/{bin,proc,sys,dev,etc,tmp,www}
cp "$(command -v busybox)" "$ROOTFS/bin/busybox"
for a in sh httpd ip; do ln -sf busybox "$ROOTFS/bin/$a"; done
MARK="HELLO-FROM-DN7-$$"
echo "$MARK" > "$ROOTFS/www/index.html"

cat > "$WORK/bundle/config.json" <<'JSON'
{
  "ociVersion": "1.0.2", "hostname": "web",
  "annotations": { "dn7.net": "bridge", "dn7.ports": "8080:80" },
  "process": { "user": {"uid":0,"gid":0},
    "args": ["/bin/httpd", "-f", "-p", "80", "-h", "/www"], "env": ["PATH=/bin"], "cwd": "/" },
  "root": { "path": "rootfs", "readonly": false },
  "linux": { "namespaces": [
    {"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"},{"type":"network"}
  ] }
}
JSON

log "create + start (httpd, publish 8080→80)"
"$BIN" create webc "$WORK/bundle"
"$BIN" start webc
sleep 0.5

log "curl published port via localhost + VM IP"
GOT_LOCAL="$(curl -s --max-time 5 http://127.0.0.1:8080/ || true)"
echo "$GOT_LOCAL" | grep -q "$MARK" || fail "localhost:8080 did not reach the container httpd"
VMIP="$(ip -4 -o addr show eth0 2>/dev/null | grep -oE '192\.168\.[0-9]+\.[0-9]+' | head -1 || true)"
if [ -n "$VMIP" ]; then
  curl -s --max-time 5 "http://$VMIP:8080/" | grep -q "$MARK" || fail "$VMIP:8080 did not reach the container"
fi
log "published port reachable (localhost${VMIP:+ + $VMIP})"

log "delete (teardown removes DNAT)"
"$BIN" delete webc --force
sleep 0.3
curl -s --max-time 3 http://127.0.0.1:8080/ | grep -q "$MARK" && fail "port still open after delete" || true
[ "$(nft list table inet dn7 2>/dev/null | grep -c 'dn7:webc')" = "0" ] || fail "DNAT rules leaked after delete"
log "port closed + DNAT rules removed"

printf '\033[32m\nALL PORT SMOKE CHECKS PASSED (P5e: published ports)\033[0m\n'
