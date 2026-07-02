#!/usr/bin/env bash
# P5b network smoke: a bridged container gets an IP on dn7br0 and pings its
# gateway. Asserts the VM's OWN networking (default route + SSH NIC) is untouched.
# Needs root. Build first: sudo DN7CRUN=.../dn7crun ./scripts/net_smoke.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/dn7ctr-net}"
BUNDLE="$WORK/bundle"; ROOTFS="$BUNDLE/rootfs"
log()  { printf '\033[36m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v ip >/dev/null || fail "need iproute2 (ip)"

if [ -n "${DN7CRUN:-}" ] && [ -x "${DN7CRUN}" ]; then BIN="$DN7CRUN"; else
  ( cd "$HERE" && cargo build --quiet --bin dn7crun ); BIN="${CARGO_TARGET_DIR:-$HERE/target}/debug/dn7crun"; fi
[ -x "$BIN" ] || fail "dn7crun not found (set DN7CRUN=…)"

# --- safety: snapshot the VM's own networking + confirm our subnet is free -----
DEF_ROUTE_BEFORE="$(ip route show default)"
# Our own dn7br0 (from a prior run) is fine; abort only if some OTHER iface holds it.
if ip -o addr show | grep -v ' dn7br0 ' | grep -qE '172\.18\.0\.'; then
  fail "172.18.0.0/24 already in use by a non-dn7 interface — abort"
fi
log "VM default route (must survive): ${DEF_ROUTE_BEFORE:-<none>}"

# --- build a busybox bundle that requests bridge networking -------------------
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends busybox-static >/dev/null 2>&1 || true
BB="$(command -v busybox)"
rm -rf "$WORK"; mkdir -p "$ROOTFS"/{bin,proc,sys,dev,etc,tmp,root}
cp "$BB" "$ROOTFS/bin/busybox"
for a in sh ip ifconfig ping grep head cat ls echo true sleep; do ln -sf busybox "$ROOTFS/bin/$a"; done

cat > "$ROOTFS/bin/probe" <<'PROBE'
#!/bin/sh
IP=$(ip addr show eth0 2>/dev/null | grep -o '172\.18\.0\.[0-9]*' | head -1)
[ -z "$IP" ] && IP=$(ifconfig eth0 2>/dev/null | grep -o '172\.18\.0\.[0-9]*' | head -1)
echo "DN7_NETNS_IP=$IP"
ping -c1 -W2 172.18.0.1 >/dev/null 2>&1 && echo "DN7_PING=ok" || echo "DN7_PING=fail"
ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo "DN7_INET=ok" || echo "DN7_INET=fail"
echo "DN7_NET_OK"
PROBE
chmod +x "$ROOTFS/bin/probe"

cat > "$BUNDLE/config.json" <<'JSON'
{
  "ociVersion": "1.0.2", "hostname": "netbox",
  "annotations": { "dn7.net": "bridge" },
  "process": { "user": {"uid":0,"gid":0}, "args": ["/bin/probe"],
    "env": ["PATH=/bin"], "cwd": "/" },
  "root": { "path": "rootfs", "readonly": false },
  "linux": { "namespaces": [
    {"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"},{"type":"network"}
  ] }
}
JSON

# --- run + assert -------------------------------------------------------------
log "run bridged container"
OUT="$("$BIN" run netc "$BUNDLE")"; echo "$OUT"
echo "$OUT" | grep -q "DN7_NETNS_IP=172.18.0." || fail "container did not get a bridge IP"
echo "$OUT" | grep -q "DN7_PING=ok"            || fail "container could not ping its gateway 172.18.0.1"
echo "$OUT" | grep -q "DN7_INET=ok"            || fail "container has no outbound internet (NAT/masquerade)"
log "container got $(echo "$OUT" | sed -n 's/^DN7_NETNS_IP=//p'), pinged its gateway, and reached the internet"

# --- safety asserts: VM networking untouched ----------------------------------
[ "$(ip route show default)" = "$DEF_ROUTE_BEFORE" ] || fail "VM default route changed!"
ip link show dn7br0 >/dev/null 2>&1 || fail "dn7br0 bridge missing"
log "VM default route intact; dn7br0 present"

# --- teardown leak check (run() frees veth + lease on exit) -------------------
ip link show | grep -oE 'dn7v[0-9a-f]+' && fail "veth leaked after run" || true
[ -f /run/dn7-container/_ipam/dn7/leases.json ] && \
  ! grep -q '"container_id": "netc"' /run/dn7-container/_ipam/dn7/leases.json || true
log "no veth leak; lease released"

printf '\033[32m\nALL NET SMOKE CHECKS PASSED (P5b bridge/veth + P5c outbound NAT)\033[0m\n'
