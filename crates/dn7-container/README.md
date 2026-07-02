# dn7-container

DN7 Panel's self-contained container runtime — **no Docker, no runc, no youki**.
A from-scratch implementation that drives the Linux kernel directly. This crate
is built incrementally (P1 → P7); it is wired into the panel at P6.

> **Linux-only.** It uses namespaces, cgroup v2, `pivot_root`, and `mknod`, which
> have no macOS equivalent. The crate still *type-checks* on a dev mac (only the
> portable `error` + `oci` modules compile there); the real build/test target is
> Linux. The repo's dev VM is a Lima Ubuntu guest (`limactl shell dn7`).

## Status

**P1 — OCI runtime core (a runc-equivalent). Done + verified.** Take an OCI
bundle (`config.json` + `rootfs/`) and run it isolated:

| Capability | Where |
|---|---|
| Namespaces (pid/mount/uts/ipc/net) via `clone(2)` | `sys/namespaces.rs`, `container/mod.rs` |
| cgroup v2 limits (memory / cpu / pids) | `sys/cgroup.rs` |
| rootfs assembly (`/proc`,`/sys`,`/dev`, device nodes) + `pivot_root` | `sys/mount.rs` |
| Container init (PID 1): env, user drop, no-new-privs, read-only root, exec | `container/init.rs` |
| Lifecycle `run`/`create`/`start`/`state`/`kill`/`delete`/`list` (+`--force` via `cgroup.kill`) | `container/mod.rs` |
| Persisted `state.json` + create→start exec FIFO | `container/state.rs` |

**P2 — image pull + runnable rootfs. Done + verified.** Pull a real image from a
registry and run it:

| Capability | Where |
|---|---|
| Reference parsing (Docker Hub defaults, `library/`, hosts, digests) | `image/reference.rs` |
| Registry v2 client: anonymous bearer-token auth, manifest, blob stream | `image/registry.rs` |
| Manifest / multi-arch index / image-config types | `image/manifest.rs` |
| Content-addressable blob store (sha256-verified) | `image/store.rs` |
| Layer apply: gunzip + untar + OCI whiteouts (merged rootfs) | `image/layer.rs` |
| Image config → OCI `config.json` (Entrypoint/Cmd/Env/WorkingDir/User) | `image/spec_gen.rs` |
| `pull` + `run-image` orchestration | `image/mod.rs` |

**P3 — process security hardening. In progress (done + verified).** Containers
are now confined like Docker:

| Capability | Where |
|---|---|
| Masked paths (`/dev/null` over files, ro tmpfs over dirs) — e.g. `/proc/kcore` | `sys/mount.rs`, `container/init.rs` |
| Read-only paths (e.g. `/proc/sys`) | `sys/mount.rs` |
| `setrlimit` resource limits | `container/init.rs` |
| Capability confinement: bounding-set drop + effective/permitted/inheritable/ambient | `container/init.rs` |
| Seccomp-BPF syscall filter (pure Rust via `seccompiler`, no libseccomp) | `sys/seccomp.rs` |
| Image-runs get Docker's default masked/readonly paths + 14-cap allowlist + a blocklist seccomp profile | `image/spec_gen.rs` |

**P4 — storage. In progress (done + verified).** Each image's merged rootfs is
extracted into the store **once** (read-only, shared); every container runs on a
**copy-on-write overlay** (shared lower + per-container upper/work) — container
start is a mount, not a copy, and writes never touch the shared image.

| Capability | Where |
|---|---|
| Extract-once shared image rootfs cache (by config digest) | `image::ensure_image_rootfs` |
| Copy-on-write overlay mount per container | `sys/overlay.rs` |

**P5 — networking. In progress.** Designed end-to-end (see
[docs/P5-networking-plan.md](docs/P5-networking-plan.md)); shells out to `ip`/`nft`
behind the sync runtime.

| Capability | Where |
|---|---|
| IPAM: flock'd lease table, deterministic names/MACs (P5a) | `net/{config,ipam}.rs` |
| Bridge + veth + per-container IP + gateway route (P5b) | `net/{backend,mod}.rs` |
| Outbound NAT (`nft` masquerade + `ip_forward`) → internet (P5c) | `net/firewall.rs` |
| DNS — `resolv.conf` from host upstreams (P5d) | `net/dns.rs` |
| Published ports — `nft` DNAT `host:port → container` + hairpin (P5e) | `net/firewall.rs` |

`run-image <img>` is networked by default (`--net none` opts out): a container
gets an IP on `dn7br0`, reaches the internet, resolves DNS, and can publish ports
with `-p 8080:80`. Setup/teardown is parent-side (no `CAP_NET_ADMIN` inside).
Verified by `scripts/{net,port}_smoke.sh` — including that the host's own
networking/SSH is untouched.

**P6 — manager ops + panel API. In progress.** Done: `net gc`, host/none modes
(P5 tail); container **`logs`**, **`exec`** (via `nsenter`), **`stats`** (cgroup
v2 counters), **volumes** (`-v name:/path` named + host binds); **`save`/`load`**
(OCI image-layout tar — registry-less image transfer); and local-first run-image
(uses a pulled/loaded image if present, works offline).

**Not yet:** user-ns id-mapping, the survive-restart shim (rest of P3); per-*layer*
sharing, registry auth (rest of P4); embedded container-name DNS (P5h); the rest
of P6 — `commit`, and the **bollard-shaped API replacing the panel's
`src/infra/docker`** (the product integration); rootless (P7).

## CLI verbs (`dn7crun`)
`run` · `create` · `start` · `state` · `kill` · `delete [--force]` · `list` ·
`logs` · `exec` · `stats` · `pull` · `save` · `load` · `commit` ·
`run-image [--net] [-p] [-v]` · `net gc`

As a **standalone engine** this now covers the Docker common path end-to-end; the
remaining work (P6) is the bollard-shaped API that lets the **panel** drive it in
place of `src/infra/docker/`.

## Layout

```
src/
  error.rs            # one error enum (portable)
  oci/spec.rs         # OCI runtime-spec config.json (portable)
  oci/bundle.rs       # bundle dir layout (portable)
  image/reference.rs  # image ref parsing                        (portable)
  image/registry.rs   # registry v2 client (ureq)                (portable)
  image/manifest.rs   # manifest/index/config types              (portable)
  image/store.rs      # content-addressable blob store           (portable)
  image/layer.rs      # gunzip+untar+whiteouts                   (portable)
  image/spec_gen.rs   # image config → config.json               (portable)
  image/mod.rs        # pull + prepare_bundle                    (portable)
  sys/namespaces.rs   # OCI namespace kinds → clone flags        (linux)
  sys/cgroup.rs       # cgroup v2 controller                     (linux)
  sys/mount.rs        # rootfs mounts + pivot_root               (linux)
  container/state.rs  # state.json + runtime dir                 (linux)
  container/init.rs   # the PID-1 child: setup → exec            (linux)
  container/mod.rs    # parent-side lifecycle orchestration      (linux)
  bin/dn7crun.rs      # runc-style CLI to drive/test it          (linux)
```

## Build & test (on the Linux VM, as root)

```sh
# inside the VM, project mounted at /work/panel
cd /work/panel/crates/dn7-container
export CARGO_TARGET_DIR=$HOME/dn7-target   # keep target off the virtiofs mount
cargo build --bin dn7crun
cargo test                                 # unit tests (24)
BIN=$CARGO_TARGET_DIR/debug/dn7crun

sudo DN7CRUN=$BIN ./scripts/smoke.sh       # P1: busybox bundle, full lifecycle
sudo DN7CRUN=$BIN ./scripts/image_smoke.sh # P2: pull + run alpine & python

# pull + run a real image directly:
sudo $BIN run-image demo alpine -- /bin/sh -c 'cat /etc/os-release'
```

`scripts/smoke.sh` asserts isolation (UTS hostname, init is PID 1, PID-ns hides
host processes), the lifecycle, `delete --force`, and a read-only rootfs.
`scripts/image_smoke.sh` pulls alpine (single layer) and python (multi-layer)
from Docker Hub and runs them.

## Design notes

- **Limiter/runtime state is process-local**, not in any reloadable config — a
  container outlives a single CLI invocation, so `state.json` under
  `/run/dn7-container/<id>` is the source of truth.
- **create→start gate:** the init parks writing to an `exec.fifo` (held as an
  inherited `O_PATH` fd it re-opens through `/proc/self/fd` after `pivot_root`);
  `start` opens the read end to release it. This mirrors runc's `exec.fifo`.
- **cgroup placement handshake:** the parent clones the init, the init blocks on
  a pipe until the parent has written its pid into `cgroup.procs`, so every
  container process is accounted from birth.
