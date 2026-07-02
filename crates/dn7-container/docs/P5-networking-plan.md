# P5 Networking — Implementation Plan (dn7-container)

> Produced by a multi-agent design workflow (5 parallel sub-problem designs →
> adversarial synthesis). The grounding fact: the runtime is **100% synchronous**
> (`clone()` + sync pipe + `waitpid`; blocking `ureq`; no tokio/async anywhere) —
> which settles every netlink-vs-async question in favor of *no async runtime*.

## 1. Decisions

| Sub-problem | Decision |
|---|---|
| Link plumbing (veth/bridge/addr/route/netns-move) | **Shell out to `ip` (iproute2)** behind a `NetBackend` trait. No async runtime to justify rtnetlink/tokio; `ip link set <veth> netns <PID>` crosses namespaces with no fd/thread juggling. |
| netns crossing | `ip link set <veth_ctr> netns <PID>` to move the peer; configure the inside via a **forked child that `setns(CLONE_NEWNET)` then `execvp("ip", …)`** (never `setns` a live multithreaded process). |
| IPAM | flock'd JSON lease table per network; leases are source of truth. Default net `dn7`, `172.18.0.0/24`, gw `.1`, bridge `dn7br0`. Leases on `/run` (tmpfs, self-cleaning on reboot); network *config* on `/var/lib`. |
| Firewall | **Shell `nft -f -` into our own `table inet dn7`.** Atomic transactions, vmap port-publishing, one-line teardown (`nft delete table inet dn7`). |
| DNS | **MVP:** write `/etc/resolv.conf` (host upstreams, stub-filtered) bind-mounted into the container. **Target (P5h):** embedded blocking responder on the bridge gateway:53. |
| Lifecycle hooks | All wiring happens **parent-side in the cgroup-sync window** (after `cg.add_pid`, before `release(wfd)`); teardown in `run` after `wait_exit` and in `delete` after cgroup drain. Child gains no code, needs no `CAP_NET_ADMIN`. |

Sanctioned ethos compromise: two external binaries (`ip`, `nft`) — both on every
modern host, both behind a trait so a pure-Rust netlink backend can swap in later.

## 2. Crates
Add only `ipnet = "2"` (Ipv4Net subnet math). `nix` `Flock` is in the enabled `fs`
feature. Shell out to `ip` + `nft` (probe at startup, fail loudly). Use `ip -j` /
`nft -j` (JSON) for reads → parse with existing serde_json. Deferred (P5h):
`hickory-proto`/`hickory-resolver` for the embedded DNS responder.

## 3. Module layout — `src/net/`
- `mod.rs` — `NetworkManager` (plan/apply/teardown/teardown_partial/reconcile); `NetMode {Bridge{ports}|Host|None}`; `NetConfig::from_bundle` (parse + VALIDATE).
- `config.rs` — `NetState` receipt; `PortMap`; `Proto`; id validation; deterministic name derivation (`veth_host = "dn7v"+sha256(id)[..8 hex]`, ≤15 bytes); `mac_for(ip)`.
- `backend.rs` — `trait NetBackend` + `ShellNet` (wraps `ip`); forked-setns-then-exec(`ip`) for the in-netns half.
- `ipam.rs` — `NetworkConfig` (persistent), `Lease`, `LeaseTable`; `with_net_lock` (flock), allocate/free/reclaim_dead, create/load network, `mac_for`.
- `firewall.rs` — `ensure_nat_table`, publish/unpublish_port (nft transaction), masquerade, teardown_container (by comment), nuke_table.
- `dns.rs` — MVP `write_resolver_files` (/etc/hosts, /etc/hostname, /etc/resolv.conf as bind,ro mounts) + `host_upstreams`. Target: `serve(gateway, upstreams)`.

`State` gains `net: Option<NetState>` (skip-if-none) **plus** a sibling
`network.json` receipt, so reconciliation survives a torn file.

## 4. Lifecycle hooks
Invariant: the netns exists the moment `clone(CLONE_NEWNET)` returns; the child is
blocked in `wait_for_cgroup()`. Do ALL wiring in that window, then `release(wfd)`.

- **`run()`**: after `cg.add_pid(pid)`, before `release(wfd)`: `NetConfig::from_bundle` (validate) → `NetworkManager::apply(id, pid, cfg)`; on error kill+wait+teardown_partial+cg.delete. After `wait_exit`: `teardown`.
- **`create_inner()`**: same `apply`; persist `state.net` + `network.json` after success; add `teardown_partial` to the `create()` rollback.
- **`start()`**: unchanged (network already live from create).
- **`delete()`**: after `wait_drained`, before `cg.delete()`: `teardown`. Order: delete nft elements → `ip link del veth_host` (ignore ENOENT) → free lease. Never tear the shared bridge/table on per-container delete. Idempotent.
- **`kill()`**: unchanged (teardown deferred to delete).
- **Host mode**: spec omits netns → `apply` no-op; must drop `CAP_NET_ADMIN`/`NET_RAW` unless opted in. **None**: keep netns, bring `lo` up only. **Pod-join** (`path:` ns): extension point.

## 5. MVP slice + Lima test
Container on `dn7br0` (`172.18.0.0/24`, gw `.1`) gets `eth0` + IP + default route +
`lo` up; outbound MASQUERADE; one published port (`-p 8080:80`). resolv.conf = host
upstreams. Safe for the VM: only create a *new* bridge on a private subnet (after a
collision check), only touch our own `table inet dn7`, record `ip_forward`'s prior
value. Never touch the VM's `eth0`/default route/SSH NIC. Test asserts `ip addr`
before/after parity + SSH survives + `curl 127.0.0.1:8080` + leak check after
`delete`.

## 6. Top risks → mitigations
1. **Host-network disruption** → never modify existing ifaces/tables; pre-flight subnet collision check; dedicated bridge + `inet dn7` table; record (don't reset) shared sysctls.
2. **Rule/lease/veth leaks on crash** → deterministic naming (`dn7v<hash>`, nft `comment "dn7:<id>"`); `dn7crun net gc` reconciles from kernel + receipts; `/run` tmpfs self-cleans on reboot; idempotent `teardown_partial` on apply failure.
3. **Firewall coexistence (Docker/firewalld/legacy)** → only our own `table inet dn7`, never append to `nat`/`filter`/`DOCKER`/firewalld chains.
4. **Security / rule injection** → validate `id` (`[a-z0-9][a-z0-9_.-]{0,63}`); derive iface names/comments from `sha256(id)`, never raw; parse ports→u16/proto→enum/ip→IpAddr; reject duplicate host_ip:port:proto; container has no `CAP_NET_ADMIN`.
5. **Async-in-sync trap** → avoid entirely (shell `ip`/`nft`); enter netns only via a *forked* `setns`+`execvp("ip")` child, never a thread.

## 7. Phase order (independently verifiable)
- **P5a** — scaffolding & IPAM (no root): `config.rs` (NetState, validation, name/mac), `ipam.rs` (flock lease table). Unit tests: distinct IPs from `.2`, deterministic MAC, free-then-realloc, dead-pid reclaim, exhaustion, concurrency = no dup IPs.
- **P5b** — link plumbing (None + Bridge L2): `backend.rs` ShellNet; veth/bridge/addr/route/lo; wire `apply`/`teardown` into `run()`. Verify: container pings gateway.
- **P5c** — outbound NAT: `firewall.rs` masquerade + `ip_forward`. Verify: container reaches 1.1.1.1.
- **P5d** — resolv.conf MVP: `dns.rs` bind mounts. Verify: `getent hosts` works.
- **P5e** — published ports: nft vmaps + DNAT + hairpin + forward rules; wire create/delete + persistence. Verify: `curl host:8080`.
- **P5f** — teardown hardening + `net gc` reconciliation.
- **P5g** — coexistence (firewalld VM) + Host/None modes + cap drop.
- **P5h** (deferred) — embedded DNS responder on gateway:53.
