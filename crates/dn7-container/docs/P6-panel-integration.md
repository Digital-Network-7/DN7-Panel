# P6 — Panel Integration Plan (wire dn7-container into the DN7 Panel)

Replace the panel's `bollard`-backed Docker integration with this runtime, behind
a backend switch so bollard stays the cross-platform default.

## The seam (small, well-bounded)
- **Seam A (primary):** `src/infra/docker/dispatch.rs::run_op(req: &Req, is_super: bool) -> Result<Value>` — a flat `match req.op` over ~42 ops. Input = `Req` DTO; output = untyped `serde_json::Value` (UI consumes JSON directly).
- **Seam B:** `src/infra/docker/model.rs::dkr() -> Docker` — the shared bollard client, used directly by ~6 files for **streaming/exec** (web terminal PTY, container file up/download, website upstream IP lookup, container target picker).
- ~13 external call sites across 9 files; the single HTTP entry is `POST /api/docker` → `app::docker::dispatch` → `run_op`.

## Architecture
1. **Backend switch via env** (mirror `DN7_EDGE`): `DN7_RUNTIME = docker (default) | dn7`. Default keeps bollard → zero behavior change + cross-platform.
2. **dn7 adapter** maps ops → `dn7_container` calls, returning the SAME JSON shapes. `dn7_container` is **synchronous** → wrap calls in `tokio::task::spawn_blocking`. It is **Linux-only** → the dn7 backend is `#[cfg(target_os = "linux")]`; bollard remains the macOS/dev fallback.
3. **Preserve JSON shapes verbatim** (the UI is untyped). Reproduce: container row (`id,name,image,state,status,ports,ip,ips,description,uptime,has_shell,managed`), container detail, image, network, volume, stats (`cpu_pct,mem_used,...`), info, and the recreate `create_container` body — field-for-field.
4. **Decouple `CreateSpec` from bollard** before the create path (it currently embeds `bollard::container::Config`). The validators (`validate.rs`, `create/checks.rs`) + rules (`core::docker::policy`) are already backend-neutral — keep them above the seam.

## Prerequisites
- Make `crates/dn7-container` a **workspace member** of the panel (remove its standalone `[workspace]`; add to the panel's). Add it as a path dependency. Its lib compiles cross-platform (only `sys`+`container` are Linux-gated), so it won't break the macOS panel build.
- The panel must build in the dev VM (it has only ever built on macOS).

## Staging (op area at a time; each independently verifiable vs bollard)
1. **Read-only first:** `info`, `list_containers`, `list_images`, `list_networks`, `list_volumes`, `inspect_container`, `container_stats` — pure JSON projections from `dn7_container::{container::list/state/stats, image, net}`.
2. **Lifecycle:** start/stop/restart/pause/unpause/kill/remove/rename.
3. **Create + pull:** the detached-op (`op_id` + progress registry) paths → `run-image`/`pull`; needs the neutral `CreateSpec`.
4. **Images:** remove/tag/retag; **save/load** map to `image::archive`; **commit** → `image::commit`.
5. **Networks/volumes:** create/remove/connect/disconnect; volumes → `image::volume` dirs.
6. **Seam B (last, hardest):** web-terminal PTY (`exec` + a real pty), container file up/download (tar in/out of the netns/rootfs), website upstream IP lookup (`inspect` → container IP).

## Correctness net
A golden-JSON harness: run each op through both backends against a live setup and diff the `Value` output. The 5 existing smokes already prove the engine; this proves shape-parity at the panel boundary.
