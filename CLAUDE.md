# DN7 Panel — agent guide

A single static Rust binary that manages a Linux host via an on-box web console
(monitoring, web terminal, containers, website, files). One crate at the root +
helper crates under `crates/`. No backend, no panel token, no runtime deps.

## Architecture constitution

- **Read [`ARCHITECTURE.md`](ARCHITECTURE.md) before any structural change.** It
  is the project constitution: layer responsibilities, the dependency direction
  (`web → app → core`; `infra → app → core`; `contracts` depends on nothing
  above `core`), the per-layer "禁止项" lists, and the file/function size limits.
- The rules are **enforced** by `tests/architecture.rs` (directory-level deny +
  module allowlist + a `core` serde whitelist). A PR that violates the
  dependency direction or the limits should fail review — don't add `arch-allow`
  exceptions without a tracked reason.

## Hard invariants

- **Zero external dependencies at runtime.** No shelling out to system programs
  (`ss`/`ip`/`useradd`/`systemctl`/…) and no `docker`/`nginx`/`openssl` CLI — all
  of it is pure Rust. The reverse proxy is the in-process edge (`crates/dn7-edge`,
  `infra::website` control plane), not external nginx.
  - **Carve-out — init/bootstrap, service lifecycle & the `dn7` management CLI.**
    Talking to the host init manager (`systemctl`/`journalctl`/`service`/
    `update-rc.d`) has no pure-Rust equivalent, so shell-out is allowed at a
    fixed, audited allowlist of non-serving-loop sites: first-run install/start
    (`platform::init_cli::register_and_start_service`), `dn7 reset` service-stop
    (`run_reset` in `main.rs`), and the human-invoked `dn7` management
    subcommands (`crates/dn7-cli/src/{service,panel,uninstall,edge}.rs` —
    `dn7 service`/`panel status|logs|restart`/`uninstall`/`edge`). None run in
    the resident serving loop (`dn7 panel status` even probes via pure-Rust
    `/proc`). The allowlist is enforced by `tests/architecture.rs`
    `no_new_init_manager_shellouts`: a NEW `systemctl`/`journalctl`/`update-rc.d`
    shell-out outside those files fails the gate. The *resident runtime* stays
    external-program-free — don't add init-manager shell-outs anywhere else.
- **Fully static musl binary.** Release builds must stay statically linked (no
  `DT_NEEDED`). Don't pull in C-linked crates.

## Build & test workflow

- The Linux build/test runs in a **Lima VM named `dn7`** (`/work/panel` mount) —
  not on the macOS host. Another process may own the build; don't kick off
  `cargo build`/`test` blindly.
- Gate every change on: `cargo fmt && cargo clippy --workspace --all-targets --
  -D warnings && cargo test --workspace` (CI runs clippy with `-D warnings`; keep
  it clean). The `--workspace` is REQUIRED — without it `cargo test`/`clippy` from
  the root package skip the helper crates (dn7-edge/dn7-container/dn7-cli/dn7-cred).
- Touched the UI? Run `node scripts/check_i18n.js` (4 languages) from the repo
  root.
- For local foreground runs use `DN7_NO_GUARDIAN=1 dn7-panel panel`; never
  hand-run the top-level `dn7-panel` (it performs a real system install).
- **Gate-green is NOT ship-ready for a user-facing flow.** fmt/clippy/tests + a
  curl/API check can all pass while the *browser* flow is broken. The forced
  first-run "Set Up Your Account" flow shipped completely non-functional TWICE —
  build 3: a JS crash (`switchTab`'s `stopTab()` wiped the modal, orphaning a
  `focus()` timeout); build 4: `/api/settings` demanded a step-up the screen has
  no password to provide — both because only the backend was verified. Before
  releasing anything touching login / first-run / setup / auth or any interactive
  screen, drive the ACTUAL flow in a real browser (puppeteer-core + system Chrome
  against a VM instance over an SSH tunnel to `127.0.0.1:<port>` — the dev-VM
  memory has the recipe) and confirm it completes end-to-end with zero console
  errors. Never release a UI flow you only curl-tested.
- **`release.toml` must parse as TOML before pushing**
  (`python3 -c "import tomllib; tomllib.load(open('release.toml','rb'))"`). CI and
  `.github/gen_releases.py` read it with `tomllib`; a raw `"` inside a `"…"` notes
  string silently breaks the build/release — use 「」 for inner quotes in
  zh-CN/zh-TW, and `\"` in `en`.
