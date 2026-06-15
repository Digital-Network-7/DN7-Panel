---
inclusion: always
---

# DN7 Panel — Code Structure Standards

These rules keep the codebase testable, reviewable, and free of "God files".
They apply to all Rust code under `src/` and to new JS modules under
`src/web/ui/js/`.

## Hard limits

- **File length: ≤ 500 lines.** A file that approaches the limit must be split
  into a module directory (`foo.rs` → `foo/` with cohesive submodules).
  Generated/data tables (the i18n string table, a full CSS theme) are the only
  exception — they have no logic to split and live in one canonical file.
- **Function length: ≤ 40 lines** (body, excluding the signature and the
  closing brace). Extract helpers when a function grows past this.
- **Parameter count: ≤ 4.** A function that needs more parameters takes a
  single `struct` (a request / params / config object) instead. Prefer a named
  `XxxParams { … }` or `XxxReq { … }` struct with documented fields.

These are limits, not targets. Smaller is better. A 200-line file with
30-line functions is healthier than one that merely squeaks under the cap.

## How to split a Rust "God file"

A capability module (`docker.rs`, `nginx.rs`, `mysql.rs`, `web/server.rs`)
should be a thin parent that wires together cohesive submodules. Split along
these seams:

- **`model` / types** — request structs, response DTOs, stored records, enums.
- **`validate`** — pure input validation (no I/O); easy to unit-test.
- **`store` / persistence** — read/write of on-disk JSON/state, path helpers.
- **`exec` / operations** — the actual side-effecting work (spawning processes,
  talking to the Docker daemon, writing nginx confs).
- **`render` / response mapping** — building the JSON/HTTP responses and
  translating errors to `ERR_CODE:*`.
- **`dispatch`** — the `op`/route table that maps an incoming request to the
  right operation. Keep this small; it only routes.

Parent module pattern (Rust 2018): keep `foo.rs` as the module root that
declares its children and re-exports the public surface:

```rust
// foo.rs
mod model;
mod validate;
mod store;
mod exec;
mod dispatch;

pub use dispatch::web_dispatch;   // re-export only what callers need
```

Child modules reach shared private items via `use super::*;` (descendant
modules can see an ancestor's private items). Keep cross-module items
`pub(crate)` or `pub(super)` — never wider than necessary.

## Workflow rules when refactoring

- **Keep the build green at every commit.** Split one cohesive group at a time,
  run `cargo fmt && cargo clippy --all-targets && cargo test`, then commit.
- **No behaviour changes inside a structural split.** Move code verbatim;
  rename/extract in a *separate* commit so diffs stay reviewable.
- **Preserve visibility minimally.** Only widen an item's visibility if a moved
  caller now lives in a different module.
- Run the embedded-JS check and i18n consistency check when touching the UI.

## When a limit is genuinely impractical

If a single function truly cannot drop under 40 lines without harming clarity
(e.g. a long, flat `match` over an op table), prefer splitting the arms into
named functions. Document any deliberate, reviewed exception with a short
`// NOTE:` explaining why — exceptions should be rare and justified, not the
norm.

## Execution discipline (don't get stuck)

Large refactors are done by *acting in small, verified steps* — not by
planning the whole thing in your head first.

- **Bias to action.** Decide the cut, make it, run the build. Don't keep
  re-deriving the perfect plan. A compiling 80%-clean split beats a perfect
  plan that never lands.
- **Work in commit-sized increments.** Extract one module, run
  `cargo fmt && cargo clippy --all-targets && cargo test`, commit. Repeat.
  Never let an in-progress refactor sit in a non-compiling state across many
  edits.
- **Let the compiler drive.** Move code, build, fix exactly what the errors
  say, repeat. The compiler is faster and more accurate than exhaustively
  reasoning about visibility/imports up front.
- **Default visibility for moved items: `pub(crate)`.** Slight over-exposure is
  fine for an internal split; tighten later if it matters.
- **Keep structs whose fields are read across modules in the parent module**
  (descendant submodules can read a parent's private fields), or make the
  fields `pub(crate)`. This avoids a cascade of field-visibility edits.
- Use mechanical tools (sed/awk) to move line ranges rather than retyping —
  it's faster and avoids transcription errors.

## Accepted exceptions (deliberate, reviewed)

A pass over the codebase split out every function whose logic was genuinely
*separable* (validation, building, parsing, per-item handling, etc.). The
functions that still exceed 40 lines are cohesive single responsibilities where
splitting would hurt readability, not help it. They are accepted exceptions:

- **Bidirectional I/O loops** — PTY / exec / tar / stream bridges that own one
  `select!`/`while` loop with intertwined read/write state:
  `terminal::run_web_pty`, `terminal::run_web_container_exec`,
  `file/ctn::upload_tar_stream`, `file::web_ctn_read_stream`,
  `supervisor::supervise_loop`.
- **Self-contained algorithms** — e.g. `nginx/store::apr1_with_salt` (the
  Apache apr1 MD5-crypt algorithm); splitting its rounds would obscure it.
- **Config / DTO assembly** — functions that are mostly one big struct/JSON
  literal after their inputs are computed: `docker/create::build_create_spec`
  (8 sub-builders already extracted), `mysql/provision::create_mysql_container`,
  `docker/containers::{container_row, inspect_container}`,
  `nginx/sites::site_from_req`.
- **Op dispatch tables** — flat `match` over an op string, each arm a one-line
  call: `docker::handle`, `mysql::handle`, `docker/containers::container_action`.
- **Orchestration pipelines** — a linear sequence of clearly-labelled await
  steps with progress reporting: `nginx/certs::acme_http01`,
  `mysql/provision::run_install_detached`,
  `web/server/settings_api::apply_settings_update`.
- **Single-pass parsers** — one stateful loop over external output:
  `metrics::detect_mem_model` (dmidecode).

When adding to one of these, prefer extracting any *new* logically-distinct step
rather than growing the function further. New functions outside these categories
must still meet the 40-line limit.
