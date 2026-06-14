---
inclusion: always
---

# DN7 Panel — Code Structure Standards

These rules keep the codebase testable, reviewable, and free of "God files".
They apply to all Rust code under `src/` and to new JS modules under
`src/web/ui/js/`.

## Hard limits

- **File length: ≤ 800 lines.** A file that approaches the limit must be split
  into a module directory (`foo.rs` → `foo/` with cohesive submodules).
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
