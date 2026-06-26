//! On-box web management console.
//!
//! A small axum HTTP server exposing the panel capabilities over HTTP with a
//! token-gated first-run setup wizard + bearer sessions. Each capability request
//! is routed
//! web → `app::<cap>::dispatch` → `infra::<cap>`. This module root is pure
//! assembly; the console-management API lives in `console`, the server kernel in
//! `http`, the route table in `routes`.

mod branding;
mod console;
mod http;
mod routes;
mod settings;
pub(crate) mod terminal;

pub use console::*;
pub use http::spawn;
