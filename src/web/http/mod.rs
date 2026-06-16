//! Axum HTTP server for the on-box web console. Pure assembly — the shared
//! kernel (state/auth/bootstrap) lives in `kernel`, error mapping in
//! `exceptions`, handlers in `controllers`, gate/headers in `middleware`, and the
//! route table in `crate::web::routes`.
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        ConnectInfo, Query, Request, State,
    },
    http::{header, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::branding;
use super::settings::{self, WebSettings};
use crate::infra::auth::AuthState;
use crate::infra::metrics::Collector;
use crate::infra::support::audit;
use crate::platform::config::PanelConfig;
use include_dir::{include_dir, Dir};

mod accounts;
mod exceptions;
mod kernel;
mod policy;

use accounts::*;
use policy::*;

pub(crate) mod controllers;
pub(crate) mod middleware;

pub(crate) use exceptions::*;
pub use kernel::spawn;
pub(crate) use kernel::*;
pub(crate) use middleware::*;
