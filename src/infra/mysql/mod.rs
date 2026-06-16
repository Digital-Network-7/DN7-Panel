//! Panel-side MySQL / MariaDB management.
//!
//! DN7 Panel provisions and manages MySQL/MariaDB **inside Docker containers** on
//! the user's server. We only ever touch instances *we* created: each managed
//! container carries the label `dn7.mysql=1` plus a `dn7.mysql.id` and a
//! local manifest under `<data>/mysql/<id>.json` (0600) recording the engine,
//! version, port mapping, data volume, and the at-rest-encrypted root password.
//! A user's own, hand-run MySQL is never listed or modified.
//!
//! Reached from the web console via `app::mysql::dispatch` (web → app → infra) —
//! a request/response JSON protocol backed by the local Docker daemon (bollard).
//! There is no backend relay.
//!
//! Requests (client -> panel):
//!   {"id","op":"info"}                                  docker present? + engines/versions
//!   {"id","op":"list"}                                  DN7 Panel-managed instances
//!   {"id","op":"install","engine","version","port"?,"expose"?}  -> {op_id} (detached)
//!   {"id","op":"start"|"stop"|"restart","inst"}
//!   {"id","op":"remove","inst","keep_data"?}
//!   {"id","op":"reset_password","inst"}                 -> {password}
//!   {"id","op":"change_port","inst","port"?,"expose"}   -> recreate, keep volume
//!   {"id","op":"switch_version","inst","engine"?,"version"} -> {op_id} (detached)
//!   {"id","op":"databases","inst"}                      -> [{name,tables,size}]
//!   {"id","op":"create_database","inst","database"}     create a new schema
//!   {"id","op":"drop_database","inst","database"}       drop a (non-system) schema
//!   {"id","op":"credentials","inst"}                    -> {host,port,user,password}
//!   {"id","op":"list_users","inst"}                     -> [{user,host,system}]
//!   {"id","op":"create_user","inst","username","host","password"}
//!   {"id","op":"drop_user","inst","username","host"}
//!   {"id","op":"grant"|"revoke","inst","username","host","database","privilege"}
//!   {"id","op":"query","inst","sql"}                     -> {columns,rows,truncated}
//!   {"id","op":"backup","inst"}                          -> {op_id} (detached dump)
//!   {"id","op":"list_ops"} / {"op_log","op_id"} / {"dismiss_op","op_id"}
//!
//! Only ONE instance is supported (fixed container `dn7-mysql`); create
//! multiple databases inside it. Engine/version switching recreates the
//! container against the same data volume — the UI warns that major upgrades
//! or cross-engine swaps may be incompatible and recommends a backup first.
//! Responses: {"id","ok":true,"data":..} / {"id","ok":false,"error":".."}

use std::collections::HashMap;
use std::sync::Mutex;

use crate::core::mysql::{image_ref, supported_versions, valid_engine, valid_version, MysqlError};
use anyhow::{anyhow, Result};
use bollard::Docker;
use futures::StreamExt;
use rand::Rng;
use serde_json::{json, Value};

pub(crate) use crate::contracts::mysql::Req;
pub(crate) use crate::core::mysql::Manifest;

mod accounts;
mod catalog;
mod dispatch;
mod exec;
mod opreg;
mod provision;
mod query;
mod store;
mod tables;

use accounts::*;
use catalog::*;
use dispatch::*;
use exec::*;
use opreg::{new_op_id, op_create, op_dismiss, op_finish, op_log, op_push, ops_snapshot, pmsg};
use provision::*;
use query::*;
use store::*;
use tables::*;

pub(crate) use dispatch::{
    op_dismiss_registry, op_log_value, ops_snapshot_value, run_op, CONTAINER, INSTANCE_ID,
};
