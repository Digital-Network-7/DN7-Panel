//! Platform layer: host process lifecycle + OS integration.
//!
//! Per `.kiro/steering/architecture.md`: these modules manage the *host
//! runtime* rather than any business capability — daemonizing, process
//! supervision/respawn, boot autostart, log rotation, install paths, pid/lock
//! files, env config, the console banner, release signing, self-update, and the
//! panel-role bootstrap. They act as composition roots (they may wire `web` /
//! `infra` / `app` together) and are not governed by the layer deny-rules.

pub(crate) mod autostart;
pub(crate) mod banner;
pub(crate) mod config;
pub(crate) mod daemon;
pub(crate) mod guardian;
pub(crate) mod init_cli;
pub(crate) mod kmod;
pub(crate) mod logrotate;
pub(crate) mod netinfo;
pub(crate) mod panel;
pub(crate) mod paths;
pub(crate) mod privilege;
pub(crate) mod procfile;
pub(crate) mod signing;
pub(crate) mod supervisor;
pub(crate) mod update;
