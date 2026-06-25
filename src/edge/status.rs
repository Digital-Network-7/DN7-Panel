//! The edge server's run state, so the control plane (and the UI through
//! `website_info`) can tell whether the listeners are up — or stuck on a port
//! conflict the operator must resolve (a foreign process holds :80/:443).

use std::sync::{Mutex, OnceLock};

/// Where the edge listeners stand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum RunState {
    /// Not started yet (pre-setup, or the panel just booted).
    #[default]
    NotStarted,
    /// Bound :80/:443 and serving.
    Running,
    /// These ports could not be bound — a foreign process holds them. The
    /// operator can force-start (kill the occupants) to take them over.
    PortConflict(Vec<u16>),
}

fn cell() -> &'static Mutex<RunState> {
    static S: OnceLock<Mutex<RunState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(RunState::NotStarted))
}

pub(crate) fn set(state: RunState) {
    *cell().lock().unwrap_or_else(|p| p.into_inner()) = state;
}

pub(crate) fn get() -> RunState {
    cell().lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// The ports currently in conflict, if the edge is stuck on a port conflict.
pub(crate) fn port_conflict() -> Option<Vec<u16>> {
    match get() {
        RunState::PortConflict(ports) => Some(ports),
        _ => None,
    }
}
