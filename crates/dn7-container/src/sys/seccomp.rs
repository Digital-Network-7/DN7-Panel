//! Seccomp-BPF syscall filtering, compiled in pure Rust via `seccompiler` (no
//! libseccomp C dependency). Translates an OCI seccomp profile into a BPF program
//! and installs it on the calling thread just before `execve`.
//!
//! MVP shape: a profile has a `defaultAction` and a list of syscalls that deviate
//! from it. `seccompiler` expresses one mismatch action + one match action, which
//! exactly fits the dominant patterns — default-deny + allowlist (Docker's
//! default profile) and default-allow + blocklist (our generated profile). A
//! profile mixing *several* non-default actions is rejected rather than silently
//! mis-applied. Argument-value conditions are not yet honoured.

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

use crate::error::{Error, Result};
use crate::oci::spec::Seccomp;

/// Build and install the seccomp filter for `profile` on the current thread.
/// Requires `no_new_privs` (or CAP_SYS_ADMIN) to already be set.
pub fn apply(profile: &Seccomp) -> Result<()> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| Error::Other(format!("seccomp: unsupported arch: {e}")))?;
    let mismatch = map_action(&profile.default_action, profile.default_errno_ret)?;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut match_action: Option<SeccompAction> = None;

    for rule in &profile.syscalls {
        let action = map_action(&rule.action, rule.errno_ret)?;
        if action == mismatch {
            continue; // already the default — no rule needed
        }
        match &match_action {
            None => match_action = Some(action.clone()),
            Some(a) if *a == action => {}
            Some(_) => {
                return Err(Error::Other(
                    "seccomp: more than one non-default action is unsupported (MVP)".into(),
                ))
            }
        }
        for name in &rule.names {
            if let Some(num) = resolve(name) {
                // Empty rule vec = match the syscall unconditionally.
                rules.entry(num).or_default();
            }
            // Unknown syscall names are skipped — profiles are written for many
            // kernels/arches and routinely list syscalls absent on some.
        }
    }

    // Nothing deviates from the default. Installing a filter would still be a
    // no-op for a default-allow profile; for a restrictive default with no rules
    // we'd block everything, which is never what an empty profile means — so skip.
    if rules.is_empty() {
        return Ok(());
    }

    let match_action = match_action.unwrap_or(SeccompAction::Allow);
    let filter = SeccompFilter::new(rules, mismatch, match_action, arch)
        .map_err(|e| Error::Other(format!("seccomp: build filter: {e}")))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::Other(format!("seccomp: compile bpf: {e}")))?;
    seccompiler::apply_filter(&program).map_err(|e| Error::Other(format!("seccomp: install: {e}")))
}

/// Resolve a syscall name to its number for the build arch.
fn resolve(name: &str) -> Option<i64> {
    name.parse::<syscalls::Sysno>().ok().map(|s| s.id() as i64)
}

/// Map an `SCMP_ACT_*` action to a `seccompiler` action.
fn map_action(action: &str, errno: Option<u32>) -> Result<SeccompAction> {
    Ok(match action {
        "SCMP_ACT_ALLOW" => SeccompAction::Allow,
        "SCMP_ACT_ERRNO" => SeccompAction::Errno(errno.unwrap_or(libc::EPERM as u32)),
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => SeccompAction::KillThread,
        "SCMP_ACT_KILL_PROCESS" => SeccompAction::KillProcess,
        "SCMP_ACT_LOG" => SeccompAction::Log,
        "SCMP_ACT_TRAP" => SeccompAction::Trap,
        "SCMP_ACT_TRACE" => SeccompAction::Trace(errno.unwrap_or(0)),
        other => return Err(Error::Other(format!("unknown seccomp action: {other}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_oci_actions() {
        assert_eq!(
            map_action("SCMP_ACT_ALLOW", None).unwrap(),
            SeccompAction::Allow
        );
        assert_eq!(
            map_action("SCMP_ACT_ERRNO", Some(13)).unwrap(),
            SeccompAction::Errno(13)
        );
        assert_eq!(
            map_action("SCMP_ACT_ERRNO", None).unwrap(),
            SeccompAction::Errno(libc::EPERM as u32)
        );
        assert!(map_action("SCMP_ACT_BOGUS", None).is_err());
    }

    #[test]
    fn resolves_known_syscalls() {
        // `mount` exists on every Linux arch we target.
        assert!(resolve("mount").is_some());
        assert!(resolve("definitely_not_a_syscall").is_none());
    }
}
