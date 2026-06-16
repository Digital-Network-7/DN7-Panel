//! Shell-probe cache + privileged-container detection.
use super::*;

/// Cache of `has_shell` probe results keyed by image id, with a short TTL.
/// Shell availability is a property of the image (the binaries it ships), so it
/// doesn't change over a container's life; the TTL just bounds staleness if an
/// image is rebuilt under the same id.
fn shell_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, (bool, u64)>> {
    static C: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (bool, u64)>>,
    > = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

const SHELL_CACHE_TTL_SECS: u64 = 60;

fn shell_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Return a cached `has_shell` result for `key` if present and fresh.
pub(crate) fn shell_cache_get(key: &str) -> Option<bool> {
    let now = shell_now();
    let mut m = shell_cache().lock().unwrap_or_else(|p| p.into_inner());
    // Opportunistically drop stale entries so the map can't grow unbounded.
    m.retain(|_, (_, ts)| now.saturating_sub(*ts) <= SHELL_CACHE_TTL_SECS);
    m.get(key).map(|(v, _)| *v)
}

/// Record a `has_shell` result for `key`.
pub(crate) fn shell_cache_put(key: &str, has: bool) {
    shell_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(key.to_string(), (has, shell_now()));
}

/// Probe whether a running container has a usable `/bin/sh` (so the terminal
/// button is only shown when an interactive shell can actually be opened).
pub(crate) async fn container_has_shell(dkr: &Docker, id: &str) -> bool {
    let exec = dkr
        .create_exec(
            id,
            bollard::exec::CreateExecOptions {
                cmd: Some(vec![
                    "/bin/sh",
                    "-c",
                    "for s in /bin/bash /bin/sh /bin/ash; do [ -x \"$s\" ] && exit 0; done; exit 1",
                ]),
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                ..Default::default()
            },
        )
        .await;
    let exec = match exec {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Start it detached, then inspect the exit code.
    if dkr
        .start_exec(
            &exec.id,
            Some(bollard::exec::StartExecOptions {
                detach: true,
                ..Default::default()
            }),
        )
        .await
        .is_err()
    {
        return false;
    }
    // Give it a brief moment, then check the exit code.
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(inspect) = dkr.inspect_exec(&exec.id).await {
            if let Some(running) = inspect.running {
                if running {
                    continue;
                }
            }
            return inspect.exit_code == Some(0);
        }
    }
    false
}

/// Inspect one container for the detail page: identity, state, restart policy,
/// created time, and shell availability.
/// Whether a running container is privileged or shares the host network/PID
/// namespace — i.e. a `docker exec` into it grants effective host root. Used to
/// gate the container terminal / exec on the super-admin (mirrors the super-only
/// create guardrail). Inspect failure is treated as "privileged" (fail closed):
/// if we can't prove a container is safe, don't expose it to a non-super admin.
pub(crate) async fn container_is_privileged(reference: &str) -> bool {
    let dkr = match dkr() {
        Ok(d) => d,
        Err(_) => return true,
    };
    let c = match dkr.inspect_container(reference, None).await {
        Ok(c) => c,
        Err(_) => return true,
    };
    let Some(h) = c.host_config.as_ref() else {
        return true;
    };
    if h.privileged.unwrap_or(false) {
        return true;
    }
    // Host/container network namespace (host-net shares the host's stack).
    if let Some(mode) = h.network_mode.as_deref() {
        if crate::domain::docker::network_mode_privileged(mode) {
            return true;
        }
    }
    // Host PID namespace = visibility/signal reach into host processes.
    if h.pid_mode.as_deref() == Some("host") {
        return true;
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_cache_roundtrip_and_miss() {
        let key = format!("dn7-test-img-{}", std::process::id());
        // Miss before insert.
        assert_eq!(shell_cache_get(&key), None);
        // Hit after insert.
        shell_cache_put(&key, true);
        assert_eq!(shell_cache_get(&key), Some(true));
        // Overwrite with a different value.
        shell_cache_put(&key, false);
        assert_eq!(shell_cache_get(&key), Some(false));
    }
}
