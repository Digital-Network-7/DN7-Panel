//! Single-container lifecycle actions (start/stop/.../remove).
use super::*;

/// Simple single-container lifecycle ops (start/stop/restart/pause/unpause/
/// kill/remove) that share the shape: resolve ref, call one bollard method,
/// report the result. `kill`/`remove` also re-check the managed-container guard.
pub(crate) async fn container_action(req: &Req, action: &str) -> Result<Value> {
    use bollard::container::{KillContainerOptions, RemoveContainerOptions, StartContainerOptions};
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let verb: &str = match action {
        "start" => {
            dkr.start_container(&r, None::<StartContainerOptions<String>>)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "started"
        }
        "stop" => {
            dkr.stop_container(&r, None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "stopped"
        }
        "restart" => {
            dkr.restart_container(&r, None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "restarted"
        }
        "pause" => {
            dkr.pause_container(&r)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "paused"
        }
        "unpause" => {
            dkr.unpause_container(&r)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "resumed"
        }
        "kill" => {
            if let Some(why) = managed_container_guard(&r).await {
                return Err(anyhow!(why));
            }
            dkr.kill_container(&r, None::<KillContainerOptions<String>>)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "killed"
        }
        "remove" => {
            // Managed service containers must be removed from their own pages.
            if let Some(why) = managed_container_guard(&r).await {
                return Err(anyhow!(why));
            }
            let opts = RemoveContainerOptions {
                force: true,
                ..Default::default()
            };
            dkr.remove_container(&r, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            // A removed container may be the upstream of a `proxy_container`
            // website (proxy_container) site. Re-sync site confs so any now-dangling site fails
            // closed (503 stub) instead of proxying to a recycled IP.
            crate::infra::website::resync_after_container_change();
            "removed"
        }
        other => return Err(anyhow!("unsupported container action: {other}")),
    };
    let mut m = serde_json::Map::new();
    m.insert(verb.to_string(), Value::String(r));
    Ok(Value::Object(m))
}
