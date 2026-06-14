//! Detached image pull + registry/mirror gating (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// Detached pull
// ---------------------------------------------------------------------------

pub(crate) fn mirror_allowed(host: &str) -> bool {
    load_dk_settings().mirrors.iter().any(|m| m == host)
}

/// Whether `host` is a configured private registry (pull selector).
pub(crate) fn registry_allowed(host: &str) -> bool {
    load_dk_settings().registries.iter().any(|r| r == host)
}

/// Normalize a user image ref to its docker.io form for mirror prefixing.
pub(crate) fn docker_io_path(image: &str) -> Option<String> {
    let has_slash = image.contains('/');
    let first = image.split('/').next().unwrap_or("");
    let qualified =
        has_slash && (first.contains('.') || first.contains(':') || first == "localhost");
    if qualified {
        return None;
    }
    let with_tag = with_default_tag(image);
    if has_slash {
        Some(format!("docker.io/{with_tag}"))
    } else {
        Some(format!("docker.io/library/{with_tag}"))
    }
}

/// Ensure the final ref has a tag (defaults to :latest), for the rename step.
pub(crate) fn with_default_tag(image: &str) -> String {
    if image.contains('@') {
        return image.to_string();
    }
    let last_seg = image.rsplit('/').next().unwrap_or(image);
    if last_seg.contains(':') {
        image.to_string()
    } else {
        format!("{image}:latest")
    }
}

/// Validate + resolve the pull, register a detached op, spawn it, return op_id.
pub(crate) fn start_pull(req: &Req) -> Result<Value> {
    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    validate_token(&image)?;

    let mirror = req
        .mirror
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let registry = req
        .registry
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Decide the actual pull source and whether a rename is needed afterwards.
    let (pull_ref, final_ref) = if let Some(reg) = registry {
        // Private registry: pull `<registry>/<image>` verbatim (no Docker Hub
        // mirror applies). Validate against the configured list.
        if !registry_allowed(reg) {
            return Err(anyhow!("ERR_CODE:docker.bad_registry"));
        }
        (format!("{reg}/{}", with_default_tag(&image)), None)
    } else {
        match mirror {
            Some(host) => {
                if !mirror_allowed(host) {
                    return Err(anyhow!("ERR_CODE:docker.bad_mirror"));
                }
                match docker_io_path(&image) {
                    Some(path) => (format!("{host}/{path}"), Some(with_default_tag(&image))),
                    None => (image.clone(), None),
                }
            }
            None => (image.clone(), None),
        }
    };

    let shown = final_ref
        .clone()
        .unwrap_or_else(|| with_default_tag(&image));
    let op_id = new_op_id();
    op_create(&op_id, "pull", &shown);

    let op_id_t = op_id.clone();
    let shown_t = shown.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, &pmsg("dk.pulling", &[pull_ref.as_str()]));
        match run_pull_detached(&op_id_t, &pull_ref).await {
            Ok(()) => {
                if let Some(final_ref) = final_ref.as_deref() {
                    if final_ref != pull_ref {
                        op_push(&op_id_t, &pmsg("dk.renaming", &[final_ref]));
                        if let Err(e) = tag_image(&pull_ref, final_ref).await {
                            op_finish(&op_id_t, "error", &e.to_string(), "");
                            return;
                        }
                        let _ = remove_image_quiet(&pull_ref).await; // best-effort
                    }
                }
                op_push(&op_id_t, &pmsg("dk.done", &[]));
                op_finish(&op_id_t, "done", "", &shown_t);
            }
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });

    Ok(json!({ "op_id": op_id, "target": shown }))
}

/// Tag an image `source` as `target` (target = repo[:tag]).
pub(crate) async fn tag_image(source: &str, target: &str) -> Result<()> {
    let (repo, tag) = match target.rsplit_once(':') {
        // Avoid splitting on a registry-port colon when there's no real tag.
        Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
        _ => (target.to_string(), "latest".to_string()),
    };
    let opts = bollard::image::TagImageOptions { repo, tag };
    dkr()?
        .tag_image(source, Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))
}

/// Remove an image, ignoring errors (best-effort cleanup after a retag).
pub(crate) async fn remove_image_quiet(reference: &str) {
    if let Ok(dkr) = dkr() {
        let opts = bollard::image::RemoveImageOptions {
            force: true,
            ..Default::default()
        };
        let _ = dkr.remove_image(reference, Some(opts), None).await;
    }
}

/// Pull `pull_ref` via the daemon's create_image stream, pushing each progress
/// Pull `pull_ref` via the daemon's create_image stream, pushing each progress
/// status line into the op registry. Detects mid-stream errors (the daemon
/// reports a failed layer via the `error` field WITHOUT ending the stream as a
/// transport error) and verifies the image actually exists afterward, so a
/// failed pull (common on mainland networks without a mirror) never reports
/// success.
pub(crate) async fn run_pull_detached(op_id: &str, pull_ref: &str) -> Result<()> {
    let dkr = dkr()?;
    let opts = bollard::image::CreateImageOptions {
        from_image: pull_ref.to_string(),
        ..Default::default()
    };
    let mut stream = dkr.create_image(Some(opts), None, None);
    let mut last = String::new();
    let mut stream_error: Option<String> = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => {
                // The daemon signals a layer/pull failure inline via `error`
                // rather than closing the stream with a transport error.
                if let Some(err) = info.error {
                    let e = err.trim();
                    if !e.is_empty() {
                        op_push(op_id, &pmsg("dk.error", &[e]));
                        stream_error = Some(trim_msg(e).unwrap_or_else(|| "拉取失败".into()));
                        continue;
                    }
                }
                // Build a concise progress line: "<status> <progress>".
                let mut line = info.status.unwrap_or_default();
                if let Some(p) = info.progress {
                    if !p.is_empty() {
                        line.push(' ');
                        line.push_str(&p);
                    }
                }
                let line = line.trim().to_string();
                if !line.is_empty() && line != last {
                    op_push(op_id, &line);
                    last = line;
                }
            }
            Err(e) => return Err(anyhow!(friendly_docker_err(&e))),
        }
    }
    if let Some(err) = stream_error {
        return Err(anyhow!(err));
    }
    // Final verification: the image must actually exist now. The stream can end
    // without an explicit error even when nothing was pulled (e.g. a dropped
    // connection mid-transfer), so confirm before reporting success.
    dkr.inspect_image(pull_ref)
        .await
        .map_err(|_| anyhow!("ERR_CODE:docker.pull_incomplete"))?;
    Ok(())
}
