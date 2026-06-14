//! Image listing, tagging, in-use guards (split from docker.rs).
use super::*;

pub(crate) fn split_repo_tag(s: &str) -> (String, String) {
    if let Some(colon) = s.rfind(':') {
        let after_last_slash = s.rfind('/').map(|sl| colon > sl).unwrap_or(true);
        if after_last_slash {
            return (s[..colon].to_string(), s[colon + 1..].to_string());
        }
    }
    (s.to_string(), "latest".to_string())
}

/// Add one or more new repo:tag references to an existing image (docker tag).
pub(crate) async fn add_image_tags(req: &Req) -> Result<Value> {
    let src = need_ref(req)?;
    let tags: Vec<String> = req
        .tags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if tags.is_empty() {
        return Err(anyhow!("ERR_CODE:docker.tag_empty"));
    }
    if tags.len() > 20 {
        return Err(anyhow!("ERR_CODE:docker.too_many_tags"));
    }
    let dkr = dkr()?;
    for t in &tags {
        if validate_token(t).is_err() {
            return Err(anyhow!("ERR_CODE:docker.bad_tag"));
        }
        let (repo, tag) = split_repo_tag(t);
        dkr.tag_image(
            &src,
            Some(bollard::image::TagImageOptions::<String> { repo, tag }),
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    Ok(json!({ "tagged": src, "count": tags.len() }))
}

/// Reconcile an image's tags to a desired set: add the new ones (docker tag),
/// then untag the removed ones (docker rmi <repo:tag>, force=false). Adds run
/// first so the image always keeps at least one tag while old ones are dropped.
pub(crate) async fn retag_image(req: &Req) -> Result<Value> {
    let reference = need_ref(req)?;
    if managed_image_guard(&reference).await {
        return Err(anyhow!("ERR_CODE:docker.image_in_use_builtin"));
    }
    let mut desired: Vec<String> = req
        .tags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    desired.dedup();
    if desired.is_empty() {
        return Err(anyhow!("ERR_CODE:docker.tag_empty"));
    }
    if desired.len() > 20 {
        return Err(anyhow!("ERR_CODE:docker.too_many_tags"));
    }
    for t in &desired {
        if validate_token(t).is_err() {
            return Err(anyhow!("ERR_CODE:docker.bad_tag"));
        }
    }
    let dkr = dkr()?;
    let info = dkr
        .inspect_image(&reference)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let current: Vec<String> = info
        .repo_tags
        .unwrap_or_default()
        .into_iter()
        .filter(|t| t != "<none>:<none>")
        .collect();
    let add: Vec<&String> = desired.iter().filter(|t| !current.contains(t)).collect();
    let remove: Vec<&String> = current.iter().filter(|t| !desired.contains(t)).collect();

    for t in &add {
        let (repo, tag) = split_repo_tag(t);
        dkr.tag_image(
            &reference,
            Some(bollard::image::TagImageOptions::<String> { repo, tag }),
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    for t in &remove {
        let opts = bollard::image::RemoveImageOptions {
            force: false,
            noprune: false,
        };
        dkr.remove_image(t, Some(opts), None)
            .await
            .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    Ok(json!({ "added": add.len(), "removed": remove.len() }))
}

pub(crate) async fn list_images() -> Result<Value> {
    let dkr = dkr()?;
    // Determine which images are used by DN7 Panel-managed service containers
    // (nginx / mysql) so the UI can mark them "内置" and the panel can refuse
    // to remove them.
    let managed_images = managed_image_refs(&dkr).await;
    let used_images = all_used_image_refs(&dkr).await;
    let opts = bollard::image::ListImagesOptions::<String> {
        all: false,
        ..Default::default()
    };
    let images = dkr
        .list_images(Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut items = Vec::new();
    for img in images {
        let short_id = img
            .id
            .strip_prefix("sha256:")
            .unwrap_or(&img.id)
            .chars()
            .take(12)
            .collect::<String>();
        // Prefer the first non-<none> repo tag; fall back to the short id.
        let tags: Vec<String> = img
            .repo_tags
            .into_iter()
            .filter(|t| t != "<none>:<none>")
            .collect();
        let (name, repo, tag) = if let Some(t) = tags.first() {
            let mut sp = t.rsplitn(2, ':');
            let tg = sp.next().unwrap_or("latest").to_string();
            let rp = sp.next().unwrap_or(t).to_string();
            (t.clone(), rp, tg)
        } else {
            (short_id.clone(), "<none>".to_string(), "<none>".to_string())
        };
        items.push(json!({
            "id": short_id,
            "name": name,
            "tags": tags,
            "repo": repo,
            "tag": tag,
            "size": human_size(img.size.max(0) as u64),
            "created": human_since(img.created),
            "created_ts": img.created,
            "managed": managed_images.contains(&name) || managed_images.contains(&short_id),
            "in_use": used_images.contains(&name) || used_images.contains(&short_id),
        }));
    }
    Ok(json!({ "images": items }))
}

/// The set of image refs (repo:tag) + short ids used by DN7 Panel-managed service
/// containers (nginx / mysql). Used to mark those images "内置" and protect
/// them from removal.
pub(crate) async fn managed_image_refs(dkr: &Docker) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = match dkr.list_containers(Some(opts)).await {
        Ok(c) => c,
        Err(_) => return out,
    };
    for c in containers {
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let has_mysql_label = c
            .labels
            .as_ref()
            .map(|l| l.contains_key("dn7.mysql"))
            .unwrap_or(false);
        let managed = name == crate::mysql::CONTAINER || has_mysql_label;
        if managed {
            if let Some(image) = c.image.clone() {
                out.insert(image);
            }
            if let Some(iid) = c.image_id.clone() {
                let short = iid
                    .strip_prefix("sha256:")
                    .unwrap_or(&iid)
                    .chars()
                    .take(12)
                    .collect::<String>();
                out.insert(short);
            }
        }
    }
    out
}

/// The set of image refs (repo:tag) + short ids used by ANY container (running
/// or stopped). Drives the image "in use" status badge.
pub(crate) async fn all_used_image_refs(dkr: &Docker) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = match dkr.list_containers(Some(opts)).await {
        Ok(c) => c,
        Err(_) => return out,
    };
    for c in containers {
        if let Some(image) = c.image.clone() {
            out.insert(image);
        }
        if let Some(iid) = c.image_id.clone() {
            let short = iid
                .strip_prefix("sha256:")
                .unwrap_or(&iid)
                .chars()
                .take(12)
                .collect::<String>();
            out.insert(short);
        }
    }
    out
}

/// If `reference` (a repo:tag or short id) is used by any container (running or
/// stopped), return that container's name so an image removal can be refused
/// with a helpful message instead of leaving a dangling/forced delete.
pub(crate) async fn image_in_use_guard(reference: &str) -> Option<String> {
    let dkr = dkr().ok()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr.list_containers(Some(opts)).await.ok()?;
    let want_short = reference
        .strip_prefix("sha256:")
        .unwrap_or(reference)
        .chars()
        .take(12)
        .collect::<String>();
    for c in containers {
        let img = c.image.clone().unwrap_or_default();
        let iid_short = c
            .image_id
            .as_deref()
            .map(|i| {
                i.strip_prefix("sha256:")
                    .unwrap_or(i)
                    .chars()
                    .take(12)
                    .collect::<String>()
            })
            .unwrap_or_default();
        if img == reference || (!want_short.is_empty() && iid_short == want_short) {
            return Some(
                c.names
                    .as_ref()
                    .and_then(|n| n.first())
                    .map(|s| s.trim_start_matches('/').to_string())
                    .unwrap_or_default(),
            );
        }
    }
    None
}

/// Format a byte count like docker's human sizes (e.g. "12.3MB").
pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

/// Format a unix-timestamp "created" into a relative "x天前/小时前" hint.
pub(crate) fn human_since(created_secs: i64) -> String {
    if created_secs <= 0 {
        return String::new();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let diff = (now - created_secs).max(0);
    if diff < 3600 {
        format!("{}分钟前", (diff / 60).max(1))
    } else if diff < 86400 {
        format!("{}小时前", diff / 3600)
    } else {
        format!("{}天前", diff / 86400)
    }
}

/// Suggest immediate subdirectories of a (partial) absolute host path, for the
/// volumes-tab host-path autocomplete. Splits the input into a parent directory
/// and a leaf prefix, enumerates the parent's subdirectories that match the
/// prefix (hidden dirs excluded), and returns up to 50 full paths. Never errors:
/// on any bad/inaccessible path it simply returns an empty list.
pub(crate) fn list_dir_suggest(req: &Req) -> Result<Value> {
    let input = req.path.as_deref().unwrap_or("/").trim().to_string();
    // Determine the directory to scan and the leaf prefix to match.
    let (dir, prefix): (String, String) = if input.is_empty() {
        ("/".into(), String::new())
    } else if input.ends_with('/') {
        (input.clone(), String::new())
    } else {
        match input.rfind('/') {
            Some(0) => ("/".into(), input[1..].to_string()),
            Some(i) => (input[..i].to_string(), input[i + 1..].to_string()),
            None => ("/".into(), String::new()),
        }
    };
    let mut out: Vec<String> = Vec::new();
    if dir.starts_with('/') {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for ent in rd.flatten() {
                if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = ent.file_name().to_str() {
                        if name.starts_with('.') {
                            continue;
                        }
                        if !prefix.is_empty() && !name.starts_with(&prefix) {
                            continue;
                        }
                        let full = if dir.ends_with('/') {
                            format!("{dir}{name}")
                        } else {
                            format!("{dir}/{name}")
                        };
                        out.push(full);
                    }
                }
            }
        }
    }
    out.sort();
    out.truncate(50);
    Ok(json!({ "dirs": out }))
}
