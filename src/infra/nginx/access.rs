//! Access lists + default-site settings (split from nginx.rs).
use super::*;

mod default_site;
mod upstream;
pub(crate) use default_site::*;
pub(crate) use upstream::*;

// Access lists: list / create-or-update / delete, plus default-site settings.
// ---------------------------------------------------------------------------

/// server_names of sites currently using each access list id.
pub(crate) fn sites_using_access() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for s in load_sites() {
        if !s.access_id.is_empty() {
            map.entry(s.access_id).or_default().push(s.server_name);
        }
    }
    map
}

/// List access lists (without password hashes), with usage info.
pub(crate) async fn list_access() -> Result<Value> {
    let lists = load_access();
    let in_use = sites_using_access();
    let out: Vec<Value> = lists
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "name": a.name,
                "satisfy": if a.satisfy == "all" { "all" } else { "any" },
                "pass_auth": a.pass_auth,
                "users": a.users.iter().map(|u| json!({ "username": u.username })).collect::<Vec<_>>(),
                "clients": a.clients,
                "used_by": in_use.get(&a.id).cloned().unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({ "access": out }))
}

/// Create (no access_id) or update (existing access_id) an access list.
pub(crate) async fn save_access_op(cmd: &SaveAccess) -> Result<Value> {
    let _state = state_lock().lock().await; // serialize access RMW (no lost update)
    let _ = layout()?; // require setup
    let name = cmd
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_access_name"))?
        .to_string();
    if !valid_access_name(&name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_access_name"));
    }
    let satisfy = match cmd.satisfy.as_deref().unwrap_or("any") {
        "all" => "all",
        _ => "any",
    }
    .to_string();
    let pass_auth = cmd.pass_auth.unwrap_or(false);

    // Validate clients.
    let clients = build_access_clients(cmd)?;

    let mut lists = load_access();
    let existing_id = cmd
        .access_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let old = existing_id
        .as_ref()
        .and_then(|id| lists.iter().find(|a| &a.id == id).cloned());

    // Build the user list: a provided password (re)hashes; an empty password on
    // an existing username reuses the stored hash.
    let users = build_access_users(cmd, old.as_ref())?;

    let id = existing_id.clone().unwrap_or_else(new_access_id);
    let list = AccessList {
        id: id.clone(),
        name,
        satisfy,
        pass_auth,
        users,
        clients,
    };
    write_htpasswd(&list)?;
    // Persist into the manifest (replace or append).
    lists.retain(|a| a.id != id);
    lists.push(list);
    save_access(&lists)?;

    // Rewrite the confs of any sites using this list, then reload.
    rewrite_sites_using_access(&id).await?;
    Ok(json!({ "id": id }))
}

/// Validate the access list's IP allow/deny client rules from the request.
fn build_access_clients(cmd: &SaveAccess) -> Result<Vec<AccessClient>> {
    let mut clients = Vec::new();
    for c in cmd.clients.clone().unwrap_or_default() {
        let dir = if c.directive == "deny" {
            "deny"
        } else {
            "allow"
        };
        if !valid_client_address(&c.address) {
            return Err(anyhow!("ERR_CODE:nginx.bad_client_addr"));
        }
        clients.push(AccessClient {
            directive: dir.to_string(),
            address: c.address.trim().to_string(),
        });
    }
    Ok(clients)
}

/// Build the access list's basic-auth users: a provided password (re)hashes;
/// an empty password on an existing username reuses its stored hash (`old`).
fn build_access_users(cmd: &SaveAccess, old: Option<&AccessList>) -> Result<Vec<AccessUser>> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for u in cmd.users.clone().unwrap_or_default() {
        let username = u.username.trim().to_string();
        if username.is_empty() {
            continue;
        }
        if !valid_auth_username(&username) {
            return Err(anyhow!("ERR_CODE:nginx.bad_auth_user"));
        }
        if !seen.insert(username.clone()) {
            return Err(anyhow!("ERR_CODE:nginx.dup_auth_user"));
        }
        let hash = if !u.password.is_empty() {
            if u.password.len() > 128 {
                return Err(anyhow!("ERR_CODE:nginx.bad_auth_pw"));
            }
            htpasswd_hash(&u.password)
        } else {
            old.and_then(|o| o.users.iter().find(|x| x.username == username))
                .map(|x| x.hash.clone())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_auth_pw"))?
        };
        users.push(AccessUser { username, hash });
    }
    Ok(users)
}

/// Delete an access list (refused while a site still uses it).
pub(crate) async fn delete_access_op(cmd: &DeleteAccess) -> Result<Value> {
    let _state = state_lock().lock().await; // serialize access RMW (no lost update)
    let id = cmd
        .access_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_access_id"))?;
    let in_use = sites_using_access();
    if let Some(sites) = in_use.get(id) {
        if !sites.is_empty() {
            return Err(anyhow!("访问列表仍被站点使用：{}", sites.join("、")));
        }
    }
    let mut lists = load_access();
    let before = lists.len();
    lists.retain(|a| a.id != id);
    if lists.len() == before {
        return Err(anyhow!("ERR_CODE:nginx.access_not_found"));
    }
    save_access(&lists)?;
    let _ = std::fs::remove_file(htpasswd_path(id));
    let _ = std::fs::remove_file(access_dir().join(format!("{id}.htpasswd")));
    Ok(json!({ "deleted": id }))
}

/// Rewrite + reload the confs of every site referencing `access_id`.
pub(crate) async fn rewrite_sites_using_access(access_id: &str) -> Result<()> {
    let lo = layout()?;
    let mut touched = false;
    for site in load_sites() {
        if site.access_id == access_id {
            // Skip SSL sites whose cert is missing (keeps nginx -t valid).
            let mut s = site.clone();
            if s.ssl {
                let have = if s.cert_name.is_empty() {
                    lo.cert_store.join(format!("{}.crt", s.id)).exists()
                } else {
                    named_crt_file(&lo, &s.cert_name).exists()
                };
                if !have {
                    s.ssl = false;
                }
            }
            if let Err(e) = write_site_conf(&lo, &s, &[]).await {
                tracing::warn!(site = %s.server_name, "access rewrite failed: {e}");
            } else {
                touched = true;
            }
        }
    }
    if touched {
        validate_and_reload(&lo).await?;
    }
    Ok(())
}

/// Current persisted http/server tuning (or defaults) — read accessor for the
/// `app::nginx` `set_tuning` use-case.
pub(crate) fn current_tuning() -> HttpTuning {
    load_tuning_opt().unwrap_or_default()
}

/// Persist already-validated tuning and re-apply it (rewrite all managed site
/// confs + the http include), then reload. The validation/merge is owned by
/// `domain::nginx::merge_http_tuning`; this is the side-effecting adapter.
pub(crate) async fn apply_tuning(t: &HttpTuning) -> Result<Value> {
    let lo = layout()?;
    save_tuning(t)?;
    write_tuning_conf();
    // Tuning is injected per-server, so rewrite every managed site conf.
    rewrite_managed_site_confs(&lo).await;
    validate_and_reload(&lo).await?;
    Ok(json!({ "ok": true }))
}

/// Rewrite every managed site's conf (e.g. after a tuning change, which is
/// injected per-server). An SSL site whose cert file is missing is degraded to
/// plain HTTP so one broken site can't fail the whole reload.
async fn rewrite_managed_site_confs(lo: &Layout) {
    for site in load_sites() {
        let mut s = site.clone();
        if s.ssl {
            let have = if s.cert_name.is_empty() {
                lo.cert_store.join(format!("{}.crt", s.id)).exists()
            } else {
                named_crt_file(lo, &s.cert_name).exists()
            };
            if !have {
                s.ssl = false;
            }
        }
        let _ = write_site_conf(lo, &s, &[]).await;
    }
}
