//! Access-list CRUD (auth users + IP rules) and the http/server tuning apply
//! adapters used by the app-layer nginx use-cases.
use super::*;

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
        .ok_or_else(|| website_err(WebsiteError::NeedAccessName))?
        .to_string();
    if !valid_access_name(&name) {
        return Err(website_err(WebsiteError::BadAccessName));
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
    // Persist into the manifest (replace or append). The edge reads the basic-auth
    // hashes from the AccessList model directly — no htpasswd files.
    lists.retain(|a| a.id != id);
    lists.push(list);
    save_access(&lists)?;

    // Rebuild the edge route table so the updated access list takes effect.
    validate_and_reload(&layout()?).await?;
    Ok(json!({ "id": id }))
}

/// Validate the access list's IP allow/deny client rules from the request. The
/// directive is a strict enum — only the exact `allow`/`deny` tokens are
/// accepted; anything else is rejected rather than silently treated as `allow`
/// (which would have quietly widened access on a typo'd directive).
fn build_access_clients(cmd: &SaveAccess) -> Result<Vec<AccessClient>> {
    let mut clients = Vec::new();
    for c in cmd.clients.clone().unwrap_or_default() {
        let dir = match c.directive.trim() {
            "allow" => "allow",
            "deny" => "deny",
            _ => return Err(website_err(WebsiteError::BadClientAddr)),
        };
        if !valid_client_address(&c.address) {
            return Err(website_err(WebsiteError::BadClientAddr));
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
            return Err(website_err(WebsiteError::BadAuthUser));
        }
        if !seen.insert(username.clone()) {
            return Err(website_err(WebsiteError::DupAuthUser));
        }
        let hash = if !u.password.is_empty() {
            if u.password.len() > 128 {
                return Err(website_err(WebsiteError::BadAuthPw));
            }
            dn7_edge::htpasswd_hash(&u.password)
        } else {
            old.and_then(|o| o.users.iter().find(|x| x.username == username))
                .map(|x| x.hash.clone())
                .ok_or_else(|| website_err(WebsiteError::NeedAuthPw))?
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
        .ok_or_else(|| website_err(WebsiteError::MissingAccessId))?;
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
        return Err(website_err(WebsiteError::AccessNotFound));
    }
    save_access(&lists)?;
    // The access list is gone from the manifest; rebuild the edge route table so
    // any site that referenced it (none, since deletion is refused while in use)
    // and the live config reflect it.
    let _ = validate_and_reload(&layout()?).await;
    Ok(json!({ "deleted": id }))
}

/// Current persisted http/server tuning (or defaults) — read accessor for the
/// `app::website` `set_tuning` use-case.
pub(crate) fn current_tuning() -> HttpTuning {
    load_tuning_opt().unwrap_or_default()
}

/// Persist already-validated tuning and rebuild the edge route table from it.
/// The validation/merge is owned by `core::website::merge_http_tuning`; this is
/// the side-effecting adapter. The edge applies tuning from the manifest at
/// build time, so persisting + reloading is all that's needed.
pub(crate) async fn apply_tuning(t: &HttpTuning) -> Result<Value> {
    let lo = layout()?;
    save_tuning(t)?;
    validate_and_reload(&lo).await?;
    Ok(json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd_with(clients: Vec<AccessClient>) -> SaveAccess {
        SaveAccess {
            clients: Some(clients),
            ..Default::default()
        }
    }

    fn client(directive: &str, address: &str) -> AccessClient {
        AccessClient {
            directive: directive.to_string(),
            address: address.to_string(),
        }
    }

    #[test]
    fn client_rules_accept_only_exact_allow_deny() {
        // Valid directive + valid address round-trips (address is trimmed).
        let out = build_access_clients(&cmd_with(vec![
            client("allow", "10.0.0.0/8"),
            client("deny", " 1.2.3.4 "),
        ]))
        .expect("valid allow/deny rules");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].directive, "allow");
        assert_eq!(out[1].directive, "deny");
        assert_eq!(out[1].address, "1.2.3.4"); // trimmed on save

        // A non-allow/deny directive is rejected, not silently widened to allow.
        assert!(build_access_clients(&cmd_with(vec![client("permit", "all")])).is_err());
        assert!(build_access_clients(&cmd_with(vec![client("", "all")])).is_err());
        assert!(build_access_clients(&cmd_with(vec![client("ALLOW", "all")])).is_err());

        // A bad address is rejected even with a valid directive.
        assert!(build_access_clients(&cmd_with(vec![client("allow", "999.999.999.999")])).is_err());
        assert!(build_access_clients(&cmd_with(vec![client("deny", "10.0.0.0/33")])).is_err());
    }
}
