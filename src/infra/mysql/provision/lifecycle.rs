//! MySQL instance lifecycle: remove/credentials/reset, change_port, switch_version (split from provision.rs).
use super::*;

// ---------------------------------------------------------------------------
// remove / credentials / reset_password.
// ---------------------------------------------------------------------------

/// Remove an instance: force-remove the container, optionally delete the data
/// volume, then drop the manifest. `keep_data=true` preserves the volume.
pub(crate) async fn remove_instance(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let keep_data = req.keep_data.unwrap_or(false);
    let dkr = dkr()?;

    // Force-remove the container (ignore "no such container").
    let opts = bollard::container::RemoveContainerOptions {
        force: true,
        v: false, // we manage the named volume separately
        ..Default::default()
    };
    if let Err(e) = dkr.remove_container(&m.container, Some(opts)).await {
        let s = e.to_string();
        if !s.contains("No such container") && !s.contains("404") {
            return Err(anyhow!(friendly(&e)));
        }
    }

    if !keep_data {
        // Remove the named data volume (force).
        if let Err(e) = dkr
            .remove_volume(
                &m.volume,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await
        {
            let s = e.to_string();
            if !s.contains("No such volume") && !s.contains("404") {
                return Err(anyhow!("删除数据卷失败：{}", friendly(&e)));
            }
        }
    }

    delete_manifest(&m.id);
    Ok(json!({ "removed": m.id, "kept_data": keep_data }))
}

/// Return connection credentials (decrypted root password) for an instance.
pub(crate) async fn credentials(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = if m.admin_user.is_empty() {
        "root".to_string()
    } else {
        m.admin_user.clone()
    };
    Ok(json!({
        "host": "127.0.0.1",
        "port": m.port,
        "exposed": m.port.is_some(),
        "user": user,
        "password": password,
        "engine": m.engine,
        "version": m.version,
    }))
}

/// Reset the root password: generate a new one, apply it inside the running
/// container via the mysql client, then persist the new ciphertext.
pub(crate) async fn reset_password(req: &Req) -> Result<Value> {
    let mut m = load_manifest(need_inst(req)?)?;
    let old = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let new = gen_password();

    // ALTER USER over the local socket, authenticating with the current root
    // password. Values are passed as separate argv entries (no shell).
    let sql = format!(
        "ALTER USER 'root'@'localhost' IDENTIFIED BY '{}'; ALTER USER 'root'@'%' IDENTIFIED BY '{}'; FLUSH PRIVILEGES;",
        sql_escape(&new),
        sql_escape(&new)
    );
    let (code, out) = mysql_exec(&m.container, &old, &sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "重置密码失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    m.root_enc = crate::infra::crypto::encrypt(&new);
    save_manifest(&m)?;
    Ok(json!({ "password": new }))
}

/// Escape a value for safe inclusion inside a single-quoted SQL string literal.
/// Backslashes and single quotes are doubled/escaped. The password charset
/// already excludes quotes/backslashes, but we escape defensively.
pub(crate) fn sql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

// ---------------------------------------------------------------------------
// change_port / switch_version: recreate the container, reusing the data volume.
// ---------------------------------------------------------------------------

/// Change (or remove) the host port mapping. Recreates the container against
/// the same data volume and root password; the data is untouched.
pub(crate) async fn change_port(req: &Req) -> Result<Value> {
    let mut m = load_manifest(need_inst(req)?)?;
    let expose = req.expose.unwrap_or(false);
    let new_port = if expose {
        let p = req.port.unwrap_or(3306);
        validate_port(p)?;
        Some(p)
    } else {
        None
    };

    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let image = image_ref(&m.engine, &m.version);
    // Reject a host port already owned by a *different* container.
    if let Some(p) = new_port {
        let dkr = dkr()?;
        if let Some(owner) = host_port_owner(&dkr, p).await {
            if owner != m.container {
                return Err(anyhow!(
                    "宿主机端口 {p} 已被容器 {owner} 占用，请换一个端口"
                ));
            }
        }
    }
    recreate_container(&m, &image, new_port, &password).await?;
    m.port = new_port;
    save_manifest(&m)?;
    Ok(json!({ "id": m.id, "port": new_port, "exposed": new_port.is_some() }))
}

/// Remove + recreate the container with the same labels/volume/password but a
/// new port mapping. Used by change_port.
pub(crate) async fn recreate_container(
    m: &Manifest,
    image: &str,
    port: Option<i64>,
    password: &str,
) -> Result<()> {
    let dkr = dkr()?;
    let opts = bollard::container::RemoveContainerOptions {
        force: true,
        v: false,
        ..Default::default()
    };
    if let Err(e) = dkr.remove_container(&m.container, Some(opts)).await {
        let s = e.to_string();
        if !s.contains("No such container") && !s.contains("404") {
            return Err(anyhow!(friendly(&e)));
        }
    }
    create_mysql_container(
        &dkr,
        &MysqlContainerSpec {
            container: &m.container,
            image,
            engine: &m.engine,
            inst_id: &m.id,
            volume: &m.volume,
            port,
            password,
        },
    )
    .await?;
    dkr.start_container(
        &m.container,
        None::<bollard::container::StartContainerOptions<String>>,
    )
    .await
    .map_err(|e| anyhow!(friendly(&e)))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// switch_version: change engine and/or version, recreating the container
// against the SAME data volume (detached so the image pull can stream). The
// data dir is reused — major upgrades or engine swaps may be incompatible, so
// the UI warns the user and recommends a backup first.
// ---------------------------------------------------------------------------

/// Start a detached engine/version switch. Returns `{op_id}` immediately.
pub(crate) fn start_switch(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let engine = req
        .engine
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&m.engine)
        .to_string();
    if !valid_engine(&engine) {
        return Err(anyhow!("ERR_CODE:mysql.bad_engine"));
    }
    let version = req
        .version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:mysql.bad_version"))?
        .to_string();
    if !valid_version(&engine, &version) {
        return Err(anyhow!("ERR_CODE:mysql.bad_version"));
    }
    if engine == m.engine && version == m.version {
        return Err(anyhow!("ERR_CODE:mysql.same_version"));
    }

    let op_id = new_op_id();
    op_create(&op_id, "switch", &m.id);
    let op_t = op_id.clone();
    tokio::spawn(async move {
        match run_switch_detached(&op_t, m, &engine, &version).await {
            Ok(()) => op_finish(&op_t, "done", "", INSTANCE_ID),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": INSTANCE_ID }))
}

/// Pull the new image, recreate the container on the same volume/password/port
/// with the new engine+version labels, then persist the updated manifest.
pub(crate) async fn run_switch_detached(
    op_id: &str,
    mut m: Manifest,
    engine: &str,
    version: &str,
) -> Result<()> {
    let dkr = dkr()?;
    let image = image_ref(engine, version);
    op_push(op_id, &pmsg("my.pulling", &[image.as_str()]));
    pull_image(&dkr, &image, op_id).await?;

    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    // Update engine/version on the manifest before recreate so the new
    // container carries the correct engine label.
    m.engine = engine.to_string();
    m.version = version.to_string();
    op_push(op_id, &pmsg("my.creating_container", &[]));
    recreate_container(&m, &image, m.port, &password).await?;
    save_manifest(&m)?;

    op_push(op_id, &pmsg("my.waiting_ready", &[]));
    if wait_ready(&m.container, &password, op_id, 180).await {
        op_push(op_id, &pmsg("my.install_done", &[]));
    } else {
        op_push(op_id, &pmsg("my.init_timeout", &[]));
    }
    Ok(())
}
