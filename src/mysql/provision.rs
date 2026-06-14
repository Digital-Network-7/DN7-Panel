//! MySQL instance lifecycle: install, remove, change_port, switch_version (split from mysql.rs).
use super::*;

// ---------------------------------------------------------------------------
// install (detached): pull image, create data volume, create + start container.
// ---------------------------------------------------------------------------

pub(crate) fn validate_port(port: i64) -> Result<()> {
    if !(1..=65535).contains(&port) {
        return Err(anyhow!("ERR_CODE:mysql.port_range"));
    }
    Ok(())
}

/// Start a detached install op. Returns `{op_id}` immediately.
pub(crate) fn start_install(req: &Req) -> Result<Value> {
    let engine = req
        .engine
        .as_deref()
        .map(str::trim)
        .unwrap_or("mysql")
        .to_string();
    if !valid_engine(&engine) {
        return Err(anyhow!("ERR_CODE:mysql.bad_engine"));
    }
    let version = req
        .version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("8.0")
        .to_string();
    if !valid_version(&engine, &version) {
        return Err(anyhow!("ERR_CODE:mysql.bad_version"));
    }
    let expose = req.expose.unwrap_or(false);
    let port = if expose {
        let p = req.port.unwrap_or(3306);
        validate_port(p)?;
        Some(p)
    } else {
        None
    };

    // Admin account name (default root) + optional explicit password.
    let admin_user = req
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("root")
        .to_string();
    if admin_user != "root" && !valid_ident(&admin_user, false) {
        return Err(anyhow!("ERR_CODE:mysql.user_name_rules"));
    }
    let password = match req.password.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => {
            if p.len() < 6 || p.len() > 128 {
                return Err(anyhow!("ERR_CODE:mysql.bad_password"));
            }
            Some(p.to_string())
        }
        _ => None,
    };

    // Single-instance: refuse if one already exists (the user manages multiple
    // databases inside it, not multiple instances).
    if load_manifest(INSTANCE_ID).is_ok() {
        return Err(anyhow!("ERR_CODE:mysql.instance_exists"));
    }

    let inst_id = INSTANCE_ID.to_string();
    let op_id = new_op_id();
    op_create(&op_id, "install", &inst_id);

    let op_t = op_id.clone();
    let inst_t = inst_id.clone();
    let spec = InstallSpec {
        engine,
        version,
        port,
        inst_id: inst_id.clone(),
        password,
        admin_user,
    };
    tokio::spawn(async move {
        match run_install_detached(&op_t, spec).await {
            Ok(()) => op_finish(&op_t, "done", "", &inst_t),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": inst_id }))
}

/// Parameters for a detached MySQL/MariaDB install (bundled to keep the
/// argument count sane).
pub(crate) struct InstallSpec {
    engine: String,
    version: String,
    port: Option<i64>,
    inst_id: String,
    password: Option<String>,
    admin_user: String,
}

/// Pull the image (streaming progress), create the data volume, then create and
/// start the container with a generated root password. Writes the manifest on
/// success so the instance is tracked even across restarts.
pub(crate) async fn run_install_detached(op_id: &str, spec: InstallSpec) -> Result<()> {
    let InstallSpec {
        engine,
        version,
        port,
        inst_id,
        password,
        admin_user,
    } = spec;
    let dkr = dkr()?;
    let image = image_ref(&engine, &version);

    // 0. If exposing a host port, fail fast when it's already published by
    // another container (a clearer error than Docker's late "port is allocated").
    if let Some(p) = port {
        if let Some(owner) = host_port_owner(&dkr, p).await {
            return Err(anyhow!(
                "宿主机端口 {p} 已被容器 {owner} 占用，请换一个端口"
            ));
        }
    }

    // 1. Pull the image (stream status lines into the op log).
    op_push(op_id, &pmsg("my.pulling", &[image.as_str()]));
    pull_image(&dkr, &image, op_id).await?;

    // 2. Create a named data volume so the data survives container recreation.
    let volume = VOLUME.to_string();
    op_push(op_id, &pmsg("my.creating_volume", &[]));
    create_volume(&dkr, &volume, &inst_id, &engine).await?;

    // 3. Use the provided root password, or generate one; store encrypted.
    let password = password.unwrap_or_else(gen_password);
    let root_enc = crate::crypto::encrypt(&password);

    // 4. Create + start the container.
    let container = CONTAINER.to_string();
    op_push(op_id, &pmsg("my.creating_container", &[]));
    create_mysql_container(
        &dkr,
        &MysqlContainerSpec {
            container: &container,
            image: &image,
            engine: &engine,
            inst_id: &inst_id,
            volume: &volume,
            port,
            password: &password,
        },
    )
    .await?;
    op_push(op_id, &pmsg("my.starting", &[]));
    dkr.start_container(
        &container,
        None::<bollard::container::StartContainerOptions<String>>,
    )
    .await
    .map_err(|e| anyhow!(friendly(&e)))?;

    // 5. Persist the manifest first (now the instance is officially
    // DN7 Panel-managed and will show up in the list even while initializing).
    let m = Manifest {
        id: inst_id.clone(),
        engine: engine.clone(),
        version: version.clone(),
        container: container.clone(),
        volume,
        port,
        root_enc,
        created_at: now_secs(),
        admin_user: admin_user.clone(),
    };
    save_manifest(&m)?;

    // 6. Wait for mysqld to actually accept connections (data-dir init takes a
    // while on first run). The container is `running` almost immediately but
    // queries fail until this completes, so block the op until it's truly ready.
    op_push(op_id, &pmsg("my.waiting_ready", &[]));
    if wait_ready(&container, &password, op_id, 180).await {
        create_admin_user(&container, &password, &admin_user).await;
        op_push(op_id, &pmsg("my.install_done", &[]));
    } else {
        // Don't hard-fail: the container exists and may still come up. Surface
        // a clear hint so the user knows to check the container's state.
        op_push(op_id, &pmsg("my.init_timeout", &[]));
    }
    Ok(())
}

/// When the admin account isn't root, create it as a full-privilege user
/// sharing the same password (root stays the panel's internal superuser).
/// No-op for `root` or an invalid identifier.
async fn create_admin_user(container: &str, password: &str, admin_user: &str) {
    if admin_user == "root" || !valid_ident(admin_user, false) {
        return;
    }
    let esc_user = sql_escape(admin_user);
    let esc_pw = sql_escape(password);
    let create = format!("CREATE USER IF NOT EXISTS '{esc_user}'@'%' IDENTIFIED BY '{esc_pw}';");
    let grant = format!("GRANT ALL PRIVILEGES ON *.* TO '{esc_user}'@'%' WITH GRANT OPTION;");
    let _ = run_stmt(container, password, &create).await;
    let _ = run_stmt(container, password, &grant).await;
    let _ = run_stmt(container, password, "FLUSH PRIVILEGES;").await;
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Pull an image, pushing each progress status line into the op log.
pub(crate) async fn pull_image(dkr: &Docker, image: &str, op_id: &str) -> Result<()> {
    let opts = bollard::image::CreateImageOptions {
        from_image: image.to_string(),
        ..Default::default()
    };
    let mut stream = dkr.create_image(Some(opts), None, None);
    let mut last = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => {
                let line = info.status.unwrap_or_default();
                if !line.is_empty() && line != last {
                    op_push(op_id, &line);
                    last = line;
                }
            }
            Err(e) => return Err(anyhow!("拉取镜像失败：{}", friendly(&e))),
        }
    }
    Ok(())
}

/// True if a host TCP port is already published by an existing container.
/// Returns the owning container's name when occupied, else None.
pub(crate) async fn host_port_owner(dkr: &Docker, port: i64) -> Option<String> {
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr.list_containers(Some(opts)).await.ok()?;
    for c in containers {
        if let Some(ports) = &c.ports {
            for p in ports {
                if p.public_port == Some(port as u16) {
                    let name = c
                        .names
                        .as_ref()
                        .and_then(|n| n.first())
                        .map(|s| s.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| "未知".to_string());
                    return Some(name);
                }
            }
        }
    }
    None
}

/// Create a named volume tagged as DN7 Panel-managed.
pub(crate) async fn create_volume(
    dkr: &Docker,
    name: &str,
    inst_id: &str,
    engine: &str,
) -> Result<()> {
    let mut labels = HashMap::new();
    labels.insert(LABEL_MANAGED.to_string(), "1".to_string());
    labels.insert(LABEL_ID.to_string(), inst_id.to_string());
    labels.insert(LABEL_ENGINE.to_string(), engine.to_string());
    let opts = bollard::volume::CreateVolumeOptions {
        name: name.to_string(),
        labels,
        ..Default::default()
    };
    dkr.create_volume(opts)
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("创建数据卷失败：{}", friendly(&e)))
}

/// Create (not start) a MySQL/MariaDB container with the data volume mounted,
/// the root password set, DN7 Panel labels applied, and an optional host port
/// binding for 3306. All values are validated; nothing is passed to a shell.
#[allow(clippy::too_many_arguments)]
/// Parameters for creating the managed MySQL/MariaDB container (bundled to keep
/// the argument count sane; borrows live only for the create call).
pub(crate) struct MysqlContainerSpec<'a> {
    pub container: &'a str,
    pub image: &'a str,
    pub engine: &'a str,
    pub inst_id: &'a str,
    pub volume: &'a str,
    pub port: Option<i64>,
    pub password: &'a str,
}

pub(crate) async fn create_mysql_container(
    dkr: &Docker,
    spec: &MysqlContainerSpec<'_>,
) -> Result<()> {
    use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};

    // Root password env. MySQL reads MYSQL_ROOT_PASSWORD; MariaDB reads
    // MARIADB_ROOT_PASSWORD but also honors MYSQL_ROOT_PASSWORD — set both so
    // either engine initializes cleanly.
    let env = vec![
        format!("MYSQL_ROOT_PASSWORD={}", spec.password),
        format!("MARIADB_ROOT_PASSWORD={}", spec.password),
    ];

    // Mount the named volume at the data dir (same path for MySQL & MariaDB).
    let binds = vec![format!("{}:/var/lib/mysql", spec.volume)];

    // Optional host port -> container 3306/tcp.
    let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
    let mut bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    exposed.insert("3306/tcp".to_string(), HashMap::new());
    if let Some(p) = spec.port {
        bindings.insert(
            "3306/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: None,
                host_port: Some(p.to_string()),
            }]),
        );
    }

    let mut labels = HashMap::new();
    labels.insert(LABEL_MANAGED.to_string(), "1".to_string());
    labels.insert(LABEL_ID.to_string(), spec.inst_id.to_string());
    labels.insert(LABEL_ENGINE.to_string(), spec.engine.to_string());

    let host_config = HostConfig {
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        binds: Some(binds),
        port_bindings: if bindings.is_empty() {
            None
        } else {
            Some(bindings)
        },
        ..Default::default()
    };

    let config = bollard::container::Config {
        image: Some(spec.image.to_string()),
        env: Some(env),
        labels: Some(labels),
        exposed_ports: Some(exposed),
        host_config: Some(host_config),
        ..Default::default()
    };

    let options = Some(bollard::container::CreateContainerOptions {
        name: spec.container.to_string(),
        platform: None,
    });
    dkr.create_container(options, config)
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("创建容器失败：{}", friendly(&e)))
}

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
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
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
    let old = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
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
    m.root_enc = crate::crypto::encrypt(&new);
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

    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
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

    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
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

/// List databases with table count and on-disk size (from information_schema).
/// System schemas are flagged so the UI can de-emphasize them.
pub(crate) async fn databases(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();

    // Tab-separated output: schema \t tables \t bytes. ORDER keeps it stable.
    let sql = "SELECT s.schema_name, \
        (SELECT COUNT(*) FROM information_schema.tables t WHERE t.table_schema = s.schema_name) AS tbls, \
        COALESCE((SELECT SUM(data_length + index_length) FROM information_schema.tables t WHERE t.table_schema = s.schema_name),0) AS bytes \
        FROM information_schema.schemata s ORDER BY s.schema_name;";
    let (code, out) = mysql_exec_query(&m.container, &password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }

    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    let mut dbs = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let name = it.next().unwrap_or("").trim();
        if name.is_empty() || name == "schema_name" {
            continue; // skip a header row if the client emits one
        }
        let tables: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let bytes: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        dbs.push(json!({
            "name": name,
            "tables": tables,
            "bytes": bytes,
            "system": SYS.contains(&name),
        }));
    }
    Ok(json!({ "databases": dbs }))
}

/// Create a new (non-system) database/schema in the single instance.
pub(crate) async fn create_database(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.db_name_rules"));
    }
    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    if SYS.contains(&db) {
        return Err(anyhow!("ERR_CODE:mysql.reserved_db_name"));
    }
    // Character set + collation: validated as plain charset identifiers so they
    // can't break out of the statement. Invalid combos are rejected by the
    // server (surfaced as a friendly error). Defaults: utf8mb4 / unicode_ci.
    let charset = req
        .charset
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("utf8mb4");
    let collation = req
        .collation
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("utf8mb4_unicode_ci");
    if !valid_charset_name(charset) {
        return Err(anyhow!("ERR_CODE:mysql.bad_charset"));
    }
    if !valid_charset_name(collation) {
        return Err(anyhow!("ERR_CODE:mysql.bad_collation"));
    }
    // Backtick-quote the identifier; valid_ident already restricts the charset.
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET {} COLLATE {};",
        db, charset, collation
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "created": db }))
}

/// Drop a (non-system) database/schema.
pub(crate) async fn drop_database(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_db_name"));
    }
    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    if SYS.contains(&db) {
        return Err(anyhow!("ERR_CODE:mysql.no_drop_system_db"));
    }
    let sql = format!("DROP DATABASE `{}`;", db);
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "dropped": db }))
}
