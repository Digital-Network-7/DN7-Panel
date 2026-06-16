//! MySQL instance lifecycle: install, remove, change_port, switch_version (split from mysql.rs).
use super::*;

mod databases;
mod lifecycle;
pub(crate) use databases::*;
pub(crate) use lifecycle::*;

// ---------------------------------------------------------------------------
// install (detached): pull image, create data volume, create + start container.
// ---------------------------------------------------------------------------

pub(crate) fn validate_port(port: i64) -> Result<()> {
    if !(1..=65535).contains(&port) {
        return Err(mysql_err(MysqlError::PortRange));
    }
    Ok(())
}

/// Start a detached install op. Returns `{op_id}` immediately.
pub(crate) fn start_install(req: &Req) -> Result<Value> {
    // Single-instance: refuse if one already exists (the user manages multiple
    // databases inside it, not multiple instances).
    if load_manifest(INSTANCE_ID).is_ok() {
        return Err(mysql_err(MysqlError::InstanceExists));
    }
    let spec = parse_install_req(req)?;

    let inst_id = spec.inst_id.clone();
    let op_id = new_op_id();
    op_create(&op_id, "install", &inst_id);

    let op_t = op_id.clone();
    let inst_t = inst_id.clone();
    tokio::spawn(async move {
        match run_install_detached(&op_t, spec).await {
            Ok(()) => op_finish(&op_t, "done", "", &inst_t),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": inst_id }))
}

/// Validate an install request into an `InstallSpec` (engine/version/port +
/// admin account name and optional explicit password).
fn parse_install_req(req: &Req) -> Result<InstallSpec> {
    let engine = req
        .engine
        .as_deref()
        .map(str::trim)
        .unwrap_or("mysql")
        .to_string();
    if !valid_engine(&engine) {
        return Err(mysql_err(MysqlError::BadEngine));
    }
    let version = req
        .version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("8.0")
        .to_string();
    if !valid_version(&engine, &version) {
        return Err(mysql_err(MysqlError::BadVersion));
    }
    let port = if req.expose.unwrap_or(false) {
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
        return Err(mysql_err(MysqlError::UserNameRules));
    }
    let password = match req.password.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => {
            if p.len() < 6 || p.len() > 128 {
                return Err(mysql_err(MysqlError::BadPassword));
            }
            Some(p.to_string())
        }
        _ => None,
    };

    Ok(InstallSpec {
        engine,
        version,
        port,
        inst_id: INSTANCE_ID.to_string(),
        password,
        admin_user,
    })
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
    let root_enc = crate::infra::crypto::encrypt(&password);

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
                // Bind the published port to loopback, not 0.0.0.0 — a managed
                // database should be reachable from the host (and SSH tunnels),
                // not exposed to the whole network by default. (Safe default per
                // the capability-guardrail rules.)
                host_ip: Some("127.0.0.1".to_string()),
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
