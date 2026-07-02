//! Container create/recreate execution (start_create + create_container) (split from create.rs).
use super::*;

/// Validate the request, register a detached op, create the container via the
/// daemon API, and (when requested) start it. Returns an op_id.
pub(crate) fn start_create(req: &Req) -> Result<Value> {
    let (spec, display_name) = build_create_spec(req)?;
    let target = if display_name.is_empty() {
        spec.image.clone()
    } else {
        display_name
    };

    let op_id = new_op_id();
    op_create(&op_id, "create", &target);

    let op_id_t = op_id.clone();
    let target_t = target.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, &pmsg("dk.creating_container", &[]));
        match create_container(spec).await {
            Ok((id, started)) => {
                let short = id.chars().take(12).collect::<String>();
                op_push(
                    &op_id_t,
                    &pmsg(
                        "dk.container_created",
                        &[
                            if started {
                                "@dklbl.created_started"
                            } else {
                                "@dklbl.created"
                            },
                            short.as_str(),
                        ],
                    ),
                );
                op_finish(&op_id_t, "done", "", &target_t);
            }
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });

    Ok(json!({ "op_id": op_id, "target": target }))
}

/// Create (and optionally start) a container via the daemon API. Returns the
/// new container id and whether it was started.
pub(crate) async fn create_container(spec: CreateSpec) -> Result<(String, bool)> {
    let dkr = dkr()?;
    // Edit/upgrade: remove the container being replaced first so the new one can
    // reuse its name. Managed service containers are never replaced this way.
    if let Some(old) = spec.replace.as_deref() {
        // Don't destroy the existing container until the new image is confirmed
        // present locally — otherwise an edit/upgrade to a missing or mistyped
        // image tag would leave the user with no container at all.
        dkr.inspect_image(&spec.image).await.map_err(|_| {
            anyhow!(
                "镜像「{}」在本地不存在，已保留原容器；请先拉取该镜像后再编辑/升级。",
                spec.image
            )
        })?;
        remove_replaced_container(&dkr, old).await?;
    }
    let options = spec
        .name
        .clone()
        .map(|name| bollard::container::CreateContainerOptions {
            name,
            platform: None,
        });
    let created = dkr
        .create_container(options, spec.config)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let id = created.id;
    // Connect any additional networks before starting, each with its optional
    // MAC / static IPv4 endpoint config.
    connect_extra_networks(&dkr, &id, &spec.extra_networks).await?;
    if spec.start {
        dkr.start_container(
            &id,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    Ok((id, spec.start))
}

/// Force-remove the container `old` is replacing (edit/upgrade).
pub(crate) async fn remove_replaced_container(dkr: &Docker, old: &str) -> Result<()> {
    let opts = bollard::container::RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    dkr.remove_container(old, Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))
}

/// Connect a freshly-created container to its additional networks (the first
/// network is applied at create time), each with its optional MAC / static IPv4.
pub(crate) async fn connect_extra_networks(
    dkr: &Docker,
    id: &str,
    nets: &[NetAttach],
) -> Result<()> {
    for a in nets {
        let endpoint = bollard::models::EndpointSettings {
            ipam_config: a
                .ipv4
                .clone()
                .map(|ip| bollard::models::EndpointIpamConfig {
                    ipv4_address: Some(ip),
                    ..Default::default()
                }),
            mac_address: a.mac.clone(),
            ..Default::default()
        };
        dkr.connect_network(
            &a.network,
            bollard::network::ConnectNetworkOptions {
                container: id.to_string(),
                endpoint_config: endpoint,
            },
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    Ok(())
}
