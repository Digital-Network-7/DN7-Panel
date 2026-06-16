//! Capability dispatch (docker/nginx/mysql JSON protocol) (split from web/server.rs).
use super::*;

// ---------------------------------------------------------------------------
// Capability dispatch (docker / nginx / mysql) — same JSON protocol as relays
// ---------------------------------------------------------------------------

pub(crate) async fn dispatch(
    state: &Shared,
    headers: &header::HeaderMap,
    chan: &str,
    body: Value,
    f: impl std::future::Future<Output = anyhow::Result<Value>>,
) -> Response {
    // Docker / Nginx / MySQL management are root-level capabilities — admin only.
    let acct = match require_admin(state, headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let res = f.await;
    // Record state-changing operations only (skip reads/polls to keep the log
    // meaningful and small).
    if !is_read_op(&op) {
        let target = body
            .get("inst")
            .or_else(|| body.get("name"))
            .or_else(|| body.get("domain"))
            .or_else(|| body.get("container"))
            .or_else(|| body.get("database"))
            .or_else(|| body.get("ref"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let (detail, response) = match &res {
            Ok(v) => (String::new(), redact_response(v)),
            Err(e) => (e.to_string(), String::new()),
        };
        audit::record_op(
            &acct.username,
            &format!("{chan}.{op}"),
            &target,
            res.is_ok(),
            &detail,
            &response,
        );
    }
    match res {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
}

/// Read-only / polling ops we don't write to the audit log.
pub(crate) fn is_read_op(op: &str) -> bool {
    matches!(
        op,
        "" | "info"
            | "list"
            | "list_ops"
            | "op_log"
            | "status"
            | "ps"
            | "stats"
            | "logs"
            | "log"
            | "inspect"
            | "get"
            | "detail"
            | "read"
            | "databases"
            | "tables"
            | "columns"
            | "table_rows"
            | "list_users"
            | "user_grants"
            | "credentials"
            | "images"
            | "networks"
            | "volumes"
            | "df"
            | "usage"
            | "ports"
            | "exists"
            | "preview"
            | "validate"
            | "test"
            | "check"
            | "changelog"
            | "dismiss_op"
            | "list_dirs"
            | "network_ips"
            | "container_stats"
            | "get_container_config"
            | "list_backups"
    )
}

pub(crate) async fn docker_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Resolve the caller's authz level for the create guardrail (privileged /
    // host-network are super-only). If they're not even an admin the inner
    // dispatch's require_admin rejects before the future is polled.
    let is_super = require_admin(&state, &headers)
        .map(|a| a.is_super)
        .unwrap_or(false);
    let fut = crate::app::docker::dispatch(&body, is_super);
    dispatch(&state, &headers, "docker", body.clone(), fut).await
}

pub(crate) async fn nginx_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::app::nginx::dispatch(&body);
    dispatch(&state, &headers, "nginx", body.clone(), fut).await
}

pub(crate) async fn mysql_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::app::mysql::dispatch(&body);
    dispatch(&state, &headers, "mysql", body.clone(), fut).await
}

#[cfg(test)]
mod tests {
    use super::is_read_op;

    #[test]
    fn read_ops_are_not_audited() {
        // A representative sample of read/poll ops that must NOT be logged.
        for op in [
            "", "info", "list", "list_ops", "op_log", "status", "stats", "logs",
        ] {
            assert!(is_read_op(op), "{op} should be a read op");
        }
    }

    #[test]
    fn state_changing_ops_are_audited() {
        // Mutating ops must be treated as auditable (not read ops).
        for op in [
            "create",
            "delete",
            "remove",
            "start",
            "stop",
            "restart",
            "add_site",
            "update_site",
            "install",
            "switch",
            "create_named_cert",
        ] {
            assert!(!is_read_op(op), "{op} must be auditable");
        }
    }
}
