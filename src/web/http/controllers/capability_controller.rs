//! Capability dispatch (docker/nginx/mysql JSON protocol) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Capability dispatch (docker / nginx / mysql) — same JSON protocol as relays
// ---------------------------------------------------------------------------

/// The audit-relevant facts about a capability request, extracted from the body
/// before the op future is built — so `dispatch` never has to clone the whole
/// request `Value` (the future borrows it) just to read the op + target.
pub(crate) struct OpMeta {
    pub(crate) op: String,
    pub(crate) target: String,
}

/// Extract `{op, target}` from a request body for audit logging. `target` is the
/// first present of the per-capability identity fields.
pub(crate) fn op_meta(body: &Value) -> OpMeta {
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
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
    OpMeta { op, target }
}

pub(crate) async fn dispatch(
    acct: &Account,
    chan: &str,
    meta: OpMeta,
    f: impl std::future::Future<Output = anyhow::Result<Value>>,
) -> Response {
    let res = f.await;
    // Record state-changing operations only (skip reads/polls to keep the log
    // meaningful and small).
    if !is_read_op(&meta.op) {
        let (detail, response) = match &res {
            Ok(v) => (String::new(), redact_response(v)),
            Err(e) => (e.to_string(), String::new()),
        };
        audit::record_op(
            &acct.username,
            &format!("{chan}.{}", meta.op),
            &meta.target,
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
            | "list_access"
            | "list_containers"
            | "list_named_certs"
            | "get_settings"
            | "list_ops"
            | "list_sites"
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
    // Docker management is admin-only — resolve the account ONCE here (it carries
    // the is_super level the create guardrail needs) and hand it to dispatch,
    // instead of re-resolving (which re-locked the session + cloned the user
    // list) inside dispatch.
    let acct = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let meta = op_meta(&body);
    let fut = crate::app::docker::dispatch(&body, acct.is_super);
    dispatch(&acct, "docker", meta, fut).await
}

pub(crate) async fn website_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let acct = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let meta = op_meta(&body);
    let fut = crate::app::website::dispatch(&body);
    dispatch(&acct, "website", meta, fut).await
}

pub(crate) async fn mysql_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let acct = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let meta = op_meta(&body);
    let fut = crate::app::mysql::dispatch(&body);
    dispatch(&acct, "mysql", meta, fut).await
}

#[cfg(test)]
mod tests {
    use super::{is_read_op, op_meta};
    use serde_json::json;

    #[test]
    fn op_meta_extracts_op_and_first_target_field() {
        // `op` is read verbatim; `target` is the first present identity field
        // in priority order (inst > name > domain > container > database > ref).
        let m = op_meta(&json!({ "op": "create", "container": "c1", "ref": "r9" }));
        assert_eq!(m.op, "create");
        assert_eq!(m.target, "c1");
        // Falls through to `ref` when the higher-priority fields are absent.
        let m = op_meta(&json!({ "op": "remove", "ref": "r9" }));
        assert_eq!(m.target, "r9");
        // Missing op/target → empty strings (no panic).
        let m = op_meta(&json!({}));
        assert_eq!(m.op, "");
        assert_eq!(m.target, "");
    }

    #[test]
    fn read_ops_are_not_audited() {
        // A representative sample of read/poll ops that must NOT be logged.
        for op in [
            "",
            "info",
            "list",
            "list_access",
            "list_named_certs",
            "list_sites",
            "list_ops",
            "op_log",
            "status",
            "stats",
            "logs",
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
