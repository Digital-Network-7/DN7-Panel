//! Parse/build the focused `contracts::nginx` command for each write op from
//! the raw capability JSON. Extracted so `dispatch` stays a flat one-line-arm
//! routing table instead of inlining field-by-field struct construction.

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::contracts::nginx::{
    CreateCert, DeleteAccess, DeleteCert, RemoveSite, RenewCert, SaveAccess, SiteForm,
};

/// Read an optional string field from the request body.
fn s(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

/// `add_site` / `update_site`: the full site form (serde-parsed).
pub(crate) fn site_form(body: &Value) -> Result<SiteForm> {
    serde_json::from_value(body.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))
}

/// `save_access`: the access-list form (serde-parsed).
pub(crate) fn save_access(body: &Value) -> Result<SaveAccess> {
    serde_json::from_value(body.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))
}

/// `remove_site`.
pub(crate) fn remove_site(body: &Value) -> RemoveSite {
    RemoveSite {
        site_id: s(body, "site_id"),
    }
}

/// `create_cert`.
pub(crate) fn create_cert(body: &Value) -> CreateCert {
    CreateCert {
        cert_mode: s(body, "cert_mode"),
        server_name: s(body, "server_name"),
        cert_pem: s(body, "cert_pem"),
        key_pem: s(body, "key_pem"),
    }
}

/// `renew_cert`.
pub(crate) fn renew_cert(body: &Value) -> RenewCert {
    RenewCert {
        cert_name: s(body, "cert_name"),
    }
}

/// `delete_cert`.
pub(crate) fn delete_cert(body: &Value) -> DeleteCert {
    DeleteCert {
        cert_name: s(body, "cert_name"),
    }
}

/// `delete_access`.
pub(crate) fn delete_access(body: &Value) -> DeleteAccess {
    DeleteAccess {
        access_id: s(body, "access_id"),
    }
}
