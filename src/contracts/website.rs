//! Nginx capability — external protocol DTOs (the wire commands the console
//! sends). Owned here (the contracts layer), built/parsed by `app::nginx`, and
//! handed to the `infra::nginx` adapters as focused per-op commands (there is no
//! longer one god-`Req`: each op receives only its own fields).
//!
//! `Location` / `AccessClient` are domain entities (contracts may reference
//! domain base types); `AccessUserInput` is transport-only and lives here.

use crate::core::website::{AccessClient, Location};
use serde::Deserialize;

/// New/changed access-list user input from the client (password is plaintext,
/// optional on edit — empty keeps the existing hash).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct AccessUserInput {
    #[serde(default)]
    pub(crate) username: String,
    #[serde(default)]
    pub(crate) password: String,
}

// ---------------------------------------------------------------------------
// Per-op command model: focused typed inputs the app builds from the request
// and hands to the infra adapters — so a write op receives only its own fields.
// The single-field commands are built by the app from the body; the ones with
// `Vec` inputs derive `Deserialize` and are parsed from the body directly.
// ---------------------------------------------------------------------------

/// `remove_site`: delete a managed site by id.
pub(crate) struct RemoveSite {
    pub(crate) site_id: Option<String>,
}

/// `renew_cert`: re-issue / regenerate a standalone named cert.
pub(crate) struct RenewCert {
    pub(crate) cert_name: Option<String>,
}

/// `delete_cert`: remove a standalone named cert (refused while in use).
pub(crate) struct DeleteCert {
    pub(crate) cert_name: Option<String>,
}

/// `delete_access`: remove an access list (refused while in use).
pub(crate) struct DeleteAccess {
    pub(crate) access_id: Option<String>,
}

/// `create_cert`: create a standalone named cert (self-signed / manual / LE).
pub(crate) struct CreateCert {
    pub(crate) cert_mode: Option<String>,
    pub(crate) server_name: Option<String>,
    pub(crate) cert_pem: Option<String>,
    pub(crate) key_pem: Option<String>,
}

/// `add_site` / `update_site`: the full managed-site form. Carries `Vec` inputs,
/// so it derives `Deserialize` and is parsed from the request body by the app
/// boundary. Shared by create (no `site_id`) and edit (with `site_id`).
#[derive(Debug, Deserialize, Default)]
pub(crate) struct SiteForm {
    #[serde(default)]
    pub(crate) site_id: Option<String>,
    #[serde(default)]
    pub(crate) server_name: Option<String>,
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) target_url: Option<String>,
    #[serde(default)]
    pub(crate) container: Option<String>,
    #[serde(default)]
    pub(crate) container_port: Option<i64>,
    #[serde(default)]
    pub(crate) root: Option<String>,
    #[serde(default)]
    pub(crate) local_root: Option<String>,
    #[serde(default)]
    pub(crate) ssl: Option<bool>,
    #[serde(default)]
    pub(crate) cert_mode: Option<String>,
    #[serde(default)]
    pub(crate) cert_name: Option<String>,
    #[serde(default)]
    pub(crate) cert_pem: Option<String>,
    #[serde(default)]
    pub(crate) key_pem: Option<String>,
    #[serde(default)]
    pub(crate) scheme: Option<String>,
    #[serde(default)]
    pub(crate) cache: Option<bool>,
    #[serde(default)]
    pub(crate) block_attacks: Option<bool>,
    #[serde(default)]
    pub(crate) websockets: Option<bool>,
    #[serde(default)]
    pub(crate) force_ssl: Option<bool>,
    #[serde(default)]
    pub(crate) http2: Option<bool>,
    #[serde(default)]
    pub(crate) hsts: Option<bool>,
    #[serde(default)]
    pub(crate) hsts_sub: Option<bool>,
    #[serde(default)]
    pub(crate) trust_proxy: Option<bool>,
    #[serde(default)]
    pub(crate) trust_proxy_cidrs: Option<String>,
    #[serde(default)]
    pub(crate) locations: Option<Vec<Location>>,
    #[serde(default)]
    pub(crate) extra_conf: Option<String>,
    #[serde(default)]
    pub(crate) access_id: Option<String>,
}

/// `save_access`: create/update an access list (HTTP basic-auth users + IP
/// allow/deny rules). Carries `Vec` inputs, so it derives `Deserialize` and is
/// parsed directly from the request body by the app boundary.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct SaveAccess {
    #[serde(default)]
    pub(crate) access_id: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) satisfy: Option<String>,
    #[serde(default)]
    pub(crate) pass_auth: Option<bool>,
    #[serde(default)]
    pub(crate) users: Option<Vec<AccessUserInput>>,
    #[serde(default)]
    pub(crate) clients: Option<Vec<AccessClient>>,
}
