//! The reload entry point the panel's website control plane calls after every
//! site/cert/access change — the in-process equivalent of `nginx -t && nginx -s
//! reload`. `infra::website` gathers the manifests into a [`ReloadInput`] and
//! calls [`reload`]; we build, validate, and atomically publish the new table.

use std::sync::Arc;

use anyhow::{anyhow, Result};

use super::build::{build_runtime, ReloadInput};
use super::{store, validate};

/// Build → validate → publish a new runtime config. Returns an `nginx -t`-style
/// error (without touching the live config) when the new model is invalid, so a
/// bad change can't take the edge server down — the previous config keeps
/// serving.
pub async fn reload(input: ReloadInput) -> Result<()> {
    let cfg = build_runtime(&input).map_err(|e| anyhow!("配置无效：{e}"))?;
    validate::validate(&cfg).map_err(|e| anyhow!("配置无效：{e}"))?;
    store::publish(Arc::new(cfg));
    tracing::info!("edge: runtime config reloaded");
    Ok(())
}
