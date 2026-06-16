//! HTTP route table (≈ Laravel `routes/`). Declares the public + authenticated
//! routes and layers the entry-gate / security-header middleware. Kept separate
//! from the controllers (which own the handler bodies) and the http kernel
//! (which owns shared state + bootstrap).

use axum::{
    routing::{get, post},
    Router,
};

use crate::web::http::controllers::*;
use crate::web::http::middleware::{entry_gate, security_headers};
use crate::web::http::Shared;

pub(crate) fn build_router(state: Shared) -> Router {
    Router::new()
        // Public (no auth): the login page + login endpoint.
        .route("/", get(index_page))
        .route("/ui/*path", get(ui_asset))
        .route("/api/login/challenge", get(login_challenge))
        .route("/api/login", post(login))
        // Authenticated API.
        .route("/api/logout", post(logout))
        .route("/api/ticket", post(mint_ticket))
        .route("/api/me", get(me))
        .route("/api/profile", post(put_profile))
        .route("/api/password", post(put_password))
        .route("/api/2fa/setup", post(twofa_setup))
        .route("/api/2fa/enable", post(twofa_enable))
        .route("/api/2fa/disable", post(twofa_disable))
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/update", post(users_update))
        .route("/api/users/delete", post(users_delete))
        .route("/api/info", get(panel_info))
        .route("/api/metrics", get(metrics))
        .route("/api/metrics/history", get(metrics_history))
        .route("/api/settings", get(get_settings).post(put_settings))
        .route("/api/restart", post(restart_panel))
        .route("/api/logs", get(logs_list))
        .route("/api/logs/clear", post(logs_clear))
        .route("/api/branding", get(get_branding).post(put_branding))
        .route("/api/update/status", get(update_status))
        .route(
            "/api/update/config",
            get(update_config_get).post(update_config_put),
        )
        .route("/api/update/check", post(update_check))
        .route("/api/update/changelog", get(update_changelog))
        .route("/api/update/apply", post(update_apply))
        .route("/api/docker", post(docker_op))
        .route("/api/nginx", post(nginx_op))
        .route("/api/mysql", post(mysql_op))
        .route("/api/terminal", get(terminal_ws))
        .route("/api/container/terminal", get(container_terminal_ws))
        .route("/api/files/list", post(files_list))
        .route("/api/files/mkdir", post(files_mkdir))
        .route("/api/files/delete", post(files_delete))
        .route("/api/files/download", get(files_download))
        .route("/api/files/upload", post(files_upload))
        .route("/api/docker/download", get(docker_download))
        .route("/api/docker/image-upload", post(docker_image_upload))
        .route("/api/nginx/static-upload", post(nginx_static_upload))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            entry_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}
