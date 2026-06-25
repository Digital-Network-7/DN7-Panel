//! Account self-service: profile / password / 2FA (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Account self-service: profile / password / 2FA (any authenticated user)
// ---------------------------------------------------------------------------

/// GET /api/me — the caller's account: identity, role, profile, 2FA + whether a
/// first-run credential setup is still pending (super-admin only).
pub(crate) async fn me(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    Json(json!({ "ok": true, "data": me_view(&state, &a) })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct ProfileReq {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    /// base64 data URL (size-limited).
    #[serde(default)]
    avatar: Option<String>,
}

pub(crate) fn clip(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

/// POST /api/profile — update the caller's own full name / nickname / avatar.
pub(crate) async fn put_profile(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<ProfileReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(av) = &req.avatar {
        let av = av.trim();
        // Mirror the branding-logo rule: an avatar must be empty (clear it) or a
        // base64 image data-URI, never an arbitrary string. The console renders
        // it in an <img src>, but validating here keeps a non-image value (e.g.
        // `javascript:`/HTML) from being stored and echoed by /api/me, /api/users.
        if !av.is_empty() && !av.starts_with("data:image/") {
            return api_err(StatusCode::BAD_REQUEST, "branding.logo_invalid");
        }
        if av.len() > 700_000 {
            return api_err(StatusCode::BAD_REQUEST, "branding.logo_invalid");
        }
    }
    if a.is_super {
        let saved = {
            let mut s = state.settings_guard();
            if let Some(f) = &req.full_name {
                s.full_name = clip(f, 64);
            }
            if let Some(n) = &req.nickname {
                s.nickname = clip(n, 40);
            }
            if let Some(av) = &req.avatar {
                s.avatar = av.clone();
            }
            s.clone()
        };
        if let Err(e) = settings::save(&saved) {
            return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
        }
    } else {
        let res = crate::app::users::update(&a.username, |u| {
            if let Some(f) = &req.full_name {
                u.full_name = clip(f, 64);
            }
            if let Some(n) = &req.nickname {
                u.nickname = clip(n, 40);
            }
            if let Some(av) = &req.avatar {
                u.avatar = av.clone();
            }
        });
        if let Err(e) = res {
            return map_core_err(e);
        }
        if let Some(f) = &req.full_name {
            let _ = crate::infra::system::set_full_name(&a.username, &clip(f, 64)).await;
        }
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct PasswordReq {
    #[serde(default)]
    pw_salt: String,
    #[serde(default)]
    pw_hash: String,
    /// KDF scheme used to compute `pw_hash` (e.g. "s256:30000"); stored so login
    /// recomputes the same verifier.
    #[serde(default)]
    pw_kdf: String,
    /// One-time challenge nonce (from `/api/login/challenge`) the `old_verifier`
    /// proof is bound to, so it can't be replayed.
    #[serde(default)]
    nonce: String,
    /// `sha256_hex(nonce ":" sha256_hex(current_salt ":" old_password))` — proves
    /// the caller knows their current password, bound to a single-use nonce.
    #[serde(default)]
    old_verifier: String,
    /// Plaintext new password (system users only) — used to sync the OS
    /// password to the panel password. Omitted for the super-admin.
    #[serde(default)]
    password: String,
}

/// POST /api/password — change the caller's own panel password (requires the
/// current password to be verified first).
pub(crate) async fn put_password(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<PasswordReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let who = a.to_principal();
    let env = WebAccountEnv { state: &state };
    let keep = bearer(&headers);
    match crate::app::account::change_password(
        &env,
        &who,
        crate::app::account::PasswordChange {
            salt: &req.pw_salt,
            hash: &req.pw_hash,
            kdf: &req.pw_kdf,
            nonce: &req.nonce,
            old_verifier: &req.old_verifier,
            plaintext: &req.password,
            keep_token: keep.as_deref(),
        },
    )
    .await
    {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => map_core_err(e),
    }
}

/// Web adapter implementing the account use-case environment over live console
/// state (settings/users store + session guard + audit + system accounts).
struct WebAccountEnv<'a> {
    state: &'a Shared,
}

impl crate::app::ports::account::AccountEnv for WebAccountEnv<'_> {
    fn current_verifier(&self, who: &crate::core::identity::Principal) -> String {
        if who.is_super {
            self.state
                .settings
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pw_hash
                .clone()
        } else {
            crate::app::users::find(&who.username)
                .map(|u| u.pw_hash)
                .unwrap_or_default()
        }
    }

    fn consume_challenge(&self, nonce: &str) -> bool {
        self.state.auth.consume_challenge(nonce)
    }

    fn verify_proof(&self, nonce: &str, verifier: &str, proof: &str) -> bool {
        crate::infra::auth::proof_matches(nonce, verifier, proof)
    }

    fn save_password(
        &self,
        who: &crate::core::identity::Principal,
        salt: &str,
        hash: &str,
        kdf: &str,
    ) -> Result<(), crate::core::Error> {
        if who.is_super {
            let saved = {
                let mut s = self
                    .state
                    .settings
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                s.set_password_hashed(salt, hash, kdf);
                s.clone()
            };
            settings::save(&saved).map_err(|e| crate::core::Error::Persist(e.to_string()))
        } else {
            // app::users::update already returns core::Error.
            crate::app::users::update(&who.username, |u| {
                u.pw_salt = salt.to_string();
                u.pw_hash = hash.to_string();
                u.pw_kdf = kdf.to_string();
            })
        }
    }

    async fn sync_system_password(&self, system_user: &str, plaintext: &str) {
        let _ = crate::infra::system::set_system_password(system_user, plaintext).await;
    }

    fn revoke_other_sessions(&self, username: &str, keep: Option<&str>) {
        self.state.auth.revoke_user(username, keep);
    }

    fn read_totp(&self, who: &crate::core::identity::Principal) -> String {
        if who.is_super {
            self.state
                .settings
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .totp_secret
                .clone()
        } else {
            crate::app::users::find(&who.username)
                .map(|u| u.totp_secret)
                .unwrap_or_default()
        }
    }

    fn write_totp(
        &self,
        who: &crate::core::identity::Principal,
        secret: &str,
        enabled: bool,
    ) -> Result<(), crate::core::Error> {
        if who.is_super {
            let saved = {
                let mut s = self
                    .state
                    .settings
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                s.totp_secret = secret.to_string();
                s.totp_enabled = enabled;
                s.clone()
            };
            settings::save(&saved).map_err(|e| crate::core::Error::Persist(e.to_string()))
        } else {
            // app::users::update already returns core::Error.
            crate::app::users::update(&who.username, |u| {
                u.totp_secret = secret.to_string();
                u.totp_enabled = enabled;
            })
        }
    }

    fn verify_totp(&self, secret: &str, code: &str) -> bool {
        // Single-use: enable/disable 2FA accept a code only once within its
        // window, matching the login path (no replay of an observed code).
        self.state.auth.verify_totp_single_use(secret, code)
    }

    fn audit(&self, username: &str, action: &str) {
        audit::record(username, action, username, true, "");
    }
}

/// POST /api/2fa/setup — generate a fresh (pending) TOTP secret + QR. 2FA is not
/// enabled until the user verifies a live code via /api/2fa/enable.
pub(crate) async fn twofa_setup(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let secret = crate::infra::support::totp::gen_secret();
    let issuer = branding::load().panel_name;
    let uri = crate::infra::support::totp::provisioning_uri(&issuer, &a.username, &secret);
    let qr = crate::infra::support::totp::qr_svg(&uri);
    if let Err(e) = write_totp(&state, &a, &secret, false) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    Json(json!({ "ok": true, "data": { "secret": secret, "uri": uri, "qr_svg": qr } }))
        .into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct CodeReq {
    #[serde(default)]
    code: String,
}

/// POST /api/2fa/enable — bind 2FA after verifying a live code.
pub(crate) async fn twofa_enable(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CodeReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let env = WebAccountEnv { state: &state };
    let keep = bearer(&headers);
    match crate::app::account::enable_2fa(&env, &a.to_principal(), &req.code, keep.as_deref()) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => map_core_err(e),
    }
}

/// POST /api/2fa/disable — verify a current code, then turn 2FA off.
pub(crate) async fn twofa_disable(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CodeReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let env = WebAccountEnv { state: &state };
    let keep = bearer(&headers);
    match crate::app::account::disable_2fa(&env, &a.to_principal(), &req.code, keep.as_deref()) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => map_core_err(e),
    }
}
