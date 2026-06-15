//! MySQL infra-support: credential generation. The engine/version catalog +
//! image-reference rules live in `domain::mysql`.
use super::*;

/// Generate a strong random root password (no shell-special chars so it's safe
/// to pass as a separate argv entry / env value; length 24).
pub(crate) fn gen_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}
