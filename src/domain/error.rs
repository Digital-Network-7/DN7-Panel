//! Application/domain error.
//!
//! Semantic variants **only** — no transport types, no wire/`err.*` strings
//! (per `.kiro/steering/architecture.md`: domain 不懂传输,也不带协议字符串).
//! The web boundary is the single place that maps these to `{http_status,
//! code}`. This enum grows as use-cases migrate off the legacy `ERR_CODE:`
//! string channel.

/// A recoverable failure from a domain / use-case operation.
#[derive(Debug)]
pub(crate) enum Error {
    /// Client-supplied password salt/hash is malformed.
    PasswordMalformed,
    /// The current-password proof did not match the stored verifier.
    OldPasswordWrong,
    /// The supplied TOTP code was missing or did not verify.
    TotpInvalid,
    /// Persisting the change failed (detail carries the underlying error).
    Persist(String),
}
