//! Web-console auth: bearer session tokens + login rate limiting.
//!
//! A successful login (correct password) mints a random token kept in memory
//! with an expiry. Requests carry it as `Authorization: Bearer <token>` (or a
//! `token` query param for WebSocket upgrades, which can't set headers from the
//! browser). Failed logins are rate-limited per source to slow brute force.
//!
//! [`AuthState`] is a thin façade over four focused, self-contained stores —
//! each in its own submodule (`session`/`challenge`/`ticket`/`rate`), owning its
//! own lock and lifecycle. [`AuthState::sweep`] prunes expired entries across
//! all of them from one place (called periodically by the server), so lifecycle
//! isn't scattered across ad-hoc prune-on-insert paths. Shared helpers (token
//! RNG/hashing, the challenge-response proof, session persistence) live here.

mod challenge;
mod rate;
mod session;
mod state;
mod ticket;
mod totp_guard;

use challenge::ChallengeStore;
use rate::RateLimiter;
use session::SessionStore;
use ticket::TicketStore;
use totp_guard::TotpGuard;

pub(crate) use state::*;
