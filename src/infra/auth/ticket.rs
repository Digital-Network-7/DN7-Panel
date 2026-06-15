//! One-time ticket store (WebSocket upgrade / download authorization) — split
//! from auth.rs.
use super::{random_token, MAX_TICKETS, TICKET_TTL};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A one-time ticket: issue time + the account it authorizes.
struct TicketRec {
    issued: Instant,
    user: String,
}

#[derive(Default)]
pub(super) struct TicketStore {
    map: Mutex<HashMap<String, TicketRec>>, // ticket -> owner
}

impl TicketStore {
    pub(super) fn issue(&self, user: &str) -> String {
        let ticket = random_token();
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        m.retain(|_, r| now.duration_since(r.issued) <= TICKET_TTL);
        while m.len() >= MAX_TICKETS {
            let Some(oldest) = m
                .iter()
                .min_by_key(|(_, r)| r.issued)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            m.remove(&oldest);
        }
        m.insert(
            ticket.clone(),
            TicketRec {
                issued: now,
                user: user.to_string(),
            },
        );
        ticket
    }

    pub(super) fn consume(&self, ticket: &str) -> Option<String> {
        if ticket.is_empty() {
            return None;
        }
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        match m.remove(ticket) {
            Some(r) if Instant::now().duration_since(r.issued) <= TICKET_TTL => Some(r.user),
            _ => None,
        }
    }

    pub(super) fn revoke_user(&self, user: &str) {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, r| r.user != user);
    }

    pub(super) fn sweep(&self) {
        let now = Instant::now();
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, r| now.duration_since(r.issued) <= TICKET_TTL);
    }
}
