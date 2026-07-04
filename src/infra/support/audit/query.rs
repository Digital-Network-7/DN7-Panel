//! Read side of the audit log: whole-file read, filtering, and real
//! (offset/limit) pagination. Split from the append/durability write path in
//! the parent module so each file stays a single concern (ARCHITECTURE.md §9).

use super::{path, Entry};

/// Read the entire log, newest first (bounded only by the on-disk size cap).
fn read_all() -> Vec<Entry> {
    let raw = match std::fs::read_to_string(path()) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<Entry> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect();
    out.reverse(); // newest first
    out
}

/// Read up to `limit` most-recent entries, newest first. Test-only convenience
/// (the live console reads through [`query`]); kept for the download-audit tests.
#[cfg(test)]
pub fn read(limit: usize) -> Vec<Entry> {
    let mut out = read_all();
    out.truncate(limit.clamp(1, 5000));
    out
}

/// Group token of an action key: the segment before the first '.'
/// ("auth.login" → "auth"). Empty when the action carries no dot.
fn action_group(action: &str) -> &str {
    match action.find('.') {
        Some(i) => &action[..i],
        None => "",
    }
}

/// Filter for a paginated audit query. Fields are AND-combined; a `None`/empty
/// field places no constraint. Timestamps are unix seconds (inclusive bounds).
#[derive(Default)]
pub struct Query {
    /// Restrict to entries with this success flag (`Some(true)` = ok only,
    /// `Some(false)` = failures only).
    pub ok: Option<bool>,
    /// Restrict to entries whose action group equals this token.
    pub module: Option<String>,
    /// Inclusive lower bound on `ts`.
    pub from_ts: Option<i64>,
    /// Inclusive upper bound on `ts`.
    pub to_ts: Option<i64>,
    /// Case-insensitive substring matched over actor / action / target /
    /// detail / ip (the raw stored fields — not localized labels).
    pub text: Option<String>,
}

impl Query {
    fn matches(&self, e: &Entry) -> bool {
        if let Some(ok) = self.ok {
            if e.ok != ok {
                return false;
            }
        }
        if let Some(m) = &self.module {
            if action_group(&e.action) != m {
                return false;
            }
        }
        if let Some(f) = self.from_ts {
            if e.ts < f {
                return false;
            }
        }
        if let Some(t) = self.to_ts {
            if e.ts > t {
                return false;
            }
        }
        if let Some(q) = &self.text {
            let q = q.to_lowercase();
            if !q.is_empty() {
                let hit = e.actor.to_lowercase().contains(&q)
                    || e.action.to_lowercase().contains(&q)
                    || e.target.to_lowercase().contains(&q)
                    || e.detail.to_lowercase().contains(&q)
                    || e.ip.to_lowercase().contains(&q);
                if !hit {
                    return false;
                }
            }
        }
        true
    }
}

/// A page of audit entries plus the totals needed to drive real pagination.
pub struct Page {
    /// The requested slice (post-filter), newest first.
    pub entries: Vec<Entry>,
    /// Number of entries matching the filter across ALL pages.
    pub total: usize,
    /// Distinct action groups present across the whole log (unfiltered), sorted —
    /// the stable option set for the module dropdown, independent of the filter.
    pub modules: Vec<String>,
}

/// Read a filtered, paginated slice (newest first): skip `offset` matching
/// entries and return up to `limit`. `total` counts all matches; `modules`
/// lists every group present so the dropdown stays stable across filters.
pub fn query(filter: &Query, offset: usize, limit: usize) -> Page {
    paginate(read_all(), filter, offset, limit)
}

/// Pure filter+paginate over an already-read (newest-first) entry list. Split
/// from [`query`] so the windowing logic is unit-testable without a data dir.
fn paginate(all: Vec<Entry>, filter: &Query, offset: usize, limit: usize) -> Page {
    let limit = limit.clamp(1, 5000);
    let mut modules: Vec<String> = all
        .iter()
        .map(|e| action_group(&e.action))
        .filter(|g| !g.is_empty())
        .map(|g| g.to_string())
        .collect();
    modules.sort();
    modules.dedup();
    let mut total = 0usize;
    let mut entries = Vec::new();
    for e in all.into_iter().filter(|e| filter.matches(e)) {
        // `total` is this match's zero-based index; push those in the window.
        if total >= offset && entries.len() < limit {
            entries.push(e);
        }
        total += 1;
    }
    Page {
        entries,
        total,
        modules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(ts: i64, actor: &str, action: &str, ok: bool) -> Entry {
        Entry {
            ts,
            actor: actor.into(),
            action: action.into(),
            target: String::new(),
            ok,
            detail: String::new(),
            ip: String::new(),
            headers: String::new(),
            response: String::new(),
        }
    }

    // Newest-first sample: 5 entries across auth/user/docker, mixed ok/fail.
    fn sample() -> Vec<Entry> {
        vec![
            mk(500, "owner", "docker.create", true),
            mk(400, "alice", "auth.login", false),
            mk(300, "owner", "user.create", true),
            mk(200, "owner", "auth.login", true),
            mk(100, "bob", "docker.remove", false),
        ]
    }

    #[test]
    fn paginate_windows_and_totals() {
        // Page 1 (offset 0, limit 2) → first two, total is the full match count.
        let p = paginate(sample(), &Query::default(), 0, 2);
        assert_eq!(p.total, 5);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].ts, 500);
        assert_eq!(p.entries[1].ts, 400);
        // Module list is the distinct groups, sorted, unfiltered.
        assert_eq!(p.modules, vec!["auth", "docker", "user"]);
        // Page 3 (offset 4) → the trailing single entry.
        let p3 = paginate(sample(), &Query::default(), 4, 2);
        assert_eq!(p3.total, 5);
        assert_eq!(p3.entries.len(), 1);
        assert_eq!(p3.entries[0].ts, 100);
        // Offset past the end → empty page, total unchanged.
        let past = paginate(sample(), &Query::default(), 99, 2);
        assert_eq!(past.total, 5);
        assert!(past.entries.is_empty());
    }

    #[test]
    fn paginate_filters_narrow_total() {
        // Failures only.
        let fails = paginate(
            sample(),
            &Query {
                ok: Some(false),
                ..Default::default()
            },
            0,
            50,
        );
        assert_eq!(fails.total, 2);
        assert!(fails.entries.iter().all(|e| !e.ok));
        // …but `modules` still reflects the WHOLE log so the dropdown is stable.
        assert_eq!(fails.modules, vec!["auth", "docker", "user"]);
        // Module filter.
        let auth = paginate(
            sample(),
            &Query {
                module: Some("auth".into()),
                ..Default::default()
            },
            0,
            50,
        );
        assert_eq!(auth.total, 2);
        assert!(auth.entries.iter().all(|e| e.action.starts_with("auth.")));
        // Timestamp range (inclusive) 200..=400.
        let win = paginate(
            sample(),
            &Query {
                from_ts: Some(200),
                to_ts: Some(400),
                ..Default::default()
            },
            0,
            50,
        );
        assert_eq!(win.total, 3);
        assert!(win.entries.iter().all(|e| (200..=400).contains(&e.ts)));
        // Free-text over raw fields (actor match, case-insensitive).
        let txt = paginate(
            sample(),
            &Query {
                text: Some("ALICE".into()),
                ..Default::default()
            },
            0,
            50,
        );
        assert_eq!(txt.total, 1);
        assert_eq!(txt.entries[0].actor, "alice");
    }
}
