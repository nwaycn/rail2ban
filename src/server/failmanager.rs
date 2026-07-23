//! Failure manager: counts failures per IP within a sliding window.

use crate::filter::MatchResult;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;

/// A single failure record.
#[derive(Debug, Clone)]
pub struct FailTicket {
    /// The IP/failure-ID.
    pub host: String,
    /// Parsed IP (when applicable).
    pub ip: Option<IpAddr>,
    /// Captured user.
    pub user: Option<String>,
    /// Captured alt user.
    pub alt_user: Option<String>,
    /// MLFID (when applicable).
    pub mlfid: Option<String>,
    /// Timestamps of all failures within the window.
    pub times: Vec<DateTime<Utc>>,
    /// Matched log lines (subject to `maxmatches`).
    pub matches: Vec<String>,
    /// Whether this ticket should not actually count (F-NOFAIL).
    pub nofail: bool,
}

impl FailTicket {
    /// Number of failures recorded.
    pub fn count(&self) -> usize {
        self.times.len()
    }

    /// Time of the most recent failure (or `None` if empty).
    pub fn last_seen(&self) -> Option<DateTime<Utc>> {
        self.times.last().copied()
    }
}

/// The FailManager tracks failures per host within a sliding `findtime` window.
pub struct FailManager {
    inner: Mutex<FailManagerInner>,
    maxretry: u32,
    findtime: Duration,
    maxmatches: usize,
}

struct FailManagerInner {
    tickets: HashMap<String, FailTicket>,
    mlfid_map: HashMap<String, String>,
}

impl FailManager {
    /// Create a new FailManager.
    pub fn new(maxretry: u32, findtime_secs: i64, maxmatches: u32) -> Self {
        Self {
            inner: Mutex::new(FailManagerInner {
                tickets: HashMap::new(),
                mlfid_map: HashMap::new(),
            }),
            maxretry,
            findtime: Duration::seconds(findtime_secs),
            maxmatches: maxmatches as usize,
        }
    }

    /// Add a failure (or nofail observation) and return a ticket when
    /// `maxretry` is reached.
    pub fn add_failure(&self, m: &MatchResult) -> Option<FailTicket> {
        let host = if let Some(mlfid) = &m.mlfid {
            // Aggregate by MLFID.
            let mut inner = self.inner.lock();
            let ticket_host = inner
                .mlfid_map
                .entry(mlfid.clone())
                .or_insert_with(|| m.host.clone().clone())
                .clone();
            ticket_host
        } else {
            m.host.clone()
        };

        let now = m.timestamp.unwrap_or_else(Utc::now);
        let mut inner = self.inner.lock();

        // Map MLFID -> host for future lines with the same MLFID.
        if let Some(mlfid) = &m.mlfid {
            inner.mlfid_map.insert(mlfid.clone(), host.clone());
        }

        let ticket = inner.tickets.entry(host.clone()).or_insert_with(|| FailTicket {
            host: host.clone(),
            ip: m.ip,
            user: m.user.clone(),
            alt_user: m.alt_user.clone(),
            mlfid: m.mlfid.clone(),
            times: Vec::new(),
            matches: Vec::new(),
            nofail: m.nofail,
        });

        // Drop old failures outside findtime window.
        let cutoff = now - self.findtime;
        ticket.times.retain(|&t| t >= cutoff);
        // Update metadata (in case the latest match has more info).
        if ticket.ip.is_none() {
            ticket.ip = m.ip;
        }
        if ticket.user.is_none() {
            ticket.user = m.user.clone();
        }
        if ticket.alt_user.is_none() {
            ticket.alt_user = m.alt_user.clone();
        }
        if m.mlfgained {
            // Success event: clear failure count.
            ticket.times.clear();
            return None;
        }
        if !m.nofail {
            ticket.times.push(now);
        }
        if ticket.matches.len() < self.maxmatches {
            ticket.matches.push(m.line.clone());
        }
        ticket.nofail = m.nofail;

        if m.nofail {
            return None;
        }
        if (ticket.times.len() as u32) >= self.maxretry {
            // Promote to ban — clone the ticket, but keep tracking in case of
            // further failures (fail2ban keeps accumulating for incremental
            // bantime).
            return Some(ticket.clone());
        }
        None
    }

    /// Forget the MLFID context (called when `<F-MLFFORGET>` matches).
    pub fn forget_mlfid(&self, mlfid: &str) {
        let mut inner = self.inner.lock();
        if let Some(host) = inner.mlfid_map.remove(mlfid) {
            // Optionally clear the ticket too; fail2ban keeps the ticket for
            // the findtime window but disconnects the MLFID.
            let _ = host;
        }
    }

    /// Remove a ticket (after a ban has been issued).
    pub fn remove(&self, host: &str) -> Option<FailTicket> {
        let mut inner = self.inner.lock();
        inner.tickets.remove(host)
    }

    /// Return a snapshot of all current failure counts.
    pub fn snapshot(&self) -> Vec<FailTicket> {
        let inner = self.inner.lock();
        inner.tickets.values().cloned().collect()
    }

    /// Currently failed count (number of tracked hosts).
    pub fn current_failed(&self) -> usize {
        self.inner.lock().tickets.len()
    }

    /// Total failed count (sum of all `times`).
    pub fn total_failed(&self) -> usize {
        let inner = self.inner.lock();
        inner.tickets.values().map(|t| t.times.len()).sum()
    }

    /// Purge entries older than `findtime`.
    pub fn purge(&self) {
        let now = Utc::now();
        let cutoff = now - self.findtime;
        let mut inner = self.inner.lock();
        inner.tickets.retain(|_, t| t.times.iter().any(|&x| x >= cutoff));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(host: &str, ts: DateTime<Utc>) -> MatchResult {
        MatchResult {
            host: host.into(),
            ip: host.parse().ok(),
            user: None,
            alt_user: None,
            mlfid: None,
            timestamp: Some(ts),
            nofail: false,
            mlfforget: false,
            mlfgained: false,
            line: format!("failed from {host}"),
            regex_index: 0,
        }
    }

    #[test]
    fn triggers_ban_after_maxretry() {
        let mgr = FailManager::new(3, 600, 10);
        let t0 = Utc::now();
        let m1 = make_match("1.2.3.4", t0);
        let m2 = make_match("1.2.3.4", t0 + Duration::seconds(1));
        let m3 = make_match("1.2.3.4", t0 + Duration::seconds(2));
        assert!(mgr.add_failure(&m1).is_none());
        assert!(mgr.add_failure(&m2).is_none());
        assert!(mgr.add_failure(&m3).is_some());
    }

    #[test]
    fn expires_old_failures() {
        let mgr = FailManager::new(2, 10, 10);
        let t0 = Utc::now() - Duration::seconds(60);
        let m1 = make_match("1.2.3.4", t0);
        let m2 = make_match("1.2.3.4", Utc::now());
        assert!(mgr.add_failure(&m1).is_none());
        assert!(mgr.add_failure(&m2).is_none());
    }
}
