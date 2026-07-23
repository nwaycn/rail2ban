//! Ban manager: tracks currently-banned IPs and their expiration.

use crate::filter::MatchResult;
use crate::server::failmanager::FailTicket;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;

/// A ban record.
#[derive(Debug, Clone)]
pub struct BanTicket {
    /// The banned IP/failure-ID.
    pub host: String,
    /// Parsed IP (when applicable).
    pub ip: Option<IpAddr>,
    /// Captured user.
    pub user: Option<String>,
    /// Captured alt user.
    pub alt_user: Option<String>,
    /// MLFID (when applicable).
    pub mlfid: Option<String>,
    /// Ban start time.
    pub time_of_ban: DateTime<Utc>,
    /// Ban duration (None = permanent).
    pub bantime: Option<Duration>,
    /// Matched log lines.
    pub matches: Vec<String>,
    /// Number of failures that triggered the ban.
    pub failures: u32,
}

impl BanTicket {
    /// Ban expiration time (None = permanent).
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        self.bantime.map(|d| self.time_of_ban + d)
    }

    /// Whether the ban has expired at `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.expires() {
            Some(exp) => now >= exp,
            None => false,
        }
    }
}

/// The BanManager tracks currently-banned IPs.
pub struct BanManager {
    inner: Mutex<BanManagerInner>,
}

struct BanManagerInner {
    bans: HashMap<String, BanTicket>,
    /// History of all bans ever issued (for statistics).
    total_banned: u64,
}

impl BanManager {
    /// Create a new BanManager.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BanManagerInner {
                bans: HashMap::new(),
                total_banned: 0,
            }),
        }
    }

    /// Add a ban. Returns `true` if this is a new ban (false if the host was
    /// already banned).
    pub fn add_ban(&self, ticket: BanTicket) -> bool {
        let mut inner = self.inner.lock();
        let host = ticket.host.clone();
        let is_new = !inner.bans.contains_key(&host);
        inner.bans.insert(host, ticket);
        if is_new {
            inner.total_banned += 1;
        }
        is_new
    }

    /// Remove a ban by host. Returns the removed ticket, if any.
    pub fn remove_ban(&self, host: &str) -> Option<BanTicket> {
        let mut inner = self.inner.lock();
        inner.bans.remove(host)
    }

    /// Returns whether the host is currently banned.
    pub fn is_banned(&self, host: &str) -> bool {
        let inner = self.inner.lock();
        inner.bans.contains_key(host)
    }

    /// Return a snapshot of all current bans.
    pub fn snapshot(&self) -> Vec<BanTicket> {
        let inner = self.inner.lock();
        inner.bans.values().cloned().collect()
    }

    /// Currently banned count.
    pub fn current_banned(&self) -> usize {
        self.inner.lock().bans.len()
    }

    /// Total banned count (lifetime).
    pub fn total_banned(&self) -> u64 {
        self.inner.lock().total_banned
    }

    /// Return all bans that have expired at `now`, removing them from the
    /// manager.
    pub fn expired(&self, now: DateTime<Utc>) -> Vec<BanTicket> {
        let mut inner = self.inner.lock();
        let expired_hosts: Vec<String> = inner
            .bans
            .iter()
            .filter(|(_, t)| t.is_expired(now))
            .map(|(h, _)| h.clone())
            .collect();
        expired_hosts
            .into_iter()
            .filter_map(|h| inner.bans.remove(&h))
            .collect()
    }

    /// Remove all bans, returning the removed tickets. Used by `actionflush`.
    pub fn clear(&self) -> Vec<BanTicket> {
        let mut inner = self.inner.lock();
        let drained: Vec<BanTicket> = inner.bans.drain().map(|(_, v)| v).collect();
        drained
    }
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a [`BanTicket`] from a [`FailTicket`] and a ban duration.
pub fn ticket_from_fail(
    fail: &FailTicket,
    matches: &MatchResult,
    bantime_secs: Option<u64>,
) -> BanTicket {
    BanTicket {
        host: fail.host.clone(),
        ip: fail.ip.or(matches.ip),
        user: fail.user.clone().or(matches.user.clone()),
        alt_user: fail.alt_user.clone().or(matches.alt_user.clone()),
        mlfid: fail.mlfid.clone().or(matches.mlfid.clone()),
        time_of_ban: Utc::now(),
        bantime: bantime_secs.map(|s| Duration::seconds(s as i64)),
        matches: fail.matches.clone(),
        failures: fail.count() as u32,
    }
}
