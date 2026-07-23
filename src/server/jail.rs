//! A running jail: ties together backend, filter, FailManager, BanManager,
//! and the jail's actions.

use crate::action::{Action, ActionExecutor, BanContext};
use crate::backend::{file::FileBackend, journal::JournalBackend, LogBackend};
use crate::config::JailConfig;
use crate::filter::{CompiledFilter, LineBuffer, MatchResult};
use crate::ip::IpFamily;
use crate::server::banmanager::{ticket_from_fail, BanManager, BanTicket};
use crate::server::database::Database;
use crate::server::failmanager::{FailManager, FailTicket};
use chrono::Utc;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A running jail handle.
pub struct JailHandle {
    /// Jail name.
    pub name: String,
    /// Sender to the jail task (for manual `banip`/`unbanip`/`attempt`).
    pub cmd_tx: mpsc::Sender<JailCommand>,
    /// Shared BanManager (for queries).
    pub ban_mgr: Arc<BanManager>,
    /// Shared FailManager (for queries).
    pub fail_mgr: Arc<FailManager>,
    /// The join handle of the jail task.
    pub join: Option<JoinHandle<()>>,
}

/// Commands sent to a jail task.
#[derive(Debug)]
pub enum JailCommand {
    /// Manually add a failure observation.
    Attempt {
        /// IP/ID.
        ip: String,
        /// Optional failure lines.
        failures: Vec<String>,
    },
    /// Manually ban an IP.
    BanIp {
        /// IP/ID.
        ip: String,
    },
    /// Manually unban an IP.
    UnbanIp {
        /// IP/ID.
        ip: String,
    },
    /// Flush all bans (run actionflush + clear ban_mgr).
    FlushAll,
    /// Restore a ban from the database on restart (does NOT run actionban).
    RestoreBan {
        /// IP/ID.
        ip: String,
        /// Parsed IP (when applicable).
        ip_addr: Option<IpAddr>,
        /// Ban start time (epoch seconds).
        time_of_ban: i64,
        /// Ban duration in seconds (None = permanent).
        bantime: Option<i64>,
    },
    /// Stop the jail.
    Stop,
}

/// A jail with all its wired-up components.
pub struct Jail {
    /// Jail config.
    pub config: JailConfig,
    /// Compiled filter.
    pub filter: CompiledFilter,
    /// Actions bound to this jail.
    pub actions: Vec<Action>,
    /// FailManager (failure tracking).
    pub fail_mgr: Arc<FailManager>,
    /// BanManager (current bans).
    pub ban_mgr: Arc<BanManager>,
    /// Optional database.
    pub db: Option<Arc<Database>>,
    /// Multi-line buffer (when `maxlines > 1`).
    pub line_buffer: Mutex<LineBuffer>,
    /// Optional ignorecommand result cache.
    pub ignore_cache: Mutex<Option<IgnoreCache>>,
}

/// Parsed `ignorecache` spec: `key="ip", max-count=N, max-time=Tm`.
#[derive(Debug)]
pub struct IgnoreCache {
    /// Maximum number of entries.
    max_count: usize,
    /// Time-to-live for each entry.
    max_time: std::time::Duration,
    /// Cached entries: key -> (result, inserted_at), in insertion order.
    entries: indexmap::IndexMap<String, (bool, std::time::Instant)>,
}

impl IgnoreCache {
    /// Parse a spec string like `key="ip", max-count=100, max-time=1h`.
    /// Returns `None` if the spec is empty or invalid.
    fn parse(spec: &str) -> Option<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return None;
        }
        let mut max_count: usize = 100;
        let mut max_time_secs: u64 = 3600;
        for part in spec.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("max-count=") {
                if let Ok(n) = v.trim().parse::<usize>() {
                    max_count = n;
                }
            } else if let Some(v) = part.strip_prefix("max-time=") {
                if let Ok(tv) = crate::time::TimeValue::parse(v.trim()) {
                    max_time_secs = tv.to_seconds_or_max();
                }
            }
            // `key="ip"` is accepted but currently only "ip" is supported.
        }
        if max_count == 0 {
            return None;
        }
        Some(Self {
            max_count,
            max_time: std::time::Duration::from_secs(max_time_secs),
            entries: indexmap::IndexMap::new(),
        })
    }

    /// Look up a cached result. Returns `None` if absent or expired.
    fn get(&self, key: &str) -> Option<bool> {
        let now = std::time::Instant::now();
        let (result, inserted) = self.entries.get(key)?;
        if now.duration_since(*inserted) > self.max_time {
            return None;
        }
        Some(*result)
    }

    /// Insert a result, evicting oldest entries when over capacity.
    fn insert(&mut self, key: String, result: bool) {
        if self.entries.len() >= self.max_count {
            // Evict one expired entry (if any) to make room.
            let now = std::time::Instant::now();
            let expired_key = self
                .entries
                .iter()
                .find(|(_, (_, t))| now.duration_since(*t) > self.max_time)
                .map(|(k, _)| k.clone());
            if let Some(k) = expired_key {
                self.entries.shift_remove(&k);
            } else if let Some(first_key) = self.entries.keys().next().cloned() {
                // Evict the oldest (first-inserted) entry.
                self.entries.shift_remove(&first_key);
            }
        }
        self.entries.insert(key, (result, std::time::Instant::now()));
    }
}

impl Jail {
    /// Process a single log line: filter → FailManager → BanManager → actions.
    async fn process_line(&self, line: &str) -> Result<(), crate::Error> {
        let mut result = {
            let mut buf = self.line_buffer.lock();
            match self.filter.process_buffered(&mut buf, line) {
                Ok(Some(r)) => r,
                Ok(None) => return Ok(()),
                Err(e) => {
                    tracing::debug!("filter error: {e}");
                    return Ok(());
                }
            }
        };

        if result.mlfforget {
            if let Some(mlfid) = &result.mlfid {
                self.fail_mgr.forget_mlfid(mlfid);
            }
            return Ok(());
        }

        // usedns: if the captured <HOST> is not an IP, attempt DNS resolution
        // (or skip, depending on the setting).
        if result.ip.is_none() && !result.host.is_empty() {
            match self.config.usedns.as_str() {
                "no" => {
                    // Non-IP host with usedns=no: skip entirely.
                    tracing::debug!(
                        "jail {}: skipping non-IP host {:?} (usedns=no)",
                        self.config.name,
                        result.host
                    );
                    return Ok(());
                }
                "yes" | "warn" => {
                    if let Some(ip) = self.resolve_dns(&result.host).await {
                        result.ip = Some(ip);
                    } else if self.config.usedns == "warn" {
                        tracing::warn!(
                            "jail {}: could not resolve host {:?} (usedns=warn)",
                            self.config.name,
                            result.host
                        );
                    }
                }
                _ => { /* "raw" or other: treat as raw failure ID */ }
            }
        }

        // Ignoreip / ignoreself / ignorecommand filtering happens at ban time.

        let bantime_secs = self.compute_bantime(&result);
        if let Some(ticket) = self.fail_mgr.add_failure(&result) {
            // Pre-ban checks: ignoreip / ignoreself / ignorecommand.
            if let Some(ip) = ticket.ip {
                if self.config.ignoreself && is_own_ip(ip) {
                    self.fail_mgr.remove(&ticket.host);
                    return Ok(());
                }
                if self.config.ignoreip.matches_ip(&ip) {
                    self.fail_mgr.remove(&ticket.host);
                    return Ok(());
                }
                if self.check_ignorecommand(&ip.to_string()).await {
                    self.fail_mgr.remove(&ticket.host);
                    return Ok(());
                }
            } else if self.config.ignoreip.matches_raw(&ticket.host)
                || self.check_ignorecommand(&ticket.host).await
            {
                self.fail_mgr.remove(&ticket.host);
                return Ok(());
            }
            self.issue_ban(ticket, &result, bantime_secs).await?;
        }
        Ok(())
    }

    /// Run the `ignorecommand` against the given IP/host.
    ///
    /// Returns `true` when the command exits 0 (meaning "ignore this IP").
    /// Honors the `ignorecache` setting to avoid redundant invocations.
    async fn check_ignorecommand(&self, ip: &str) -> bool {
        let Some(cmd_template) = &self.config.ignorecommand else {
            return false;
        };
        // Check cache first.
        if let Some(cached) = self.ignore_cache.lock().as_ref().and_then(|c| c.get(ip)) {
            return cached;
        }
        let cmd = cmd_template.replace("<ip>", ip);
        let result = run_ignore_command(&cmd).await;
        // Store in cache.
        if let Some(cache) = self.ignore_cache.lock().as_mut() {
            cache.insert(ip.to_string(), result);
        }
        result
    }

    /// Resolve a hostname to an IP address (first A/AAAA record).
    /// Uses a 3-second timeout to avoid blocking the pipeline.
    async fn resolve_dns(&self, host: &str) -> Option<IpAddr> {
        // Skip obviously non-hostname strings (empty, numeric-only, etc.)
        if host.is_empty() || host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return host.parse().ok();
        }
        let host_owned = host.to_string();
        let result = tokio::task::spawn_blocking(move || {
            // Use std::net::ToSocketAddrs for synchronous DNS resolution.
            use std::net::ToSocketAddrs;
            (host_owned.as_str(), 0u16)
                .to_socket_addrs()
                .ok()?
                .map(|sa| sa.ip())
                .next()
        })
        .await;
        match result {
            Ok(ip) => ip,
            Err(e) => {
                tracing::debug!("DNS resolution task failed for {host}: {e}");
                None
            }
        }
    }

    async fn issue_ban(
        &self,
        fail: FailTicket,
        matches: &MatchResult,
        bantime_secs: Option<u64>,
    ) -> Result<(), crate::Error> {
        let ticket = ticket_from_fail(&fail, matches, bantime_secs);
        let host = ticket.host.clone();
        let ctx = BanContext {
            ip: ticket.host.clone(),
            ip_addr: ticket.ip,
            family: ticket
                .ip
                .map(crate::ip::family_of)
                .unwrap_or(IpFamily::Inet4),
            user: ticket.user.clone(),
            alt_user: ticket.alt_user.clone(),
            fid: if ticket.ip.is_none() {
                Some(ticket.host.clone())
            } else {
                None
            },
            bantime: bantime_secs,
            matches: ticket.matches.clone(),
            failures: ticket.failures,
        };

        // Persist to DB.
        if let Some(db) = &self.db {
            let data = serde_json::json!({
                "user": ticket.user,
                "matches": ticket.matches,
            })
            .to_string();
            let _ = db.add_ban(
                &self.config.name,
                &host,
                ticket.time_of_ban.timestamp(),
                bantime_secs.map(|s| s as i64),
                &data,
            );
        }

        // Execute actions.
        for a in &mut self.actions.iter() {
            let mut a = a.clone();
            // actioncheck → actionrepair → retry check, per fail2ban behavior.
            match ActionExecutor::check(&a, &ctx).await {
                Ok(true) => { /* check passed, proceed to ban */ }
                Ok(false) => { /* no check configured, proceed to ban */ }
                Err(e) => {
                    tracing::warn!(
                        "jail {}: actioncheck {} failed for {host}: {e}, running actionrepair",
                        self.config.name,
                        a.name
                    );
                    if let Err(re) = ActionExecutor::repair(&a, &ctx).await {
                        tracing::error!(
                            "jail {}: actionrepair {} failed for {host}: {re}",
                            self.config.name,
                            a.name
                        );
                        // Skip ban for this action since check/repair failed.
                        continue;
                    }
                    // Retry check after repair.
                    if let Err(e2) = ActionExecutor::check(&a, &ctx).await {
                        tracing::error!(
                            "jail {}: actioncheck {} still failing after repair for {host}: {e2}",
                            self.config.name,
                            a.name
                        );
                        continue;
                    }
                }
            }
            if let Err(e) = ActionExecutor::ban(&mut a, &ctx).await {
                tracing::error!(
                    "jail {}: actionban {} failed for {host}: {e}",
                    self.config.name,
                    a.name
                );
            }
        }

        self.ban_mgr.add_ban(ticket);
        self.fail_mgr.remove(&host);
        tracing::info!(
            "jail {}: BAN {} for {:?}s",
            self.config.name,
            host,
            bantime_secs
        );
        Ok(())
    }

    async fn manual_ban(&self, ip: &str) -> Result<(), crate::Error> {
        let parsed: Option<IpAddr> = ip.parse().ok();
        let ctx = BanContext {
            ip: ip.to_string(),
            ip_addr: parsed,
            family: parsed
                .map(crate::ip::family_of)
                .unwrap_or(IpFamily::Inet4),
            user: None,
            alt_user: None,
            fid: if parsed.is_none() { Some(ip.to_string()) } else { None },
            bantime: self.compute_bantime(&MatchResult {
                host: ip.to_string(),
                ip: parsed,
                user: None,
                alt_user: None,
                mlfid: None,
                timestamp: Some(Utc::now()),
                nofail: false,
                mlfforget: false,
                mlfgained: false,
                line: String::new(),
                regex_index: 0,
            }),
            matches: vec![],
            failures: 0,
        };
        for a in &mut self.actions.iter() {
            let mut a = a.clone();
            let _ = ActionExecutor::ban(&mut a, &ctx).await;
        }
        let ticket = BanTicket {
            host: ip.to_string(),
            ip: parsed,
            user: None,
            alt_user: None,
            mlfid: None,
            time_of_ban: Utc::now(),
            bantime: ctx.bantime.map(|s| chrono::Duration::seconds(s as i64)),
            matches: vec![],
            failures: 0,
        };
        self.ban_mgr.add_ban(ticket);
        Ok(())
    }

    async fn manual_unban(&self, ip: &str) -> Result<(), crate::Error> {
        if self.ban_mgr.remove_ban(ip).is_some() {
            if let Some(db) = &self.db {
                let _ = db.remove_ban(&self.config.name, ip);
            }
            let ctx = BanContext {
                ip: ip.to_string(),
                ip_addr: ip.parse().ok(),
                family: crate::ip::family_of_or_default(ip),
                user: None,
                alt_user: None,
                fid: None,
                bantime: None,
                matches: vec![],
                failures: 0,
            };
            for a in &mut self.actions.iter() {
                let mut a = a.clone();
                let _ = ActionExecutor::unban(&mut a, &ctx).await;
            }
        }
        Ok(())
    }

    /// Flush all bans: run `actionflush` for each action (if configured),
    /// then clear the BanManager. Actions without `actionflush` fall back to
    /// per-IP `actionunban`.
    async fn flush_all_bans(&self) -> Result<(), crate::Error> {
        let tickets = self.ban_mgr.clear();
        if let Some(db) = &self.db {
            // Remove all bans for this jail from DB.
            for t in &tickets {
                let _ = db.remove_ban(&self.config.name, &t.host);
            }
        }
        // Try actionflush first; if not configured, fall back to per-IP unban.
        let mut any_flush = false;
        for a in &self.actions {
            if a.config.actionflush.is_some() {
                any_flush = true;
                let a = a.clone();
                if let Err(e) = ActionExecutor::flush(&a).await {
                    tracing::warn!(
                        "jail {}: actionflush {} failed: {e}",
                        self.config.name,
                        a.name
                    );
                }
            }
        }
        // If no actionflush configured, run per-IP actionunban.
        if !any_flush {
            for ticket in &tickets {
                let ctx = BanContext {
                    ip: ticket.host.clone(),
                    ip_addr: ticket.ip,
                    family: ticket
                        .ip
                        .map(crate::ip::family_of)
                        .unwrap_or(IpFamily::Inet4),
                    user: ticket.user.clone(),
                    alt_user: ticket.alt_user.clone(),
                    fid: if ticket.ip.is_none() {
                        Some(ticket.host.clone())
                    } else {
                        None
                    },
                    bantime: ticket.bantime.map(|d| d.num_seconds().max(0) as u64),
                    matches: ticket.matches.clone(),
                    failures: ticket.failures,
                };
                for a in &self.actions {
                    let mut a = a.clone();
                    let _ = ActionExecutor::unban(&mut a, &ctx).await;
                }
            }
        }
        if !tickets.is_empty() {
            tracing::info!(
                "jail {}: FLUSH {} bans",
                self.config.name,
                tickets.len()
            );
        }
        Ok(())
    }

    async fn manual_attempt(&self, ip: &str, _failures: &[String]) -> Result<(), crate::Error> {
        let m = MatchResult {
            host: ip.to_string(),
            ip: ip.parse().ok(),
            user: None,
            alt_user: None,
            mlfid: None,
            timestamp: Some(Utc::now()),
            nofail: false,
            mlfforget: false,
            mlfgained: false,
            line: format!("manual attempt from {ip}"),
            regex_index: 0,
        };
        if let Some(ticket) = self.fail_mgr.add_failure(&m) {
            let bantime = self.compute_bantime(&m);
            self.issue_ban(ticket, &m, bantime).await?;
        }
        Ok(())
    }

    /// Restore a ban from the database (does NOT run actionban, since the
    /// firewall rule is presumed to still be in effect).
    async fn restore_ban(
        &self,
        ip: &str,
        ip_addr: Option<IpAddr>,
        time_of_ban_epoch: i64,
        bantime_secs: Option<i64>,
    ) -> Result<(), crate::Error> {
        let time_of_ban = chrono::DateTime::<Utc>::from_timestamp(time_of_ban_epoch, 0)
            .unwrap_or_else(Utc::now);
        let bantime = bantime_secs.map(|s| chrono::Duration::seconds(s));
        let ticket = BanTicket {
            host: ip.to_string(),
            ip: ip_addr,
            user: None,
            alt_user: None,
            mlfid: None,
            time_of_ban,
            bantime,
            matches: vec![],
            failures: 0,
        };
        // Check if already expired.
        if ticket.is_expired(Utc::now()) {
            if let Some(db) = &self.db {
                let _ = db.remove_ban(&self.config.name, ip);
            }
            return Ok(());
        }
        self.ban_mgr.add_ban(ticket);
        tracing::debug!("jail {}: restored ban for {ip}", self.config.name);
        Ok(())
    }

    fn compute_bantime(&self, _m: &MatchResult) -> Option<u64> {
        let base = self.config.bantime.to_seconds_or_max();
        if self.config.bantime_increment {
            // Simple increment: base * factor^(ban_count). Look up history in DB.
            let factor = self.config.bantime_factor.max(1) as u64;
            let ban_count = self
                .db
                .as_ref()
                .and_then(|db| db.ban_count(&self.config.name, &_m.host).ok())
                .unwrap_or(0);
            let inc = base.saturating_mul(factor.saturating_pow(ban_count as u32));
            let inc = if let Some(max) = self.config.bantime_maxtime {
                inc.min(max.to_seconds_or_max())
            } else {
                inc
            };
            // Optional random jitter (dodge synchronized retries).
            let inc = if let Some(rnd) = self.config.bantime_rndtime {
                let rnd_secs = rnd.to_seconds_or_max();
                if rnd_secs > 0 {
                    inc + rand_u64_below(rnd_secs)
                } else {
                    inc
                }
            } else {
                inc
            };
            Some(inc)
        } else {
            Some(base)
        }
    }

    /// Purge expired bans: run `actionunban` for each, remove from DB.
    pub async fn purge_expired_bans(&self) -> Result<(), crate::Error> {
        let now = Utc::now();
        let expired = self.ban_mgr.expired(now);
        for ticket in expired {
            let host = ticket.host.clone();
            // Run actionunban for each action.
            let ctx = BanContext {
                ip: ticket.host.clone(),
                ip_addr: ticket.ip,
                family: ticket
                    .ip
                    .map(crate::ip::family_of)
                    .unwrap_or(IpFamily::Inet4),
                user: ticket.user.clone(),
                alt_user: ticket.alt_user.clone(),
                fid: if ticket.ip.is_none() {
                    Some(ticket.host.clone())
                } else {
                    None
                },
                bantime: ticket.bantime.map(|d| d.num_seconds().max(0) as u64),
                matches: ticket.matches.clone(),
                failures: ticket.failures,
            };
            for a in &self.actions {
                let mut a = a.clone();
                if let Err(e) = ActionExecutor::unban(&mut a, &ctx).await {
                    tracing::warn!(
                        "jail {}: actionunban {} for {host}: {e}",
                        self.config.name,
                        a.name
                    );
                }
            }
            if let Some(db) = &self.db {
                let _ = db.remove_ban(&self.config.name, &host);
            }
            tracing::info!("jail {}: UNBAN {} (expired)", self.config.name, host);
        }
        // Also purge old failure entries.
        self.fail_mgr.purge();
        Ok(())
    }
}

/// Generate a pseudo-random u64 in `[0, n)`. Uses a simple thread-local
/// seed derived from time (sufficient for jitter; not crypto-grade).
fn rand_u64_below(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new({
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xDEAD_BEEF_CAFE_F00D);
            now.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        });
    }
    STATE.with(|s| {
        let mut x = s.get();
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x % n
    })
}

impl Jail {
    /// Spawn a jail: opens backends, starts the filter pipeline, listens for
    /// [`JailCommand`]s.
    pub async fn spawn(
        config: JailConfig,
        filter: CompiledFilter,
        actions: Vec<Action>,
        db: Option<Arc<Database>>,
    ) -> Result<JailHandle, crate::Error> {
        let name = config.name.clone();
        let maxretry = config.maxretry;
        let findtime = config.findtime.to_seconds_or_max() as i64;
        let maxmatches = config.maxmatches;
        let maxlines = filter.maxlines;
        let ignore_cache = config
            .ignorecache
            .as_deref()
            .and_then(IgnoreCache::parse);

        let mut jail = Self {
            config: config.clone(),
            filter,
            actions,
            fail_mgr: Arc::new(FailManager::new(maxretry, findtime, maxmatches)),
            ban_mgr: Arc::new(BanManager::new()),
            db,
            line_buffer: Mutex::new(LineBuffer::new(maxlines)),
            ignore_cache: Mutex::new(ignore_cache),
        };

        // Run actionstart for each action.
        for a in &mut jail.actions {
            if let Err(e) = ActionExecutor::start(a, false).await {
                tracing::error!("jail {}: actionstart {} failed: {e}", name, a.name);
            }
        }

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<JailCommand>(32);

        // Start the backend(s).
        let (log_tx, mut log_rx) = mpsc::channel::<crate::backend::LogLine>(1024);

        let jail_arc = Arc::new(jail);
        let jail_for_task = jail_arc.clone();
        let ban_mgr_handle = jail_arc.ban_mgr.clone();
        let fail_mgr_handle = jail_arc.fail_mgr.clone();
        let log_tx_clone = log_tx.clone();
        let config_for_backend = config.clone();

        // Spawn each logpath as its own backend task.
        let backend_task = tokio::spawn(async move {
            if let Err(e) = spawn_backends(&config_for_backend, log_tx_clone).await {
                tracing::error!("jail {}: backend error: {e}", config_for_backend.name);
            }
        });

        let name_for_task = name.clone();
        // Purge interval: check expired bans every 30s (or more often for short bantimes).
        let purge_interval = std::time::Duration::from_secs(30);
        let join = tokio::spawn(async move {
            let jail = jail_for_task;
            let mut purge_ticker = tokio::time::interval(purge_interval);
            purge_ticker.tick().await; // skip immediate first tick
            loop {
                tokio::select! {
                    Some(line) = log_rx.recv() => {
                        if let Err(e) = jail.process_line(&line.text).await {
                            tracing::warn!("jail {}: process_line error: {e}", name_for_task);
                        }
                    }
                    Some(cmd) = cmd_rx.recv() => {
                        match cmd {
                            JailCommand::Stop => break,
                            JailCommand::BanIp { ip } => {
                                if let Err(e) = jail.manual_ban(&ip).await {
                                    tracing::warn!("jail {}: manual ban {ip}: {e}", name_for_task);
                                }
                            }
                            JailCommand::UnbanIp { ip } => {
                                if let Err(e) = jail.manual_unban(&ip).await {
                                    tracing::warn!("jail {}: manual unban {ip}: {e}", name_for_task);
                                }
                            }
                            JailCommand::FlushAll => {
                                if let Err(e) = jail.flush_all_bans().await {
                                    tracing::warn!("jail {}: flush all bans: {e}", name_for_task);
                                }
                            }
                            JailCommand::Attempt { ip, failures } => {
                                if let Err(e) = jail.manual_attempt(&ip, &failures).await {
                                    tracing::warn!("jail {}: manual attempt {ip}: {e}", name_for_task);
                                }
                            }
                            JailCommand::RestoreBan { ip, ip_addr, time_of_ban, bantime } => {
                                if let Err(e) = jail.restore_ban(&ip, ip_addr, time_of_ban, bantime).await {
                                    tracing::warn!("jail {}: restore ban {ip}: {e}", name_for_task);
                                }
                            }
                        }
                    }
                    _ = purge_ticker.tick() => {
                        if let Err(e) = jail.purge_expired_bans().await {
                            tracing::debug!("jail {}: purge error: {e}", name_for_task);
                        }
                    }
                    else => break,
                }
            }
            // Final purge on shutdown.
            let _ = jail.purge_expired_bans().await;
            // Run actionstop for each action.
            for a in &jail.actions {
                let mut a = a.clone();
                if let Err(e) = ActionExecutor::stop(&mut a).await {
                    tracing::warn!("jail {}: actionstop {}: {e}", name_for_task, a.name);
                }
            }
            // Stop actions on shutdown.
            let _ = backend_task.await;
            tracing::info!("jail {} stopped", name_for_task);
        });

        Ok(JailHandle {
            name,
            cmd_tx,
            ban_mgr: ban_mgr_handle,
            fail_mgr: fail_mgr_handle,
            join: Some(join),
        })
    }
}

/// Spawn the backends for a jail based on its config.
async fn spawn_backends(
    config: &JailConfig,
    tx: mpsc::Sender<crate::backend::LogLine>,
) -> Result<(), crate::Error> {
    if config.logpath.is_empty() && config.backend == "auto" && config.systemd_if_nologs {
        let backend = JournalBackend::new(config.journalmatch.clone());
        let _ = backend.run(tx).await;
        return Ok(());
    }
    let paths: Vec<PathBuf> = config
        .logpath
        .iter()
        .flat_map(|p| glob::glob(p).ok().into_iter().flatten())
        .filter_map(|r| r.ok())
        .collect();
    if paths.is_empty() {
        if config.skip_if_nologs {
            tracing::warn!(
                "jail {}: no log files found; skipping (skip_if_nologs=true)",
                config.name
            );
            return Ok(());
        }
        if config.systemd_if_nologs && config.backend == "auto" {
            tracing::info!(
                "jail {}: no log files found; switching to systemd backend",
                config.name
            );
            let backend = JournalBackend::new(config.journalmatch.clone());
            let _ = backend.run(tx).await;
            return Ok(());
        }
        return Err(crate::Error::config(format!(
            "jail {}: no log files found for {:?}",
            config.name, config.logpath
        )));
    }
    let backend = FileBackend::new(paths, false);
    let _ = backend.run(tx).await;
    Ok(())
}

/// Detect whether an IP is one of the local machine's IPs.
fn is_own_ip(ip: IpAddr) -> bool {
    // Simple implementation: 127.x and ::1 are always "own".
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Run an ignorecommand and return `true` when it exits 0 (ignore the IP).
async fn run_ignore_command(cmd: &str) -> bool {
    let argv = match shlex::split(cmd) {
        Some(v) if !v.is_empty() => v,
        _ => {
            tracing::warn!("ignorecommand: invalid command line: {cmd}");
            return false;
        }
    };
    tracing::debug!("ignorecommand exec: {:?}", argv);
    let mut command = tokio::process::Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    command.kill_on_drop(true);
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        command.status(),
    )
    .await
    {
        Ok(Ok(status)) => status.success(),
        Ok(Err(e)) => {
            tracing::warn!("ignorecommand {cmd:?}: {e}");
            false
        }
        Err(_) => {
            tracing::warn!("ignorecommand {cmd:?}: timed out");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_cache_parse_and_lookup() {
        let mut c = IgnoreCache::parse(r#"key="ip", max-count=2, max-time=1h"#).unwrap();
        assert_eq!(c.max_count, 2);
        assert!(c.get("1.2.3.4").is_none());
        c.insert("1.2.3.4".into(), true);
        assert_eq!(c.get("1.2.3.4"), Some(true));
        c.insert("5.6.7.8".into(), false);
        assert_eq!(c.get("5.6.7.8"), Some(false));
        // Eviction: third insert evicts oldest (1.2.3.4).
        c.insert("9.10.11.12".into(), true);
        assert!(c.get("1.2.3.4").is_none(), "oldest should be evicted");
        assert_eq!(c.get("9.10.11.12"), Some(true));
    }

    #[test]
    fn ignore_cache_empty_spec() {
        assert!(IgnoreCache::parse("").is_none());
        assert!(IgnoreCache::parse("   ").is_none());
    }
}
