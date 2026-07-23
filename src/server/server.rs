//! The rail2ban server: owns the configuration, runs jails, and serves
//! client requests over a Unix socket.

use crate::action::Action;
use crate::config::LoadedConfig;
use crate::error::{Error, Result};
use crate::filter::CompiledFilter;
use crate::server::database::Database;
use crate::server::jail::{Jail, JailCommand, JailHandle};
#[cfg(unix)]
use crate::server::commands::dispatch;
#[cfg(unix)]
use crate::protocol::{Request, Response};
use parking_lot::RwLock;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

/// The rail2ban server.
pub struct Server {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    config: RwLock<LoadedConfig>,
    jails: Mutex<Vec<JailHandle>>,
    db: Mutex<Option<Arc<Database>>>,
    loglevel: RwLock<String>,
    logtarget: RwLock<String>,
    dbfile: RwLock<String>,
    dbmaxmatches: RwLock<u32>,
    dbpurgeage: RwLock<u64>,
    /// Sender to stop the server task.
    stop_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Configuration search directories (for `reload`).
    search_dirs: RwLock<Vec<std::path::PathBuf>>,
}

impl Server {
    /// Build a new server from a loaded configuration.
    pub fn new(config: LoadedConfig) -> Self {
        let global = config.global.clone();
        Self {
            inner: Arc::new(ServerInner {
                config: RwLock::new(config),
                jails: Mutex::new(vec![]),
                db: Mutex::new(None),
                loglevel: RwLock::new(global.loglevel.clone()),
                logtarget: RwLock::new(global.logtarget.clone()),
                dbfile: RwLock::new(global.dbfile.clone()),
                dbmaxmatches: RwLock::new(global.dbmaxmatches),
                dbpurgeage: RwLock::new(global.dbpurgeage),
                stop_tx: Mutex::new(None),
                search_dirs: RwLock::new(vec![]),
            }),
        }
    }

    /// Set the configuration search directories (enables `reload`).
    pub fn set_search_dirs(&self, dirs: Vec<std::path::PathBuf>) {
        *self.inner.search_dirs.write() = dirs;
    }

    /// Return the configuration search directories as a comma-joined string.
    pub fn config_path(&self) -> String {
        self.inner
            .search_dirs
            .read()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Open the database and restore bans.
    pub async fn init_db(&self) -> Result<()> {
        let path = {
            let inner = self.inner.config.read();
            inner.global.dbfile.clone()
        };
        if path.eq_ignore_ascii_case("none") || path.is_empty() {
            return Ok(());
        }
        let p = std::path::PathBuf::from(&path);
        let db = Database::open(Some(&p))?;
        let arc = Arc::new(db);
        *self.inner.db.lock().await = Some(arc);
        Ok(())
    }

    /// Start all enabled jails.
    pub async fn start_all_enabled(&self) -> Result<usize> {
        let names: Vec<String> = {
            let cfg = self.inner.config.read();
            cfg.jails
                .jails
                .iter()
                .filter(|(_, j)| j.enabled)
                .map(|(n, _)| n.clone())
                .collect()
        };
        let mut count = 0;
        for name in names {
            if let Err(e) = self.start_jail(&name).await {
                tracing::error!("failed to start jail {name}: {e}");
            } else {
                count += 1;
            }
        }
        // Restore bans from the database after all jails are started.
        self.restore_bans_from_db().await;
        Ok(count)
    }

    /// Restore bans from the database into the appropriate jail BanManagers.
    /// Called after all jails have been started.
    pub async fn restore_bans_from_db(&self) {
        let db = self.inner.db.lock().await.clone();
        let Some(db) = db else { return };
        let bans = match db.list_bans() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("failed to read bans from database: {e}");
                return;
            }
        };
        let jails = self.inner.jails.lock().await;
        let mut restored = 0u64;
        for ban in &bans {
            if let Some(h) = jails.iter().find(|j| j.name == ban.jail) {
                let ip_addr: Option<IpAddr> = ban.ip.parse().ok();
                let _ = h
                    .cmd_tx
                    .send(JailCommand::RestoreBan {
                        ip: ban.ip.clone(),
                        ip_addr,
                        time_of_ban: ban.time_of_ban,
                        bantime: ban.bantime,
                    })
                    .await;
                restored += 1;
            }
        }
        if restored > 0 {
            tracing::info!("restored {restored} bans from database");
        }
    }

    /// Start a single jail by name.
    pub async fn start_jail(&self, name: &str) -> Result<()> {
        // Check whether it's already running.
        if self.get_jail(name).await.is_some() {
            return Err(Error::Jail(format!("{name} already running")));
        }
        let (jail_cfg, filter_cfg, action_defs) = {
            let cfg = self.inner.config.read();
            let jail_cfg = cfg
                .jails
                .jails
                .get(name)
                .cloned()
                .ok_or_else(|| Error::Jail(format!("unknown jail: {name}")))?;
            let filter_def = cfg
                .filters
                .get(&jail_cfg.filter)
                .ok_or_else(|| Error::Jail(format!("filter {} not loaded", jail_cfg.filter)))?;
            let filter_cfg = filter_def.materialize(
                &jail_cfg.filter_params,
                &cfg.jails.defaults,
                &cfg.defaults,
            )?;
            let mut action_defs = Vec::new();
            for spec in &jail_cfg.actions {
                let an = crate::config::loader::action_name(spec);
                if an.is_empty() {
                    continue;
                }
                let params = crate::config::loader::action_params(spec)?;
                if let Some(def) = cfg.actions.get(an) {
                    action_defs.push((def.clone(), params));
                }
            }
            (jail_cfg, filter_cfg, action_defs)
        };

        let compiled_filter = CompiledFilter::compile(filter_cfg)?;
        let db = self.inner.db.lock().await.clone();

        let mut actions = Vec::new();
        for (def, params) in action_defs {
            let cfg = def.materialize(&params, &self.inner.config.read().jails.defaults, &self.inner.config.read().defaults, None)?;
            actions.push(Action::new(name, cfg));
        }

        let handle = Jail::spawn(jail_cfg, compiled_filter, actions, db).await?;
        self.inner.jails.lock().await.push(handle);
        tracing::info!("jail {name} started");
        Ok(())
    }

    /// Stop a single jail.
    pub async fn stop_jail(&self, name: &str) -> Result<()> {
        let mut jails = self.inner.jails.lock().await;
        let idx = jails.iter().position(|h| h.name == name);
        if let Some(idx) = idx {
            let h = jails.remove(idx);
            let _ = h.cmd_tx.send(JailCommand::Stop).await;
            if let Some(join) = h.join {
                let _ = join.await;
            }
            Ok(())
        } else {
            Err(Error::Jail(format!("{name} not running")))
        }
    }

    /// Restart a single jail: stop then start.
    pub async fn restart_jail(&self, name: &str) -> Result<()> {
        // Best-effort stop (ignore "not running" error).
        let _ = self.stop_jail(name).await;
        self.start_jail(name).await
    }

    /// Reload configuration from disk and restart all jails.
    pub async fn reload_config(&self, new_config: LoadedConfig) -> Result<usize> {
        // Stop all running jails.
        self.stop_all().await;
        // Replace configuration.
        {
            let mut cfg = self.inner.config.write();
            *cfg = new_config;
            let global = cfg.global.clone();
            *self.inner.loglevel.write() = global.loglevel;
            *self.inner.logtarget.write() = global.logtarget;
            *self.inner.dbfile.write() = global.dbfile;
            *self.inner.dbmaxmatches.write() = global.dbmaxmatches;
            *self.inner.dbpurgeage.write() = global.dbpurgeage;
        }
        // Reopen database.
        self.init_db().await?;
        // Start all enabled jails.
        self.start_all_enabled().await
    }

    /// Stop all jails.
    pub async fn stop_all(&self) {
        let mut jails = self.inner.jails.lock().await;
        for h in jails.drain(..) {
            let _ = h.cmd_tx.send(JailCommand::Stop).await;
            if let Some(join) = h.join {
                let _ = join.await;
            }
        }
    }

    /// Add a new jail at runtime.
    pub async fn add_jail(&self, name: &str, _backend: &str) -> Result<()> {
        let jail_cfg = {
            let cfg = self.inner.config.read();
            cfg.jails.jails.get(name).cloned()
        };
        match jail_cfg {
            Some(j) => self.start_jail(&j.name).await,
            None => Err(Error::Jail(format!("unknown jail: {name}"))),
        }
    }

    /// List all running jails.
    pub async fn list_jails(&self) -> Vec<JailHandle> {
        // We can't clone JailHandle (it owns a JoinHandle); return lightweight
        // copies sharing the managers (join is None — callers must not await
        // shutdown through these copies).
        let jails = self.inner.jails.lock().await;
        jails
            .iter()
            .map(|h| JailHandle {
                name: h.name.clone(),
                cmd_tx: h.cmd_tx.clone(),
                ban_mgr: h.ban_mgr.clone(),
                fail_mgr: h.fail_mgr.clone(),
                join: None,
            })
            .collect()
    }

    /// Get a running jail handle by name.
    pub async fn get_jail(&self, name: &str) -> Option<JailHandle> {
        let jails = self.inner.jails.lock().await;
        jails.iter().find(|h| h.name == name).map(|h| JailHandle {
            name: h.name.clone(),
            cmd_tx: h.cmd_tx.clone(),
            ban_mgr: h.ban_mgr.clone(),
            fail_mgr: h.fail_mgr.clone(),
            join: None,
        })
    }

    /// Stats for a jail.
    pub async fn jail_stats(&self, handle: &JailHandle) -> serde_json::Value {
        let cfg = self.inner.config.read();
        let j = cfg.jails.jails.get(&handle.name);
        let snapshot = handle.ban_mgr.snapshot();
        let banned_ips: Vec<&str> = snapshot.iter().map(|t| t.host.as_str()).collect();
        let banned_detail: Vec<serde_json::Value> = snapshot
            .iter()
            .map(|t| {
                json!({
                    "ip": t.host,
                    "time_of_ban": t.time_of_ban.timestamp(),
                    "bantime": t.bantime.map(|d| d.num_seconds()),
                    "failures": t.failures,
                    "matches": t.matches,
                })
            })
            .collect();
        json!({
            "jail": handle.name,
            "enabled": j.map(|j| j.enabled).unwrap_or(false),
            "filter": j.map(|j| j.filter.clone()).unwrap_or_default(),
            "logpath": j.map(|j| j.logpath.clone()).unwrap_or_default(),
            "maxretry": j.map(|j| j.maxretry).unwrap_or(0),
            "maxmatches": j.map(|j| j.maxmatches).unwrap_or(0),
            "findtime": j.map(|j| j.findtime.to_seconds_or_max()).unwrap_or(0),
            "bantime": j.map(|j| j.bantime.to_seconds_or_max()).unwrap_or(0),
            "usedns": j.map(|j| j.usedns.clone()).unwrap_or_default(),
            "currently_banned": handle.ban_mgr.current_banned(),
            "total_banned": handle.ban_mgr.total_banned(),
            "currently_failed": handle.fail_mgr.current_failed(),
            "total_failed": handle.fail_mgr.total_failed(),
            "banned_ips": banned_ips,
            "banned_list": banned_detail,
        })
    }

    /// Get a jail attribute (used by `get <JAIL> <KEY>`).
    pub async fn get_jail_attr(&self, handle: &JailHandle, key: &str) -> String {
        let cfg = self.inner.config.read();
        let j = match cfg.jails.jails.get(&handle.name) {
            Some(j) => j,
            None => return String::new(),
        };
        match key {
            "logpath" => j.logpath.join(" "),
            "logencoding" => j.logencoding.clone(),
            "journalmatch" => j.journalmatch.join(" + "),
            "ignoreself" => j.ignoreself.to_string(),
            "ignoreip" => j
                .ignoreip
                .iter()
                .map(|e| match e {
                    crate::ip::IgnoreEntry::Net(n) => n.to_string(),
                    crate::ip::IgnoreEntry::Ip(ip) => ip.to_string(),
                    crate::ip::IgnoreEntry::Raw(s) => s.clone(),
                })
                .collect::<Vec<_>>()
                .join(" "),
            "ignorecommand" => j.ignorecommand.clone().unwrap_or_default(),
            "ignorecache" => j.ignorecache.clone().unwrap_or_default(),
            "failregex" => String::new(), // from compiled filter
            "ignoreregex" => String::new(),
            "findtime" => j.findtime.to_seconds_or_max().to_string(),
            "bantime" => j.bantime.to_seconds_or_max().to_string(),
            "usedns" => j.usedns.clone(),
            "maxretry" => j.maxretry.to_string(),
            "maxmatches" => j.maxmatches.to_string(),
            "maxlines" => j.maxlines.to_string(),
            "actions" => j.actions.join(", "),
            _ => j.extra.get(key).cloned().unwrap_or_default(),
        }
    }

    /// Unban an IP across all jails that actually have it banned.
    pub async fn unban_ip(&self, ip: &str) -> bool {
        let mut found = false;
        let jails = self.inner.jails.lock().await;
        for h in jails.iter() {
            // Only send unban to jails where this IP is actually banned.
            if h.ban_mgr.is_banned(ip) {
                let _ = h.cmd_tx.send(JailCommand::UnbanIp { ip: ip.into() }).await;
                found = true;
            }
        }
        if found {
            if let Some(db) = self.inner.db.lock().await.as_ref() {
                let _ = db.remove_ban_all_jails(ip);
            }
        }
        found
    }

    /// Unban all IPs across all jails (uses actionflush when available).
    pub async fn unban_all(&self) {
        let jails = self.inner.jails.lock().await;
        for h in jails.iter() {
            let _ = h.cmd_tx.send(JailCommand::FlushAll).await;
        }
        if let Some(db) = self.inner.db.lock().await.as_ref() {
            let _ = db.remove_all_bans();
        }
    }

    /// Return a map of `jail -> [banned ip]`.
    pub async fn banned_map(&self) -> serde_json::Value {
        let jails = self.inner.jails.lock().await;
        let mut map = serde_json::Map::new();
        for h in jails.iter() {
            let bans: Vec<String> = h
                .ban_mgr
                .snapshot()
                .iter()
                .map(|t| t.host.clone())
                .collect();
            if !bans.is_empty() {
                map.insert(h.name.clone(), json!(bans));
            }
        }
        json!(map)
    }

    /// Return the list of jails in which `ip` is banned.
    pub async fn jails_banning(&self, ip: &str) -> Vec<String> {
        let jails = self.inner.jails.lock().await;
        jails
            .iter()
            .filter(|h| h.ban_mgr.is_banned(ip))
            .map(|h| h.name.clone())
            .collect()
    }

    /// Log level getter.
    pub async fn loglevel(&self) -> String {
        self.inner.loglevel.read().clone()
    }
    /// Log level setter.
    pub async fn set_loglevel(&self, v: String) {
        *self.inner.loglevel.write() = v;
    }
    /// Log target getter.
    pub async fn logtarget(&self) -> String {
        self.inner.logtarget.read().clone()
    }
    /// Log target setter.
    pub async fn set_logtarget(&self, v: String) {
        *self.inner.logtarget.write() = v;
    }
    /// dbfile getter.
    pub async fn dbfile(&self) -> String {
        self.inner.dbfile.read().clone()
    }
    /// dbfile setter.
    pub async fn set_dbfile(&self, v: String) {
        *self.inner.dbfile.write() = v;
    }
    /// dbmaxmatches getter.
    pub async fn dbmaxmatches(&self) -> u32 {
        *self.inner.dbmaxmatches.read()
    }
    /// dbmaxmatches setter.
    pub async fn set_dbmaxmatches(&self, v: u32) {
        *self.inner.dbmaxmatches.write() = v;
    }
    /// dbpurgeage getter.
    pub async fn dbpurgeage(&self) -> u64 {
        *self.inner.dbpurgeage.read()
    }
    /// dbpurgeage setter.
    pub async fn set_dbpurgeage(&self, v: u64) {
        *self.inner.dbpurgeage.write() = v;
    }

    /// Run the IPC server loop on the given socket path. Blocks until the
    /// server is stopped.
    #[cfg(unix)]
    pub async fn run(self: Arc<Self>, socket_path: &str) -> Result<()> {
        // Remove any stale socket file.
        let _ = std::fs::remove_file(socket_path);
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let listener = tokio::net::UnixListener::bind(socket_path)
            .map_err(|e| Error::other(format!("binding {socket_path}: {e}")))?;
        tracing::info!("rail2ban-server listening on {socket_path}");

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        *self.inner.stop_tx.lock().await = Some(stop_tx);

        tokio::spawn(async move {
            if let Ok(()) = stop_rx.await {
                tracing::info!("stop signal received, shutting down");
            }
        });

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, _) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("accept: {e}");
                            continue;
                        }
                    };
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(server, stream).await {
                            tracing::debug!("connection error: {e}");
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("ctrl-c received, shutting down");
                    break;
                }
            }
        }
        self.stop_all().await;
        let _ = std::fs::remove_file(socket_path);
        Ok(())
    }

    /// Run loop on non-Unix platforms: just idle until stopped.
    #[cfg(not(unix))]
    pub async fn run(self: Arc<Self>, _socket_path: &str) -> Result<()> {
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        *self.inner.stop_tx.lock().await = Some(stop_tx);
        let _ = stop_rx.await;
        self.stop_all().await;
        Ok(())
    }

    /// Trigger a graceful shutdown.
    pub async fn shutdown(&self) {
        if let Some(tx) = self.inner.stop_tx.lock().await.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(unix)]
async fn handle_conn(server: Arc<Server>, stream: tokio::net::UnixStream) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::err(format!("invalid request: {e}"));
                let json = serde_json::to_string(&resp)?;
                write_half.write_all(json.as_bytes()).await?;
                write_half.write_all(b"\n").await?;
                continue;
            }
        };
        let resp = dispatch(&server, &req).await;
        let json = serde_json::to_string(&resp)?;
        write_half.write_all(json.as_bytes()).await?;
        write_half.write_all(b"\n").await?;
    }
}
