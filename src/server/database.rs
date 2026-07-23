//! SQLite-backed ban persistence.
//!
//! Stores current bans and history so that bans survive server restarts and
//! `bantime_increment` can use prior ban counts.

use crate::error::{Error, Result};
use chrono::Utc;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;
use parking_lot::Mutex;

/// A persistent store of ban tickets.
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open (or create) the database at `path`. `None` disables persistence
    /// (in-memory).
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let conn = match path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            Error::Database(rusqlite::Error::ToSqlConversionFailure(
                                Box::new(e),
                            ))
                        })?;
                    }
                }
                Connection::open(p)?
            }
            None => Connection::open_in_memory()?,
        };
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS bans (
                jail     TEXT NOT NULL,
                ip       TEXT NOT NULL,
                timeofban INTEGER NOT NULL,
                bantime  INTEGER,
                data     TEXT,
                PRIMARY KEY (jail, ip, timeofban)
            );
            CREATE TABLE IF NOT EXISTS bips (
                jail     TEXT NOT NULL,
                ip       TEXT NOT NULL,
                timeofban INTEGER NOT NULL,
                PRIMARY KEY (jail, ip)
            );
            "#,
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a ban record and update the current-ban index (`bips`).
    pub fn add_ban(
        &self,
        jail: &str,
        ip: &str,
        time_of_ban: i64,
        bantime: Option<i64>,
        data: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO bans (jail, ip, timeofban, bantime, data) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![jail, ip, time_of_ban, bantime, data],
        )?;
        // Update the current-ban index (one row per jail+ip).
        conn.execute(
            "INSERT OR REPLACE INTO bips (jail, ip, timeofban) VALUES (?, ?, ?)",
            rusqlite::params![jail, ip, time_of_ban],
        )?;
        Ok(())
    }

    /// Remove a ban record (after unban / expiry) and the corresponding bips entry.
    pub fn remove_ban(&self, jail: &str, ip: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM bans WHERE rowid IN (SELECT rowid FROM bans WHERE jail = ? AND ip = ? ORDER BY timeofban DESC LIMIT 1)",
            rusqlite::params![jail, ip],
        )?;
        conn.execute(
            "DELETE FROM bips WHERE jail = ? AND ip = ?",
            rusqlite::params![jail, ip],
        )?;
        Ok(())
    }

    /// Remove all bans for a given IP across all jails.
    pub fn remove_ban_all_jails(&self, ip: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM bans WHERE ip = ?", rusqlite::params![ip])?;
        conn.execute("DELETE FROM bips WHERE ip = ?", rusqlite::params![ip])?;
        Ok(())
    }

    /// Remove all bans across all jails.
    pub fn remove_all_bans(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM bans", [])?;
        conn.execute("DELETE FROM bips", [])?;
        Ok(())
    }

    /// Return the number of historical bans for `(jail, ip)`.
    /// Used by `bantime_increment` to compute the increment factor.
    pub fn ban_count(&self, jail: &str, ip: &str) -> Result<i64> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM bans WHERE jail = ? AND ip = ?",
            rusqlite::params![jail, ip],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// Purge ban history older than `max_age` seconds. Also cleans up
    /// `bips` entries for bans that have expired (non-permanent bans whose
    /// `timeofban + bantime < now`).
    pub fn purge(&self, max_age_secs: i64) -> Result<()> {
        let now = Utc::now().timestamp();
        let cutoff = now - max_age_secs;
        let conn = self.conn.lock();
        // 1. Remove bips entries for bans that have expired.
        //    A ban is expired if bantime is not NULL and timeofban + bantime < now.
        conn.execute(
            "DELETE FROM bips WHERE (jail, ip, timeofban) IN (
                SELECT jail, ip, timeofban FROM bans
                WHERE bantime IS NOT NULL AND timeofban + bantime < ?1
            )",
            rusqlite::params![now],
        )?;
        // 2. Delete old historical bans not in bips (no longer active).
        conn.execute(
            "DELETE FROM bans WHERE timeofban < ?1 AND (jail, ip, timeofban) NOT IN (
                SELECT jail, ip, timeofban FROM bips
            )",
            rusqlite::params![cutoff],
        )?;
        Ok(())
    }

    /// Return all *current* bans (one per jail+ip, the most recent) for
    /// restore-on-restart. Uses the `bips` table to identify active bans.
    pub fn list_bans(&self) -> Result<Vec<DbBan>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT b.jail, b.ip, b.timeofban, b.bantime, b.data
             FROM bans b
             INNER JOIN bips ON b.jail = bips.jail AND b.ip = bips.ip AND b.timeofban = bips.timeofban
             ORDER BY b.timeofban DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DbBan {
                jail: row.get(0)?,
                ip: row.get(1)?,
                time_of_ban: row.get(2)?,
                bantime: row.get(3)?,
                data: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// A row in the `bans` table.
#[derive(Debug, Clone)]
pub struct DbBan {
    /// Jail name.
    pub jail: String,
    /// IP/failure-ID.
    pub ip: String,
    /// Ban time (epoch seconds).
    pub time_of_ban: i64,
    /// Ban duration in seconds (None = permanent).
    pub bantime: Option<i64>,
    /// JSON-encoded ticket data.
    pub data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_in_memory() {
        let db = Database::open(None).unwrap();
        db.add_ban("sshd", "1.2.3.4", 1000, Some(3600), "{}").unwrap();
        assert_eq!(db.ban_count("sshd", "1.2.3.4").unwrap(), 1);
        db.remove_ban("sshd", "1.2.3.4").unwrap();
        assert_eq!(db.ban_count("sshd", "1.2.3.4").unwrap(), 0);
    }

    #[test]
    fn purge_removes_old() {
        let db = Database::open(None).unwrap();
        let now = Utc::now().timestamp();
        db.add_ban("sshd", "1.2.3.4", now - 100_000, Some(3600), "{}").unwrap();
        db.add_ban("sshd", "5.6.7.8", now, Some(3600), "{}").unwrap();
        db.purge(60).unwrap();
        let bans = db.list_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "5.6.7.8");
    }

    #[test]
    fn list_bans_returns_only_current_via_bips() {
        let db = Database::open(None).unwrap();
        // Simulate 3 historical bans for the same IP (bantime_increment scenario).
        db.add_ban("sshd", "1.2.3.4", 1000, Some(3600), "{}").unwrap();
        db.add_ban("sshd", "1.2.3.4", 2000, Some(3600), "{}").unwrap();
        db.add_ban("sshd", "1.2.3.4", 3000, Some(3600), "{}").unwrap();
        // ban_count sees all 3 historical entries.
        assert_eq!(db.ban_count("sshd", "1.2.3.4").unwrap(), 3);
        // list_bans returns only 1 (the most recent, tracked by bips).
        let bans = db.list_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "1.2.3.4");
        assert_eq!(bans[0].time_of_ban, 3000);
    }

    #[test]
    fn remove_ban_clears_bips() {
        let db = Database::open(None).unwrap();
        db.add_ban("sshd", "1.2.3.4", 1000, Some(3600), "{}").unwrap();
        assert_eq!(db.list_bans().unwrap().len(), 1);
        db.remove_ban("sshd", "1.2.3.4").unwrap();
        assert_eq!(db.list_bans().unwrap().len(), 0);
    }

    #[test]
    fn purge_keeps_active_bans() {
        let db = Database::open(None).unwrap();
        let now = Utc::now().timestamp();
        // Old ban that's still active (in bips).
        db.add_ban("sshd", "1.2.3.4", now - 100_000, Some(999_999), "{}").unwrap();
        db.purge(60).unwrap();
        // Should still be listed because it's active.
        let bans = db.list_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "1.2.3.4");
    }
}
