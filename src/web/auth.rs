//! Authentication and session management for the web interface.
//!
//! Provides:
//! - Argon2-based password hashing (resistant to GPU/ASIC attacks)
//! - Session token management with idle + absolute timeouts
//! - Brute-force protection via per-IP login rate limiting
//! - Admin user storage in a dedicated SQLite database

use argon2::password_hash::{Error as HashError, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Idle session timeout (8 hours of inactivity).
const SESSION_IDLE_TTL: Duration = Duration::from_secs(8 * 3600);
/// Absolute session lifetime (24 hours max, regardless of activity).
const SESSION_ABSOLUTE_TTL: Duration = Duration::from_secs(24 * 3600);
/// Maximum failed login attempts before lockout.
const MAX_LOGIN_ATTEMPTS: u32 = 5;
/// Duration of IP lockout after too many failed attempts.
const LOGIN_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Window for counting failed login attempts (sliding window).
const LOGIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Name of the session cookie.
pub const SESSION_COOKIE_NAME: &str = "rail2ban_session";
/// Minimum password length.
const MIN_PASSWORD_LEN: usize = 8;

/// Authentication error types.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Invalid credentials.
    #[error("invalid username or password")]
    InvalidCredentials,
    /// IP address is locked out due to too many failed attempts.
    #[error("too many failed attempts, try again in {} seconds", secs_remaining)]
    LockedOut {
        /// Seconds remaining until the lockout expires.
        secs_remaining: u64,
    },
    /// Admin user already exists (during setup).
    #[error("admin user already exists")]
    AlreadyExists,
    /// No admin user has been created yet.
    #[error("setup required")]
    SetupRequired,
    /// Password does not meet complexity requirements.
    #[error("password does not meet complexity requirements: {0}")]
    WeakPassword(String),
    /// Old password is incorrect (during password change).
    #[error("current password is incorrect")]
    IncorrectOldPassword,
    /// User not found.
    #[error("user not found")]
    UserNotFound,
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    /// Password hashing error.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),
    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Admin user information (excluding password).
#[derive(Debug, Clone, Serialize)]
pub struct AdminInfo {
    /// Username.
    pub username: String,
    /// Unix timestamp (seconds) of account creation.
    pub created_at: i64,
    /// Unix timestamp (seconds) of last successful login.
    pub last_login: Option<i64>,
}

/// A live session for an authenticated admin.
struct Session {
    /// The username this session belongs to.
    username: String,
    /// When the session was created (absolute expiry = created + SESSION_ABSOLUTE_TTL).
    created_at: Instant,
    /// Time of last API access (idle expiry = last_access + SESSION_IDLE_TTL).
    last_access: Instant,
}

/// SQLite-backed admin user store.
pub struct AuthDb {
    conn: Mutex<Connection>,
}

impl AuthDb {
    /// Open (or create) the auth database at `path`.
    pub fn open(path: &Path) -> Result<Self, AuthError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS admin_users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL,
                last_login    INTEGER
            );
            CREATE TABLE IF NOT EXISTS login_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT,
                ip            TEXT NOT NULL,
                success       INTEGER NOT NULL,
                attempted_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_log_ip ON login_log(ip, attempted_at);
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS admin_users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL,
                last_login    INTEGER
            );
            CREATE TABLE IF NOT EXISTS login_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT,
                ip            TEXT NOT NULL,
                success       INTEGER NOT NULL,
                attempted_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_log_ip ON login_log(ip, attempted_at);
            "#,
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Check whether any admin user exists.
    pub fn admin_exists(&self) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM admin_users",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    /// Create the initial admin user. Fails if one already exists.
    pub fn create_admin(&self, username: &str, password: &str) -> Result<(), AuthError> {
        let hash = hash_password(password)?;
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
            rusqlite::params![username, hash, now, now],
        )?;
        Ok(())
    }

    /// Verify credentials and return the username if valid.
    ///
    /// When the user does not exist, a dummy password hash is still verified
    /// to prevent timing attacks (username enumeration).
    pub fn verify(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        let conn = self.conn.lock();
        let hash: Option<String> = conn
            .query_row(
                "SELECT password_hash FROM admin_users WHERE username = ?",
                rusqlite::params![username],
                |row| row.get(0),
            )
            .ok();
        // Release the DB lock before password verification (CPU-bound).
        drop(conn);
        match hash {
            Some(h) => {
                let parsed = PasswordHash::new(&h)?;
                Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
            }
            None => {
                // Run dummy verification to prevent timing attacks.
                let dummy = get_dummy_hash();
                if let Ok(parsed) = PasswordHash::new(dummy) {
                    let _ = Argon2::default().verify_password(password.as_bytes(), &parsed);
                }
                Ok(false)
            }
        }
    }

    /// Change a user's password after verifying the old one.
    pub fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        if !self.verify(username, old_password)? {
            return Err(AuthError::IncorrectOldPassword);
        }
        let hash = hash_password(new_password)?;
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let affected = conn.execute(
            "UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE username = ?",
            rusqlite::params![hash, now, username],
        )?;
        if affected == 0 {
            return Err(AuthError::UserNotFound);
        }
        Ok(())
    }

    /// Record a login attempt in the audit log.
    pub fn log_attempt(&self, username: Option<&str>, ip: &str, success: bool) {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO login_log (username, ip, success, attempted_at) VALUES (?, ?, ?, ?)",
            rusqlite::params![username, ip, success as i32, now],
        );
    }

    /// Update the `last_login` timestamp for a user.
    pub fn update_last_login(&self, username: &str) {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock();
        let _ = conn.execute(
            "UPDATE admin_users SET last_login = ? WHERE username = ?",
            rusqlite::params![now, username],
        );
    }

    /// Retrieve admin user info.
    pub fn get_admin_info(&self, username: &str) -> Result<AdminInfo, AuthError> {
        let conn = self.conn.lock();
        let row = conn.query_row(
            "SELECT username, created_at, last_login FROM admin_users WHERE username = ?",
            rusqlite::params![username],
            |row| {
                Ok(AdminInfo {
                    username: row.get(0)?,
                    created_at: row.get(1)?,
                    last_login: row.get(2)?,
                })
            },
        )?;
        Ok(row)
    }

    /// Count failed login attempts from `ip` within the sliding window.
    pub fn count_recent_failures(&self, ip: &str) -> i64 {
        let cutoff = (chrono::Utc::now().timestamp())
            - (LOGIN_ATTEMPT_WINDOW.as_secs() as i64);
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM login_log WHERE ip = ? AND success = 0 AND attempted_at > ?",
            rusqlite::params![ip, cutoff],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }
}

/// The central authentication manager: combines the user store with
/// in-memory session tracking and brute-force protection.
pub struct AuthManager {
    db: AuthDb,
    sessions: Mutex<HashMap<String, Session>>,
}

impl AuthManager {
    /// Create a new auth manager backed by the given database.
    pub fn new(db: AuthDb) -> Self {
        Self {
            db,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if no admin user has been created yet (first-run setup).
    pub fn is_setup_required(&self) -> bool {
        !self.db.admin_exists()
    }

    /// Perform initial admin setup. Only works when no admin exists.
    pub fn setup(&self, username: &str, password: &str) -> Result<(), AuthError> {
        if self.db.admin_exists() {
            return Err(AuthError::AlreadyExists);
        }
        validate_username(username)?;
        validate_password(password)?;
        self.db.create_admin(username, password)
    }

    /// Attempt to log in. On success, returns a session token.
    /// On failure, records the attempt and may lock out the IP.
    pub fn login(
        &self,
        username: &str,
        password: &str,
        client_ip: &str,
    ) -> Result<String, AuthError> {
        // Check IP lockout via DB-backed failure count.
        let failures = self.db.count_recent_failures(client_ip);
        if failures >= MAX_LOGIN_ATTEMPTS as i64 {
            let remaining = LOGIN_LOCKOUT.as_secs();
            return Err(AuthError::LockedOut {
                secs_remaining: remaining,
            });
        }

        let valid = self.db.verify(username, password)?;
        self.db.log_attempt(Some(username), client_ip, valid);

        if !valid {
            // Check if this attempt triggered a lockout.
            let new_failures = self.db.count_recent_failures(client_ip);
            if new_failures >= MAX_LOGIN_ATTEMPTS as i64 {
                return Err(AuthError::LockedOut {
                    secs_remaining: LOGIN_LOCKOUT.as_secs(),
                });
            }
            return Err(AuthError::InvalidCredentials);
        }

        // Success: create session.
        self.db.update_last_login(username);
        let token = generate_session_token();
        let now = Instant::now();
        let session = Session {
            username: username.to_string(),
            created_at: now,
            last_access: now,
        };
        self.sessions.lock().insert(token.clone(), session);
        Ok(token)
    }

    /// Destroy a session (logout).
    pub fn logout(&self, token: &str) {
        self.sessions.lock().remove(token);
    }

    /// Validate a session token. Returns the username if valid and not expired.
    /// Also extends the idle timeout on successful access.
    pub fn validate_session(&self, token: &str) -> Option<String> {
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        let session = sessions.get_mut(token)?;
        // Check absolute expiry.
        if now.duration_since(session.created_at) >= SESSION_ABSOLUTE_TTL {
            sessions.remove(token);
            return None;
        }
        // Check idle expiry.
        if now.duration_since(session.last_access) >= SESSION_IDLE_TTL {
            sessions.remove(token);
            return None;
        }
        // Extend idle timeout.
        session.last_access = now;
        Some(session.username.clone())
    }

    /// Change the password for `username` after verifying the old password.
    /// Invalidates all existing sessions for this user.
    pub fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        validate_password(new_password)?;
        self.db.change_password(username, old_password, new_password)?;
        // Invalidate all sessions for this user (force re-login).
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, s| s.username != username);
        Ok(())
    }

    /// Retrieve admin info for `username`.
    pub fn get_admin_info(&self, username: &str) -> Result<AdminInfo, AuthError> {
        self.db.get_admin_info(username)
    }

    /// Remove all expired sessions from memory.
    /// Should be called periodically to prevent memory growth.
    pub fn cleanup_expired_sessions(&self) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, s| {
            now.duration_since(s.created_at) < SESSION_ABSOLUTE_TTL
                && now.duration_since(s.last_access) < SESSION_IDLE_TTL
        });
    }
}

/// Generate a cryptographically random 256-bit session token (hex-encoded).
fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

/// Hash a password using Argon2id.
fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Lazily-initialized dummy password hash for timing attack prevention.
/// Used when verifying a login for a non-existent user so that the response
/// time is similar to verifying a real user.
static DUMMY_HASH: OnceLock<String> = OnceLock::new();

/// Get a dummy Argon2 hash, initializing it on first use.
fn get_dummy_hash() -> &'static str {
    DUMMY_HASH.get_or_init(|| {
        hash_password("dummy_password_for_timing_protection").unwrap_or_default()
    })
}

/// Validate username: 3-32 chars, alphanumeric + underscore/hyphen.
fn validate_username(username: &str) -> Result<(), AuthError> {
    if username.len() < 3 || username.len() > 32 {
        return Err(AuthError::WeakPassword(
            "username must be 3-32 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AuthError::WeakPassword(
            "username may only contain letters, digits, underscore, hyphen".into(),
        ));
    }
    Ok(())
}

/// Validate password complexity: min 8 chars, at least one uppercase,
/// one lowercase, and one digit.
fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(AuthError::WeakPassword(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AuthError::WeakPassword(
            "password must contain at least one uppercase letter".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(AuthError::WeakPassword(
            "password must contain at least one lowercase letter".into(),
        ));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::WeakPassword(
            "password must contain at least one digit".into(),
        ));
    }
    Ok(())
}

/// Minimal hex encoder (avoids adding the `hex` crate as a dependency).
mod hex {
    /// Encode bytes as a lowercase hex string.
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> AuthManager {
        AuthManager::new(AuthDb::open_in_memory().unwrap())
    }

    #[test]
    fn setup_and_login_flow() {
        let m = mgr();
        assert!(m.is_setup_required());
        m.setup("admin", "Passw0rd").unwrap();
        assert!(!m.is_setup_required());
        // Double setup fails.
        assert!(matches!(m.setup("admin2", "Passw0rd"), Err(AuthError::AlreadyExists)));
        // Correct login.
        let token = m.login("admin", "Passw0rd", "127.0.0.1").unwrap();
        assert!(m.validate_session(&token).is_some());
        // Wrong password.
        assert!(matches!(
            m.login("admin", "wrong", "127.0.0.1"),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn weak_password_rejected() {
        let m = mgr();
        assert!(m.setup("admin", "short").is_err());
        assert!(m.setup("admin", "alllowercase").is_err());
        assert!(m.setup("admin", "ALLUPPER1").is_err());
        assert!(m.setup("admin", "NoDigitsHere").is_err());
        assert!(m.setup("admin", "Passw0rd").is_ok());
    }

    #[test]
    fn change_password_invalidates_sessions() {
        let m = mgr();
        m.setup("admin", "Passw0rd").unwrap();
        let token = m.login("admin", "Passw0rd", "127.0.0.1").unwrap();
        assert!(m.validate_session(&token).is_some());
        m.change_password("admin", "Passw0rd", "NewPass1").unwrap();
        // Old session is invalidated.
        assert!(m.validate_session(&token).is_none());
        // Old password no longer works.
        assert!(m.login("admin", "Passw0rd", "127.0.0.1").is_err());
        // New password works.
        let token2 = m.login("admin", "NewPass1", "127.0.0.1").unwrap();
        assert!(m.validate_session(&token2).is_some());
    }

    #[test]
    fn brute_force_lockout() {
        let m = mgr();
        m.setup("admin", "Passw0rd").unwrap();
        // 5 failed attempts.
        for _ in 0..5 {
            let _ = m.login("admin", "wrong", "10.0.0.1");
        }
        // 6th attempt is locked out (even with correct password).
        let result = m.login("admin", "Passw0rd", "10.0.0.1");
        assert!(matches!(result, Err(AuthError::LockedOut { .. })));
        // Different IP is not locked out.
        let result = m.login("admin", "Passw0rd", "10.0.0.2");
        assert!(result.is_ok());
    }

    #[test]
    fn logout_destroys_session() {
        let m = mgr();
        m.setup("admin", "Passw0rd").unwrap();
        let token = m.login("admin", "Passw0rd", "127.0.0.1").unwrap();
        assert!(m.validate_session(&token).is_some());
        m.logout(&token);
        assert!(m.validate_session(&token).is_none());
    }

    #[test]
    fn invalid_username_rejected() {
        let m = mgr();
        assert!(m.setup("ab", "Passw0rd").is_err()); // too short
        assert!(m.setup("admin space", "Passw0rd").is_err()); // space
        assert!(m.setup("valid_admin-1", "Passw0rd").is_ok());
    }
}
