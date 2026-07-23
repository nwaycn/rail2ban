//! Embedded web management interface for rail2ban.
//!
//! Provides a REST API and a single-page web dashboard served via HTTP.
//! The web server runs inside the same process as the rail2ban server,
//! sharing direct access to the `Server` state.
//!
//! # Authentication
//!
//! All management API endpoints require authentication via a session cookie.
//! The login flow uses Argon2 password hashing and includes brute-force
//! protection (per-IP rate limiting + lockout). On first run, a setup
//! endpoint allows creating the initial admin account.

pub mod auth;
pub mod handlers;
pub mod middleware;
pub mod routes;

pub use auth::{AuthDb, AuthError, AuthManager};
pub use routes::create_router;

use crate::server::Server;
use middleware::RateLimiter;
use std::sync::Arc;

/// Shared application state for the web server.
#[derive(Clone)]
pub struct WebState {
    /// The rail2ban server instance.
    pub server: Arc<Server>,
    /// Authentication manager (sessions, password verification, rate limiting).
    pub auth: Arc<AuthManager>,
    /// Rate limiter for sensitive endpoints (login/setup).
    pub login_limiter: Arc<RateLimiter>,
    /// Whether to trust proxy headers (X-Forwarded-For, X-Real-IP).
    /// When `false` (default), only the connection's remote address is used.
    /// Enable only when running behind a trusted reverse proxy.
    pub trust_proxy: bool,
}
