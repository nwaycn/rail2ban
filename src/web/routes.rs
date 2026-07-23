//! HTTP route definitions for the web management interface.
//!
//! All API routes are prefixed with `/emc/api/` (following the security
//! convention of using non-obvious paths for management endpoints).
//! The dashboard is served at `/emc/`.
//!
//! # Authentication
//!
//! Public endpoints (login, setup, session-check, status, version) are
//! accessible without authentication. All other endpoints require a valid
//! session cookie. Sensitive endpoints (login, setup) are rate-limited.

use crate::web::handlers;
use crate::web::middleware::{rate_limit_sensitive, require_auth, security_headers};
use crate::web::WebState;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

/// Build the main web router with authentication and security middleware.
pub fn create_router(state: WebState) -> Router {
    let api = Router::new()
        // Auth (public — no session required)
        .route("/login", post(handlers::login))
        .route("/logout", post(handlers::logout_clear))
        .route("/session", get(handlers::check_session))
        .route("/setup", post(handlers::setup))
        .route("/change-password", post(handlers::change_password))
        .route("/admin/info", get(handlers::get_admin_info))
        // System (public)
        .route("/status", get(handlers::get_status))
        .route("/version", get(handlers::get_version))
        // System (protected)
        .route("/stats", get(handlers::get_stats))
        .route("/loglevel", get(handlers::get_loglevel))
        .route("/loglevel", post(handlers::set_loglevel))
        // Jails (protected)
        .route("/jails", get(handlers::list_jails))
        .route("/jails/:name", get(handlers::get_jail))
        .route("/jails/:name/start", post(handlers::start_jail))
        .route("/jails/:name/stop", post(handlers::stop_jail))
        .route("/jails/:name/restart", post(handlers::restart_jail))
        // Bans (protected)
        .route("/banned", get(handlers::list_banned))
        .route("/banned/:ip", get(handlers::check_banned))
        .route("/ban", post(handlers::ban_ip))
        .route("/unban", post(handlers::unban_ip))
        .route("/unban-all", post(handlers::unban_all))
        // Config (protected)
        .route("/reload", post(handlers::reload_config))
        .route("/config", get(handlers::get_config))
        // Log (protected)
        .route("/log", get(handlers::get_log))
        // Apply rate limiting on sensitive endpoints.
        .layer(from_fn_with_state(state.clone(), rate_limit_sensitive))
        // Require authentication for all non-public API routes.
        .layer(from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/emc", get(|| async { handlers::dashboard_html() }))
        .route("/emc/", get(|| async { handlers::dashboard_html() }))
        .nest("/emc/api", api)
        // Security headers on all responses.
        .layer(from_fn(security_headers))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
