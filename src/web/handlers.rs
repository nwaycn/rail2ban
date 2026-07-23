//! HTTP handler functions for the web management API.

use crate::server::jail::JailCommand;
use crate::web::middleware::{build_session_cookie, clear_session_cookie, extract_client_ip, extract_session_token};
use crate::web::WebState;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;

/// Standard JSON API response wrapper.
#[derive(Serialize)]
pub struct ApiResponse {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Optional message (error description or informational text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Optional structured data payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ApiResponse {
    /// Build a successful response with data.
    fn ok(data: Value) -> Self {
        Self {
            ok: true,
            message: None,
            data: Some(data),
        }
    }

    /// Build a failure response with a message.
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: Some(msg.into()),
            data: None,
        }
    }
}

/// Request body for ban/unban operations.
#[derive(Deserialize)]
pub struct BanRequest {
    /// Target jail name (required for ban, optional for unban).
    pub jail: Option<String>,
    /// Target IP address.
    pub ip: String,
}

/// Request body for loglevel change.
#[derive(Deserialize)]
pub struct LogLevelRequest {
    /// New log level value (e.g. `INFO`, `DEBUG`).
    pub level: String,
}

/// Request body for login.
#[derive(Deserialize)]
pub struct LoginRequest {
    /// Admin username.
    pub username: String,
    /// Admin password.
    pub password: String,
}

/// Request body for initial setup (create first admin).
#[derive(Deserialize)]
pub struct SetupRequest {
    /// Desired admin username.
    pub username: String,
    /// Desired admin password.
    pub password: String,
}

/// Request body for password change.
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// Current password (for verification).
    pub old_password: String,
    /// New password.
    pub new_password: String,
}

/// Query params for config lookup.
#[derive(Deserialize)]
pub struct ConfigQuery {
    /// Optional config key to look up (e.g. `loglevel`).
    pub key: Option<String>,
}

/// Query params for log retrieval.
#[derive(Deserialize)]
pub struct LogQuery {
    /// Maximum number of log lines to return.
    pub lines: Option<usize>,
}

// ===== Auth handlers =====

/// POST /emc/api/login — authenticate and create a session.
pub async fn login(
    State(state): State<WebState>,
    connect_info: Option<axum::extract::ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = extract_client_ip(
        &headers,
        connect_info.map(|ci| ci.0.ip()).as_ref(),
        state.trust_proxy,
    );

    match state.auth.login(&body.username, &body.password, &ip) {
        Ok(token) => {
            let cookie = build_session_cookie(&token, 8 * 3600);
            let data = json!({
                "username": body.username,
                "message": "login successful",
            });
            (
                StatusCode::OK,
                [(header::SET_COOKIE, cookie)],
                Json(ApiResponse::ok(data)),
            )
                .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            let status = match &e {
                crate::web::auth::AuthError::LockedOut { .. } => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::UNAUTHORIZED,
            };
            (status, Json(ApiResponse::err(msg))).into_response()
        }
    }
}

/// POST /emc/api/logout — destroy the current session and clear cookie.
pub async fn logout_clear(
    State(state): State<WebState>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(token) = extract_session_token(&headers) {
        state.auth.logout(&token);
    }
    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_session_cookie())],
        Json(ApiResponse::ok(json!({"message": "logged out"}))),
    )
        .into_response()
}

/// GET /emc/api/session — check if the current session is valid.
pub async fn check_session(
    State(state): State<WebState>,
    headers: axum::http::HeaderMap,
) -> Json<ApiResponse> {
    if let Some(token) = extract_session_token(&headers) {
        if let Some(username) = state.auth.validate_session(&token) {
            let setup_required = state.auth.is_setup_required();
            return Json(ApiResponse::ok(json!({
                "authenticated": true,
                "username": username,
                "setup_required": setup_required,
            })));
        }
    }
    Json(ApiResponse::ok(json!({
        "authenticated": false,
        "setup_required": state.auth.is_setup_required(),
    })))
}

/// POST /emc/api/setup — create the initial admin user (first-run only).
pub async fn setup(
    State(state): State<WebState>,
    Json(body): Json<SetupRequest>,
) -> Response {
    if !state.auth.is_setup_required() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("setup already completed")),
        )
            .into_response();
    }
    match state.auth.setup(&body.username, &body.password) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(ApiResponse::ok(json!({
                "message": "admin user created, please log in",
                "username": body.username,
            }))),
        )
            .into_response(),
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            (status, Json(ApiResponse::err(e.to_string()))).into_response()
        }
    }
}

/// POST /emc/api/change-password — change the admin password.
pub async fn change_password(
    State(state): State<WebState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Response {
    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::err("not authenticated")),
            )
                .into_response();
        }
    };
    let username = match state.auth.validate_session(&token) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::err("session expired")),
            )
                .into_response();
        }
    };
    match state.auth.change_password(&username, &body.old_password, &body.new_password) {
        Ok(()) => {
            // Password change invalidates all sessions; clear the cookie.
            (
                StatusCode::OK,
                [(header::SET_COOKIE, clear_session_cookie())],
                Json(ApiResponse::ok(json!({
                    "message": "password changed, please log in again",
                }))),
            )
                .into_response()
        }
        Err(e) => {
            let status = match &e {
                crate::web::auth::AuthError::IncorrectOldPassword => StatusCode::UNAUTHORIZED,
                crate::web::auth::AuthError::WeakPassword(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(ApiResponse::err(e.to_string()))).into_response()
        }
    }
}

/// GET /emc/api/admin/info — get admin user info.
pub async fn get_admin_info(
    State(state): State<WebState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::err("not authenticated")),
            )
                .into_response();
        }
    };
    let username = match state.auth.validate_session(&token) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::err("session expired")),
            )
                .into_response();
        }
    };
    match state.auth.get_admin_info(&username) {
        Ok(info) => Json(ApiResponse::ok(json!({
            "username": info.username,
            "created_at": info.created_at,
            "last_login": info.last_login,
        })))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(e.to_string())),
        )
            .into_response(),
    }
}

// ===== System handlers =====

/// GET /emc/api/status — overall system status.
pub async fn get_status(State(state): State<WebState>) -> Json<ApiResponse> {
    let jails = state.server.list_jails().await;
    let total_banned: usize = jails.iter().map(|h| h.ban_mgr.current_banned()).sum();
    let total_failed: usize = jails.iter().map(|h| h.fail_mgr.current_failed()).sum();
    Json(ApiResponse::ok(json!({
        "jails_count": jails.len(),
        "jail_names": jails.iter().map(|h| h.name.clone()).collect::<Vec<_>>(),
        "total_currently_banned": total_banned,
        "total_currently_failed": total_failed,
        "setup_required": state.auth.is_setup_required(),
    })))
}

/// GET /emc/api/stats — detailed statistics for all jails.
pub async fn get_stats(State(state): State<WebState>) -> Json<ApiResponse> {
    let mut out = serde_json::Map::new();
    for h in state.server.list_jails().await {
        let stats = state.server.jail_stats(&h).await;
        out.insert(h.name.clone(), stats);
    }
    Json(ApiResponse::ok(json!(out)))
}

/// GET /emc/api/version — server version.
pub async fn get_version() -> Json<ApiResponse> {
    Json(ApiResponse::ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
    })))
}

/// GET /emc/api/loglevel — current log level.
pub async fn get_loglevel(State(state): State<WebState>) -> Json<ApiResponse> {
    Json(ApiResponse::ok(json!({
        "loglevel": state.server.loglevel().await,
    })))
}

/// POST /emc/api/loglevel — set log level.
pub async fn set_loglevel(
    State(state): State<WebState>,
    Json(body): Json<LogLevelRequest>,
) -> Json<ApiResponse> {
    state.server.set_loglevel(body.level.clone()).await;
    Json(ApiResponse::ok(json!({"loglevel": body.level})))
}

// ===== Jail handlers =====

/// GET /emc/api/jails — list all jails.
pub async fn list_jails(State(state): State<WebState>) -> Json<ApiResponse> {
    let jails = state.server.list_jails().await;
    let data: Vec<Value> = jails
        .iter()
        .map(|h| {
            json!({
                "name": h.name,
                "currently_banned": h.ban_mgr.current_banned(),
                "total_banned": h.ban_mgr.total_banned(),
                "currently_failed": h.fail_mgr.current_failed(),
                "total_failed": h.fail_mgr.total_failed(),
            })
        })
        .collect();
    Json(ApiResponse::ok(json!(data)))
}

/// GET /emc/api/jails/:name — detailed info for a specific jail.
pub async fn get_jail(
    State(state): State<WebState>,
    Path(name): Path<String>,
) -> Json<ApiResponse> {
    match state.server.get_jail(&name).await {
        Some(h) => {
            let stats = state.server.jail_stats(&h).await;
            Json(ApiResponse::ok(stats))
        }
        None => Json(ApiResponse::err(format!("jail not found: {name}"))),
    }
}

/// POST /emc/api/jails/:name/start — start a jail.
pub async fn start_jail(
    State(state): State<WebState>,
    Path(name): Path<String>,
) -> Json<ApiResponse> {
    match state.server.start_jail(&name).await {
        Ok(()) => Json(ApiResponse::ok(json!({"started": name}))),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /emc/api/jails/:name/stop — stop a jail.
pub async fn stop_jail(
    State(state): State<WebState>,
    Path(name): Path<String>,
) -> Json<ApiResponse> {
    match state.server.stop_jail(&name).await {
        Ok(()) => Json(ApiResponse::ok(json!({"stopped": name}))),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

/// POST /emc/api/jails/:name/restart — restart a jail.
pub async fn restart_jail(
    State(state): State<WebState>,
    Path(name): Path<String>,
) -> Json<ApiResponse> {
    match state.server.restart_jail(&name).await {
        Ok(()) => Json(ApiResponse::ok(json!({"restarted": name}))),
        Err(e) => Json(ApiResponse::err(e.to_string())),
    }
}

// ===== Ban handlers =====

/// GET /emc/api/banned — list all banned IPs grouped by jail.
pub async fn list_banned(State(state): State<WebState>) -> Json<ApiResponse> {
    let map = state.server.banned_map().await;
    Json(ApiResponse::ok(map))
}

/// GET /emc/api/banned/:ip — check which jails have banned this IP.
pub async fn check_banned(
    State(state): State<WebState>,
    Path(ip): Path<String>,
) -> Json<ApiResponse> {
    let jails = state.server.jails_banning(&ip).await;
    Json(ApiResponse::ok(json!({
        "ip": ip,
        "banned_in": jails,
        "is_banned": !jails.is_empty(),
    })))
}

/// POST /emc/api/ban — ban an IP in a specific jail.
pub async fn ban_ip(
    State(state): State<WebState>,
    Json(body): Json<BanRequest>,
) -> Json<ApiResponse> {
    let jail_name = match &body.jail {
        Some(j) => j.clone(),
        None => return Json(ApiResponse::err("jail field is required")),
    };
    match state.server.get_jail(&jail_name).await {
        Some(h) => {
            let _ = h
                .cmd_tx
                .send(JailCommand::BanIp { ip: body.ip.clone() })
                .await;
            Json(ApiResponse::ok(json!({"banned": body.ip, "jail": jail_name})))
        }
        None => Json(ApiResponse::err(format!("jail not found: {jail_name}"))),
    }
}

/// POST /emc/api/unban — unban an IP across all jails.
pub async fn unban_ip(
    State(state): State<WebState>,
    Json(body): Json<BanRequest>,
) -> Json<ApiResponse> {
    let found = state.server.unban_ip(&body.ip).await;
    Json(ApiResponse::ok(json!({
        "unbanned": body.ip,
        "was_banned": found,
    })))
}

/// POST /emc/api/unban-all — unban all IPs.
pub async fn unban_all(State(state): State<WebState>) -> Json<ApiResponse> {
    state.server.unban_all().await;
    Json(ApiResponse::ok(json!({"action": "unbanned all"})))
}

// ===== Config handlers =====

/// GET /emc/api/config — get config values.
pub async fn get_config(
    State(state): State<WebState>,
    Query(q): Query<ConfigQuery>,
) -> Json<ApiResponse> {
    match q.key.as_deref() {
        Some("loglevel") => {
            Json(ApiResponse::ok(json!({"loglevel": state.server.loglevel().await})))
        }
        Some("logtarget") => {
            Json(ApiResponse::ok(json!({"logtarget": state.server.logtarget().await})))
        }
        Some("dbfile") => {
            Json(ApiResponse::ok(json!({"dbfile": state.server.dbfile().await})))
        }
        Some("dbmaxmatches") => Json(ApiResponse::ok(
            json!({"dbmaxmatches": state.server.dbmaxmatches().await}),
        )),
        Some("dbpurgeage") => Json(ApiResponse::ok(
            json!({"dbpurgeage": state.server.dbpurgeage().await}),
        )),
        Some("socket") => {
            Json(ApiResponse::ok(json!({"socket": state.server.config_path()})))
        }
        Some(k) => Json(ApiResponse::err(format!("unknown config key: {k}"))),
        None => {
            let mut cfg = serde_json::Map::new();
            cfg.insert("loglevel".into(), json!(state.server.loglevel().await));
            cfg.insert("logtarget".into(), json!(state.server.logtarget().await));
            cfg.insert("dbfile".into(), json!(state.server.dbfile().await));
            cfg.insert("dbmaxmatches".into(), json!(state.server.dbmaxmatches().await));
            cfg.insert("dbpurgeage".into(), json!(state.server.dbpurgeage().await));
            cfg.insert("socket".into(), json!(state.server.config_path()));
            Json(ApiResponse::ok(json!(cfg)))
        }
    }
}

/// POST /emc/api/reload — reload configuration.
pub async fn reload_config(State(state): State<WebState>) -> Json<ApiResponse> {
    let dirs: Vec<std::path::PathBuf> = state
        .server
        .config_path()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .collect();
    if dirs.is_empty() {
        return Json(ApiResponse::err("no config search dirs available"));
    }
    let loader = crate::config::ConfigLoader::new(dirs);
    match loader.load() {
        Ok(loaded) => match state.server.reload_config(loaded).await {
            Ok(n) => Json(ApiResponse::ok(json!({"reloaded": true, "jails_started": n}))),
            Err(e) => Json(ApiResponse::err(format!("reload failed: {e}"))),
        },
        Err(e) => Json(ApiResponse::err(format!("config parse error: {e}"))),
    }
}

// ===== Log handler =====

/// GET /emc/api/log — retrieve recent log output.
pub async fn get_log(
    State(_state): State<WebState>,
    Query(q): Query<LogQuery>,
) -> Json<ApiResponse> {
    let _ = q.lines;
    Json(ApiResponse::ok(json!({
        "lines": [],
        "note": "log streaming not yet implemented; use journalctl or log file directly"
    })))
}

// ===== Dashboard HTML =====

/// Serve the embedded dashboard HTML page.
pub fn dashboard_html() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(DASHBOARD_HTML),
    )
}

/// The single-page dashboard HTML (inline to avoid extra file dependencies).
/// Uses Chart.js from CDN for visualization.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");
