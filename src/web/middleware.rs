//! HTTP middleware for authentication, security headers, and rate limiting.

use crate::web::auth::SESSION_COOKIE_NAME;
use crate::web::WebState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Paths that do NOT require authentication.
/// These are accessible without a valid session.
const PUBLIC_PATHS: &[&str] = &[
    "/emc/api/login",
    "/emc/api/logout",
    "/emc/api/session",
    "/emc/api/setup",
    "/emc/api/version",
    "/emc",
    "/emc/",
];

/// Paths subject to strict rate limiting (login attempts).
const RATE_LIMITED_PATHS: &[&str] = &["/emc/api/login", "/emc/api/setup"];

/// Extract the client IP from headers or connection info.
///
/// When `trust_proxy` is `true`, checks `X-Real-IP` then `X-Forwarded-For`
/// (first entry), falling back to the connection's remote address.
/// When `false` (default), only the connection's remote address is used —
/// proxy headers are ignored to prevent IP spoofing.
pub fn extract_client_ip(
    headers: &HeaderMap,
    connect_info: Option<&IpAddr>,
    trust_proxy: bool,
) -> String {
    if trust_proxy {
        if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real.trim().parse::<IpAddr>() {
                return ip.to_string();
            }
        }
        if let Some(fwd) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = fwd.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip.to_string();
                }
            }
        }
    }
    connect_info
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

/// Parse the session token from the `Cookie` header.
pub fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Auth middleware: rejects requests without a valid session.
///
/// Public paths (login, setup, dashboard HTML) are allowed through.
/// All other `/emc/api/*` paths require a valid session cookie.
pub async fn require_auth(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    // Allow public paths without authentication.
    if PUBLIC_PATHS.contains(&path) || !path.starts_with("/emc/api/") {
        return next.run(request).await;
    }

    // Extract and validate session token.
    let token = match extract_session_token(request.headers()) {
        Some(t) => t,
        None => return unauthorized_response("not authenticated"),
    };

    match state.auth.validate_session(&token) {
        Some(_username) => next.run(request).await,
        None => unauthorized_response("session expired or invalid"),
    }
}

/// Security headers middleware: adds standard protective HTTP headers
/// to every response.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    response
}

/// Simple in-memory rate limiter using a sliding window per IP.
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    /// Maximum requests within the window.
    max_requests: usize,
    /// Sliding window duration.
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter allowing `max_requests` per `window`.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    /// Check if a request from `key` (usually IP) is allowed.
    /// Returns `true` if allowed, `false` if rate-limited.
    /// Also periodically cleans up stale entries to prevent memory growth.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut map = self.inner.lock();
        let entry = map.entry(key.to_string()).or_default();
        // Remove entries outside the window.
        entry.retain(|t| *t > cutoff);
        if entry.len() >= self.max_requests {
            return false;
        }
        entry.push(now);
        true
    }

    /// Remove all entries that have no timestamps within the current window.
    /// Should be called periodically to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut map = self.inner.lock();
        map.retain(|_, entries| {
            entries.retain(|t| *t > cutoff);
            !entries.is_empty()
        });
    }
}

/// Rate-limiting middleware for sensitive endpoints (login, setup).
pub async fn rate_limit_sensitive(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !RATE_LIMITED_PATHS.contains(&path) {
        return next.run(request).await;
    }

    let connect_info = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let ip = extract_client_ip(request.headers(), connect_info.as_ref(), state.trust_proxy);

    if state.login_limiter.check(&ip) {
        next.run(request).await
    } else {
        too_many_requests_response()
    }
}

/// Build a 401 Unauthorized JSON response.
fn unauthorized_response(msg: &str) -> Response {
    let body = serde_json::json!({
        "ok": false,
        "message": msg,
    });
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Build a 429 Too Many Requests JSON response.
fn too_many_requests_response() -> Response {
    let body = serde_json::json!({
        "ok": false,
        "message": "too many requests, please slow down",
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Build a `Set-Cookie` header value for the session token with secure flags.
///
/// `HttpOnly` prevents JS access, `SameSite=Strict` mitigates CSRF,
/// `Path=/emc` restricts the cookie to the management interface.
pub fn build_session_cookie(token: &str, max_age_secs: i64) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/emc; Max-Age={max_age_secs}"
    )
}

/// Build a cookie header that clears the session cookie.
pub fn clear_session_cookie() -> String {
    format!(
        "{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/emc; Max-Age=0"
    )
}
