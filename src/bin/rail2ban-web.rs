//! `rail2ban-web` — web management interface for rail2ban.
//!
//! Runs an embedded rail2ban server with an HTTP management dashboard.
//! This is a convenience binary that starts both the rail2ban daemon
//! and the web interface in a single process.
//!
//! # Authentication
//!
//! On first run, visit the dashboard at `/emc/` to create an admin account.
//! Subsequent logins require the admin username and password. All management
//! API endpoints require a valid session cookie.

use clap::{Arg, ArgAction, Command};
use rail2ban::config::ConfigLoader;
use rail2ban::server::Server;
use rail2ban::web::middleware::RateLimiter;
use rail2ban::web::{create_router, AuthDb, AuthManager, WebState};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new("rail2ban-web")
        .version(env!("CARGO_PKG_VERSION"))
        .about("rail2ban web management interface")
        .arg(
            Arg::new("conf")
                .short('c')
                .long("conf")
                .help("configuration directory (comma-separated)")
                .value_name("DIR"),
        )
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .help("HTTP listen address (host:port)")
                .default_value("0.0.0.0:8080")
                .value_name("ADDR"),
        )
        .arg(
            Arg::new("authdb")
                .long("authdb")
                .help("path to the auth database file")
                .default_value("/var/lib/rail2ban/rail2ban-auth.db")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("trust-proxy")
                .long("trust-proxy")
                .action(ArgAction::SetTrue)
                .help("trust X-Forwarded-For/X-Real-IP headers (enable only behind a reverse proxy)"),
        )
        .arg(
            Arg::new("loglevel")
                .long("loglevel")
                .help("log level (CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG)")
                .value_name("LEVEL"),
        )
        .arg(
            Arg::new("socket")
                .short('s')
                .long("socket")
                .help("Unix socket path for rail2ban IPC (optional)")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .action(ArgAction::SetTrue)
                .help("test configuration and exit"),
        )
        .get_matches();

    let conf_dirs: Vec<PathBuf> = matches
        .get_one::<String>("conf")
        .map(|s| s.split(',').map(|p| PathBuf::from(p.trim())).collect())
        .unwrap_or_else(|| {
            vec![
                PathBuf::from("/etc/rail2ban"),
                PathBuf::from("/etc/fail2ban"),
            ]
        });

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            matches
                .get_one::<String>("loglevel")
                .cloned()
                .unwrap_or_else(|| "info".into()),
        )
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let loader = ConfigLoader::new(conf_dirs.clone());
    let config = match loader.load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    if matches.get_flag("test") {
        eprintln!("configuration OK ({} jails)", config.jails.jails.len());
        return Ok(());
    }

    let listen_addr = matches
        .get_one::<String>("listen")
        .unwrap()
        .clone();

    let authdb_path = matches
        .get_one::<String>("authdb")
        .unwrap()
        .clone();

    let mut global = config.global.clone();
    if let Some(socket) = matches.get_one::<String>("socket") {
        global.socket = socket.clone();
    }
    let mut config = config;
    config.global = global;

    // Initialize the rail2ban server.
    let server = Arc::new(Server::new(config));
    server.set_search_dirs(conf_dirs);
    if let Err(e) = server.init_db().await {
        tracing::warn!("database init failed: {e}");
    }
    let n = server.start_all_enabled().await?;
    tracing::info!("started {n} jails");

    // Initialize the auth database.
    let authdb_path = PathBuf::from(&authdb_path);
    let auth_db = match AuthDb::open(&authdb_path) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("failed to open auth database at {}: {e}", authdb_path.display());
            std::process::exit(1);
        }
    };
    let auth_manager = Arc::new(AuthManager::new(auth_db));

    // Rate limiter: max 20 requests per 15 minutes per IP on login/setup.
    let login_limiter = Arc::new(RateLimiter::new(20, Duration::from_secs(15 * 60)));

    let trust_proxy = matches.get_flag("trust-proxy");
    if trust_proxy {
        tracing::warn!("trust-proxy is enabled — only use behind a trusted reverse proxy");
    }

    if auth_manager.is_setup_required() {
        tracing::warn!(
            "no admin user found — visit http://{listen_addr}/emc/ to create the initial admin account"
        );
    }

    // Spawn periodic cleanup task for expired sessions and rate limiter entries.
    {
        let auth = auth_manager.clone();
        let limiter = login_limiter.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                auth.cleanup_expired_sessions();
                limiter.cleanup();
            }
        });
    }

    let state = WebState {
        server: server.clone(),
        auth: auth_manager,
        login_limiter,
        trust_proxy,
    };
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("web management interface listening on http://{listen_addr}/emc/");

    println!("\n  rail2ban web management interface");
    println!("  ──────────────────────────────────");
    println!("  Dashboard:  http://{listen_addr}/emc/");
    println!("  API base:   http://{listen_addr}/emc/api/");
    println!("  Auth DB:    {}", authdb_path.display());
    println!("  Press Ctrl+C to stop\n");

    // Use `into_make_service_with_connect_info` so the login handler
    // can access the client's IP address for brute-force protection.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
