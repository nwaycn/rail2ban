//! `rail2ban-server` — the long-running daemon.

use clap::{Arg, ArgAction, Command};
use rail2ban::config::{ConfigLoader, LoadedConfig};
use rail2ban::server::Server;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new("rail2ban-server")
        .version(env!("CARGO_PKG_VERSION"))
        .about("rail2ban daemon")
        .arg(
            Arg::new("conf")
                .short('c')
                .long("conf")
                .help("configuration directory (comma-separated)")
                .value_name("DIR"),
        )
        .arg(
            Arg::new("socket")
                .short('s')
                .long("socket")
                .help("socket path")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("loglevel")
                .long("loglevel")
                .help("log level (CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG)")
                .value_name("LEVEL"),
        )
        .arg(
            Arg::new("foreground")
                .short('f')
                .long("foreground")
                .action(ArgAction::SetTrue)
                .help("run in foreground"),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .action(ArgAction::SetTrue)
                .help("test configuration and exit"),
        )
        .arg(
            Arg::new("dump")
                .short('d')
                .long("dump")
                .action(ArgAction::SetTrue)
                .help("dump configuration and exit"),
        )
        .get_matches();

    let conf_dirs: Vec<PathBuf> = matches
        .get_one::<String>("conf")
        .map(|s| {
            s.split(',')
                .map(|p| PathBuf::from(p.trim()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                PathBuf::from("/etc/rail2ban"),
                PathBuf::from("/etc/fail2ban"),
            ]
        });

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(matches.get_one::<String>("loglevel").cloned().unwrap_or_else(|| "info".into())));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let loader = ConfigLoader::new(conf_dirs.clone());
    let config: LoadedConfig = match loader.load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    if matches.get_flag("dump") {
        println!("[global]");
        println!("loglevel = {}", config.global.loglevel);
        println!("logtarget = {}", config.global.logtarget);
        println!("socket = {}", config.global.socket);
        println!("dbfile = {}", config.global.dbfile);
        println!();
        for (name, j) in &config.jails.jails {
            println!("[{name}]");
            println!("enabled = {}", j.enabled);
            println!("filter = {}", j.filter);
            println!("logpath = {}", j.logpath.join(" "));
            println!("maxretry = {}", j.maxretry);
            println!("findtime = {}s", j.findtime.to_seconds_or_max());
            println!("bantime = {}s", j.bantime.to_seconds_or_max());
            println!();
        }
        return Ok(());
    }
    if matches.get_flag("test") {
        eprintln!("configuration OK ({} jails)", config.jails.jails.len());
        return Ok(());
    }

    let mut global = config.global.clone();
    if let Some(socket) = matches.get_one::<String>("socket") {
        global.socket = socket.clone();
    }
    let socket_path = global.socket.clone();
    let mut config = config;
    config.global = global;

    let server = Arc::new(Server::new(config));
    server.set_search_dirs(conf_dirs);
    if let Err(e) = server.init_db().await {
        tracing::warn!("database init failed: {e}");
    }
    let n = server.start_all_enabled().await?;
    tracing::info!("started {n} jails");

    server.run(&socket_path).await?;
    Ok(())
}
