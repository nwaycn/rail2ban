//! Command dispatcher: turns a [`crate::protocol::Request`] into a
//! [`crate::protocol::Response`] by mutating server state.

use crate::protocol::{Request, Response};
use crate::server::jail::{JailCommand, JailHandle};
use crate::server::Server;
use serde_json::json;
use std::sync::Arc;

/// Dispatch a request against the server.
pub async fn dispatch(server: &Arc<Server>, req: &Request) -> Response {
    if req.args.is_empty() {
        return Response::err("empty command");
    }
    let cmd = req.args[0].as_str();
    match cmd {
        "ping" => Response::ok("pong"),
        "echo" => Response::ok(req.args.get(1).cloned().unwrap_or_default()),
        "version" => Response::ok(env!("CARGO_PKG_VERSION")),
        "status" => status(server, &req.args[1..]).await,
        "start" => start(server, &req.args[1..]).await,
        "stop" => stop(server, &req.args[1..]).await,
        "reload" => reload(server, &req.args[1..]).await,
        "restart" => restart(server, &req.args[1..]).await,
        "unban" => unban(server, &req.args[1..]).await,
        "banned" => banned(server, &req.args[1..]).await,
        "stat" | "statistics" => statistics(server).await,
        "get" => get(server, &req.args[1..]).await,
        "set" => set(server, &req.args[1..]).await,
        "add" => add(server, &req.args[1..]).await,
        "flushlogs" => Response::ok(""),
        _ => Response::err(format!("unknown command: {cmd}")),
    }
}

async fn status(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        let jails = server.list_jails().await;
        let data = json!({
            "jails": jails.iter().map(|h| h.name.clone()).collect::<Vec<_>>(),
            "count": jails.len(),
        });
        return Response::ok_data(data);
    }
    let name = &args[0];
    let jail = match server.get_jail(name).await {
        Some(j) => j,
        None => return Response::err(format!("no such jail: {name}")),
    };
    let stats = server.jail_stats(&jail).await;
    Response::ok_data(stats)
}

async fn start(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        return Response::err("start: missing jail name (or use 'start --all' to start all enabled jails)");
    }
    if args[0] == "--all" {
        match server.start_all_enabled().await {
            Ok(n) => Response::ok(format!("started {n} jails")),
            Err(e) => Response::err(e.to_string()),
        }
    } else {
        match server.start_jail(&args[0]).await {
            Ok(()) => Response::ok(format!("started jail {}", args[0])),
            Err(e) => Response::err(e.to_string()),
        }
    }
}

async fn stop(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        server.stop_all().await;
        return Response::ok("stopping all jails");
    }
    match server.stop_jail(&args[0]).await {
        Ok(()) => Response::ok(format!("stopped jail {}", args[0])),
        Err(e) => Response::err(e.to_string()),
    }
}

async fn unban(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        return Response::err("unban: missing IP or --all");
    }
    if args[0] == "--all" {
        server.unban_all().await;
        return Response::ok("unbanned all");
    }
    let mut count = 0u32;
    for ip in &args[0..] {
        if server.unban_ip(ip).await {
            count += 1;
        }
    }
    Response::ok(count.to_string())
}

async fn banned(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        let map = server.banned_map().await;
        return Response::ok_data(map);
    }
    let mut out = serde_json::Map::new();
    for ip in &args[0..] {
        let jails = server.jails_banning(ip).await;
        out.insert(ip.clone(), json!(jails));
    }
    Response::ok_data(json!(out))
}

async fn statistics(server: &Arc<Server>) -> Response {
    let mut out = serde_json::Map::new();
    for h in server.list_jails().await {
        let stats = server.jail_stats(&h).await;
        out.insert(h.name.clone(), stats);
    }
    Response::ok_data(json!(out))
}

async fn get(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        return Response::err("get: missing arguments");
    }
    match args[0].as_str() {
        "loglevel" => Response::ok(server.loglevel().await),
        "logtarget" => Response::ok(server.logtarget().await),
        "dbfile" => Response::ok(server.dbfile().await),
        "dbmaxmatches" => Response::ok(server.dbmaxmatches().await.to_string()),
        "dbpurgeage" => Response::ok(server.dbpurgeage().await.to_string()),
        _ if args.len() >= 2 => {
            let jail = &args[0];
            let key = &args[1];
            let j = match server.get_jail(jail).await {
                Some(j) => j,
                None => return Response::err(format!("no such jail: {jail}")),
            };
            Response::ok(server.get_jail_attr(&j, key).await)
        }
        _ => Response::err(format!("get: unknown {:?}", args)),
    }
}

async fn set(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        return Response::err("set: missing arguments");
    }
    match args[0].as_str() {
        "loglevel" => {
            if args.len() < 2 {
                return Response::err("set loglevel: missing value");
            }
            server.set_loglevel(args[1].clone()).await;
            Response::ok("OK")
        }
        "logtarget" => {
            if args.len() < 2 {
                return Response::err("set logtarget: missing value");
            }
            server.set_logtarget(args[1].clone()).await;
            Response::ok("OK")
        }
        "dbfile" => {
            if args.len() < 2 {
                return Response::err("set dbfile: missing value");
            }
            server.set_dbfile(args[1].clone()).await;
            Response::ok("OK")
        }
        "dbmaxmatches" => {
            if args.len() < 2 {
                return Response::err("set dbmaxmatches: missing value");
            }
            match args[1].parse::<u32>() {
                Ok(n) => {
                    server.set_dbmaxmatches(n).await;
                    Response::ok("OK")
                }
                Err(_) => Response::err(format!("invalid integer: {}", args[1])),
            }
        }
        "dbpurgeage" => {
            if args.len() < 2 {
                return Response::err("set dbpurgeage: missing value");
            }
            match crate::time::TimeValue::parse(&args[1]) {
                Ok(v) => {
                    server.set_dbpurgeage(v.to_seconds_or_max()).await;
                    Response::ok("OK")
                }
                Err(e) => Response::err(e.to_string()),
            }
        }
        _ if args.len() >= 3 => {
            // set <JAIL> banip <IP> ...
            let jail_name = &args[0];
            let action = args[1].as_str();
            let rest = &args[2..];
            let j = match server.get_jail(jail_name).await {
                Some(j) => j,
                None => return Response::err(format!("no such jail: {jail_name}")),
            };
            set_jail_attr(&j, action, rest).await
        }
        _ => Response::err(format!("set: unknown {:?}", args)),
    }
}

async fn set_jail_attr(jail: &JailHandle, action: &str, rest: &[String]) -> Response {
    match action {
        "banip" => {
            let mut count = 0u32;
            for ip in rest {
                let _ = jail.cmd_tx.send(JailCommand::BanIp { ip: ip.clone() }).await;
                count += 1;
            }
            Response::ok(count.to_string())
        }
        "unbanip" => {
            let mut count = 0u32;
            for ip in rest {
                let _ = jail.cmd_tx.send(JailCommand::UnbanIp { ip: ip.clone() }).await;
                count += 1;
            }
            Response::ok(count.to_string())
        }
        "attempt" => {
            if rest.is_empty() {
                return Response::err("attempt: missing IP");
            }
            let ip = rest[0].clone();
            let failures = rest[1..].to_vec();
            let _ = jail
                .cmd_tx
                .send(JailCommand::Attempt { ip, failures })
                .await;
            Response::ok("OK")
        }
        _ => Response::err(format!("set <jail> {action}: not implemented")),
    }
}

async fn add(server: &Arc<Server>, args: &[String]) -> Response {
    if args.len() < 2 {
        return Response::err("add: usage: add <JAIL> <BACKEND>");
    }
    match server.add_jail(&args[0], &args[1]).await {
        Ok(()) => Response::ok(format!("added jail {}", args[0])),
        Err(e) => Response::err(e.to_string()),
    }
}

async fn reload(server: &Arc<Server>, args: &[String]) -> Response {
    // `reload --all` or `reload <JAIL>`: re-parse config from disk and restart.
    let dirs: Vec<std::path::PathBuf> = server
        .config_path()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .collect();
    if dirs.is_empty() {
        return Response::err("reload: no config search dirs available");
    }
    let loader = crate::config::ConfigLoader::new(dirs);
    match loader.load() {
        Ok(loaded) => {
            if args.is_empty() || args[0] == "--all" {
                match server.reload_config(loaded).await {
                    Ok(n) => Response::ok(format!("reloaded, started {n} jails")),
                    Err(e) => Response::err(format!("reload failed: {e}")),
                }
            } else {
                // Reload a single jail: restart it.
                let name = &args[0];
                match server.restart_jail(name).await {
                    Ok(()) => Response::ok(format!("restarted jail {name}")),
                    Err(e) => Response::err(e.to_string()),
                }
            }
        }
        Err(e) => Response::err(format!("reload: failed to parse config: {e}")),
    }
}

async fn restart(server: &Arc<Server>, args: &[String]) -> Response {
    if args.is_empty() {
        return Response::err("restart: missing jail name");
    }
    match server.restart_jail(&args[0]).await {
        Ok(()) => Response::ok(format!("restarted jail {}", args[0])),
        Err(e) => Response::err(e.to_string()),
    }
}
