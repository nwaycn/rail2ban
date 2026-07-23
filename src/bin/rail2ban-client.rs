//! `rail2ban-client` — the CLI client.

use clap::{Arg, ArgAction, Command};
use rail2ban::protocol::{send_request, Request, DEFAULT_SOCKET, DEFAULT_TIMEOUT_SECS};
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let matches = Command::new("rail2ban-client")
        .version(env!("CARGO_PKG_VERSION"))
        .about("rail2ban client")
        .arg(
            Arg::new("conf")
                .short('c')
                .long("conf")
                .help("configuration directory")
                .value_name("DIR"),
        )
        .arg(
            Arg::new("socket")
                .short('s')
                .long("socket")
                .help("socket path")
                .value_name("FILE")
                .default_value(DEFAULT_SOCKET),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("timeout in seconds")
                .value_name("SECS")
                .default_value("30"),
        )
        .arg(
            Arg::new("str2sec")
                .long("str2sec")
                .help("convert time abbreviation to seconds and exit")
                .value_name("STRING"),
        )
        .arg(
            Arg::new("dump")
                .short('d')
                .long("dump")
                .action(ArgAction::SetTrue)
                .help("dump configuration"),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .action(ArgAction::SetTrue)
                .help("test configuration"),
        )
        .arg(
            Arg::new("command")
                .num_args(1..)
                .help("subcommand and arguments, e.g. `status sshd`"),
        )
        .get_matches();

    if let Some(s) = matches.get_one::<String>("str2sec") {
        match rail2ban::time::TimeValue::parse(s) {
            Ok(v) => {
                println!("{}", v.to_seconds_or_max());
                return Ok(());
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }

    let socket = matches.get_one::<String>("socket").cloned().unwrap();
    let timeout = matches
        .get_one::<String>("timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let timeout = Duration::from_secs(timeout);

    let args: Vec<String> = matches
        .get_many::<String>("command")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();

    if args.is_empty() {
        eprintln!("usage: rail2ban-client [OPTIONS] <COMMAND>...");
        std::process::exit(2);
    }

    let req = Request::new(args.iter().map(|s| s.as_str()));
    let resp = match send_request(&socket, &req, timeout) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if resp.ok {
        if let Some(msg) = resp.message {
            println!("{msg}");
        }
        if let Some(data) = resp.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
    } else {
        if let Some(msg) = resp.message {
            eprintln!("error: {msg}");
        }
        std::process::exit(1);
    }
    Ok(())
}
