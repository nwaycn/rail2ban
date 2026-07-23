//! `rail2ban-regex` — offline regex testing tool.
//!
//! Usage:
//! ```text
//! rail2ban-regex <log-file|-> <filter> [<datepattern>]
//! rail2ban-regex --filter <filter-name> <log-file|->
//! ```

use clap::{Arg, ArgAction, Command};
use rail2ban::config::FilterDefinition;
use rail2ban::filter::CompiledFilter;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let matches = Command::new("rail2ban-regex")
        .version(env!("CARGO_PKG_VERSION"))
        .about("offline regex testing tool")
        .arg(
            Arg::new("log")
                .required(true)
                .help("log file path, or '-' for stdin"),
        )
        .arg(
            Arg::new("filter")
                .required(true)
                .help("filter name, or inline failregex"),
        )
        .arg(
            Arg::new("datepattern")
                .required(false)
                .help("explicit datepattern (optional)"),
        )
        .arg(
            Arg::new("conf")
                .short('c')
                .long("conf")
                .help("configuration directory")
                .value_name("DIR"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("print every matched line"),
        )
        .get_matches();

    let conf_dirs: Vec<PathBuf> = matches
        .get_one::<String>("conf")
        .map(|s| s.split(',').map(|p| PathBuf::from(p.trim())).collect())
        .unwrap_or_else(|| vec![PathBuf::from("/etc/rail2ban"), PathBuf::from("/etc/fail2ban")]);

    let log_path = matches.get_one::<String>("log").unwrap();
    let filter_arg = matches.get_one::<String>("filter").unwrap();
    let datepattern = matches.get_one::<String>("datepattern").cloned();
    let verbose = matches.get_flag("verbose");

    // Build the FilterConfig: either load a named filter or build an inline one.
    let mut filter_cfg = if log_path == "-" || std::path::Path::new(log_path).exists() {
        // Treat filter_arg as a filter name.
        let def = FilterDefinition::load(filter_arg, &conf_dirs)?;
        let defaults = indexmap::IndexMap::new();
        let builtins = rail2ban::config::builtin_defaults();
        def.materialize(&indexmap::IndexMap::new(), &defaults, &builtins)?
    } else {
        // Inline failregex.
        let mut cfg = rail2ban::config::FilterConfig {
            name: "inline".into(),
            prefregex: None,
            failregex: vec![filter_arg.clone()],
            ignoreregex: vec![],
            datepattern: None,
            maxlines: 1,
            logtype: "file".into(),
            journalmatch: vec![],
            init: indexmap::IndexMap::new(),
        };
        let _ = &mut cfg;
        cfg
    };
    if let Some(dp) = datepattern {
        filter_cfg.datepattern = Some(dp);
    }

    let compiled = CompiledFilter::compile(filter_cfg)?;

    // Read log lines.
    let reader: Box<dyn BufRead> = if log_path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(std::fs::File::open(log_path)?))
    };

    let mut total = 0u64;
    let mut matched = 0u64;
    let mut hosts = std::collections::BTreeSet::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.is_empty() {
            continue;
        }
        total += 1;
        match compiled.process_line(&line) {
            Ok(Some(m)) => {
                matched += 1;
                hosts.insert(m.host.clone());
                if verbose {
                    println!("[OK] host={} line={}", m.host, line);
                }
            }
            Ok(None) => {
                if verbose {
                    println!("[--] {}", line);
                }
            }
            Err(e) => {
                if verbose {
                    println!("[ERR] {e}: {}", line);
                }
            }
        }
    }

    println!();
    println!("Lines: total={}, matched={}", total, matched);
    println!("Unique hosts: {}", hosts.len());
    for h in &hosts {
        println!("  {}", h);
    }
    Ok(())
}
