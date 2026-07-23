//! Action lifecycle execution.
//!
//! Each action is materialized into an [`Action`] instance bound to a jail.
//! When a ban/unban event occurs, the [`ActionExecutor`] expands the
//! `<ip>`, `<F-USER>`, `<name>`, `<bantime>`, ... tags into the action's
//! command strings and runs them.

use crate::config::ActionConfig;
use crate::error::{Error, Result};
use crate::ip::IpFamily;
use chrono::Utc;
use indexmap::IndexMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// A materialized action bound to a specific jail.
#[derive(Debug, Clone)]
pub struct Action {
    /// The action name.
    pub name: String,
    /// The jail name.
    pub jail: String,
    /// Resolved action config.
    pub config: ActionConfig,
    /// Whether `actionstart` has already been executed.
    pub started: bool,
}

impl Action {
    /// Build a new action bound to `jail`.
    pub fn new(jail: &str, cfg: ActionConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            jail: jail.into(),
            config: cfg,
            started: false,
        }
    }
}

/// Information passed to `actionban`/`actionunban`/`actioncheck`.
#[derive(Debug, Clone)]
pub struct BanContext {
    /// The banned IP address (or raw failure ID).
    pub ip: String,
    /// Parsed IP (when applicable).
    pub ip_addr: Option<IpAddr>,
    /// IP family.
    pub family: IpFamily,
    /// Captured user (from failregex `<F-USER>`).
    pub user: Option<String>,
    /// Captured alt user.
    pub alt_user: Option<String>,
    /// Raw failure ID (for non-IP bans).
    pub fid: Option<String>,
    /// Ban duration in seconds (None = permanent).
    pub bantime: Option<u64>,
    /// Matched log lines (subject to `maxmatches`).
    pub matches: Vec<String>,
    /// Number of failures that triggered the ban.
    pub failures: u32,
}

impl BanContext {
    /// Build a minimal context for an IP ban.
    pub fn for_ip(ip: IpAddr, bantime: Option<u64>) -> Self {
        let family = crate::ip::family_of(ip);
        Self {
            ip: ip.to_string(),
            ip_addr: Some(ip),
            family,
            user: None,
            alt_user: None,
            fid: None,
            bantime,
            matches: vec![],
            failures: 0,
        }
    }
}

/// Execute action commands.
pub struct ActionExecutor;

impl ActionExecutor {
    /// Run `actionstart` (if not yet started or if `force` is true).
    pub async fn start(action: &mut Action, force: bool) -> Result<()> {
        if action.started && !force {
            return Ok(());
        }
        if action.config.actionstart_on_demand && !force {
            return Ok(());
        }
        if let Some(cmd) = &action.config.actionstart {
            run_command(cmd, &action.config.init, &action.jail, None, action.config.timeout).await?;
        }
        action.started = true;
        Ok(())
    }

    /// Run `actionstop`.
    pub async fn stop(action: &mut Action) -> Result<()> {
        if !action.started {
            return Ok(());
        }
        if let Some(cmd) = &action.config.actionstop {
            run_command(cmd, &action.config.init, &action.jail, None, action.config.timeout).await?;
        }
        action.started = false;
        Ok(())
    }

    /// Run `actioncheck`. Returns Ok(true) if check passed, Ok(false) if
    /// check is not configured, Err on failure.
    pub async fn check(action: &Action, ctx: &BanContext) -> Result<bool> {
        if let Some(cmd) = &action.config.actioncheck {
            run_command(cmd, &action.config.init, &action.jail, Some(ctx), action.config.timeout)
                .await
                .map(|_| true)
        } else {
            Ok(false)
        }
    }

    /// Run `actionrepair` (when `actioncheck` fails).
    pub async fn repair(action: &Action, ctx: &BanContext) -> Result<()> {
        if let Some(cmd) = &action.config.actionrepair {
            run_command(cmd, &action.config.init, &action.jail, Some(ctx), action.config.timeout).await?;
        }
        Ok(())
    }

    /// Run `actionflush` (clear all bans at once).
    pub async fn flush(action: &Action) -> Result<()> {
        if let Some(cmd) = &action.config.actionflush {
            run_command(cmd, &action.config.init, &action.jail, None, action.config.timeout).await?;
        }
        Ok(())
    }

    /// Run `actionban`. If `actionstart_on_demand` is set and the action has
    /// not yet started, `actionstart` is run first.
    pub async fn ban(action: &mut Action, ctx: &BanContext) -> Result<()> {
        if action.config.actionstart_on_demand && !action.started {
            Self::start(action, true).await?;
        }
        if let Some(cmd) = &action.config.actionban {
            run_command(cmd, &action.config.init, &action.jail, Some(ctx), action.config.timeout).await?;
        }
        Ok(())
    }

    /// Run `actionunban`.
    pub async fn unban(action: &mut Action, ctx: &BanContext) -> Result<()> {
        if let Some(cmd) = &action.config.actionunban {
            run_command(cmd, &action.config.init, &action.jail, Some(ctx), action.config.timeout).await?;
        }
        Ok(())
    }
}

async fn run_command(
    cmd_template: &str,
    init: &IndexMap<String, String>,
    jail: &str,
    ctx: Option<&BanContext>,
    timeout_secs: u64,
) -> Result<()> {
    let expanded = expand_command(cmd_template, init, jail, ctx);
    let argv = shlex::split(&expanded)
        .ok_or_else(|| Error::Action(format!("invalid command line: {expanded}")))?;
    if argv.is_empty() {
        return Ok(());
    }
    tracing::debug!("exec: {:?}", argv);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);

    let child = command
        .spawn()
        .map_err(|e| Error::Action(format!("spawning {:?}: {e}", argv[0])))?;
    let result = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await;
    match result {
        Ok(Ok(out)) => {
            if out.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(Error::Action(format!(
                    "command {:?} exited with {:?}: {}",
                    argv[0],
                    out.status.code(),
                    stderr.trim()
                )))
            }
        }
        Ok(Err(e)) => Err(Error::Action(format!(
            "waiting for {:?}: {e}",
            argv[0]
        ))),
        Err(_) => Err(Error::Action(format!(
            "command {:?} timed out after {timeout_secs}s",
            argv[0]
        ))),
    }
}

/// Expand `<ip>`, `<F-USER>`, ... tags inside an action command template.
pub fn expand_command(
    template: &str,
    init: &IndexMap<String, String>,
    jail: &str,
    ctx: Option<&BanContext>,
) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(end) = template[i..].find('>') {
                let tag = &template[i + 1..i + end];
                if let Some(value) = lookup_tag(tag, init, jail, ctx) {
                    out.push_str(&value);
                    i += end + 1;
                    continue;
                }
            }
        }
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&template[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn utf8_len(b: u8) -> usize {
    if b < 0xC0 {
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

fn lookup_tag(
    tag: &str,
    init: &IndexMap<String, String>,
    jail: &str,
    ctx: Option<&BanContext>,
) -> Option<String> {
    match tag {
        "ip" => ctx.map(|c| c.ip.clone()),
        "ip-host" => ctx.and_then(|c| c.ip_addr.map(|_| c.ip.clone())),
        "ip-family" => ctx.map(|c| c.family.as_str().to_string()),
        "F-USER" => ctx.and_then(|c| c.user.clone()),
        "F-ALT_USER" => ctx.and_then(|c| c.alt_user.clone()),
        "fid" => ctx.and_then(|c| c.fid.clone()).or_else(|| ctx.map(|c| c.ip.clone())),
        "name" | "jail" => Some(jail.to_string()),
        "bantime" => ctx.and_then(|c| c.bantime.map(|s| s.to_string())),
        "unbanip" => ctx.map(|c| c.ip.clone()),
        "matches" => ctx.map(|c| c.matches.join("\n")),
        "ipmatches" | "ipjailmatches" => ctx.map(|c| c.matches.join("\n")),
        "failures" => ctx.map(|c| c.failures.to_string()),
        _ => {
            // Init parameter.
            init.get(tag).cloned()
        }
    }
}

#[allow(dead_code)]
fn _now_iso() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ActionConfig;
    use indexmap::IndexMap;

    #[allow(dead_code)]
    fn make_cfg() -> ActionConfig {
        ActionConfig {
            name: "test".into(),
            actionstart: Some("echo start <name>".into()),
            actionstop: Some("echo stop".into()),
            actioncheck: None,
            actionrepair: None,
            actionflush: None,
            actionban: Some("echo ban <ip>".into()),
            actionunban: Some("echo unban <ip>".into()),
            actionstart_on_demand: false,
            timeout: 5,
            init: IndexMap::new(),
        }
    }

    #[test]
    fn expands_ip_tag() {
        let ctx = BanContext::for_ip("192.0.2.10".parse().unwrap(), Some(3600));
        let out = expand_command("echo ban <ip> from <name>", &IndexMap::new(), "sshd", Some(&ctx));
        assert_eq!(out, "echo ban 192.0.2.10 from sshd");
    }

    #[test]
    fn expands_init_param() {
        let mut init = IndexMap::new();
        init.insert("port".into(), "ssh".into());
        let out = expand_command("iptables -p <port>", &init, "sshd", None);
        assert_eq!(out, "iptables -p ssh");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn runs_start_and_ban() {
        let mut a = Action::new("sshd", make_cfg());
        ActionExecutor::start(&mut a, false).await.unwrap();
        assert!(a.started);
        let ctx = BanContext::for_ip("192.0.2.10".parse().unwrap(), Some(3600));
        ActionExecutor::ban(&mut a, &ctx).await.unwrap();
        ActionExecutor::stop(&mut a).await.unwrap();
        assert!(!a.started);
    }
}
