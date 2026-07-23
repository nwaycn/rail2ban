//! Jail configuration model.

use crate::error::{Error, Result};
use crate::ip::IgnoreList;
use crate::time::TimeValue;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// A single jail definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailConfig {
    /// Jail name (e.g. `sshd`).
    pub name: String,
    /// Whether this jail is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Filter name (e.g. `sshd`); resolved against `filter.d/`.
    pub filter: String,
    /// Filter init parameters, e.g. `{"mode": "normal"}`.
    #[serde(default)]
    pub filter_params: IndexMap<String, String>,
    /// Log paths to monitor.
    #[serde(default)]
    pub logpath: Vec<String>,
    /// Whether to tail the log on start (vs. read from head).
    #[serde(default)]
    pub logpath_tail: Vec<bool>,
    /// Backend: `auto` | `pyinotify`/`inotify` | `polling` | `systemd`.
    #[serde(default = "default_backend")]
    pub backend: String,
    /// Log encoding.
    #[serde(default = "default_logencoding")]
    pub logencoding: String,
    /// Forced log timezone (e.g. `UTC+0200`).
    #[serde(default)]
    pub logtimezone: Option<String>,
    /// systemd journal match expressions (`+` separated = OR).
    #[serde(default)]
    pub journalmatch: Vec<String>,
    /// `maxretry` failures within `findtime` triggers a ban.
    #[serde(default = "default_maxretry")]
    pub maxretry: u32,
    /// Sliding window length (seconds).
    #[serde(default = "default_findtime")]
    pub findtime: TimeValue,
    /// Ban duration (seconds, or permanent).
    #[serde(default = "default_bantime")]
    pub bantime: TimeValue,
    /// Ban time increment parameters (for recidive-style escalating bans).
    #[serde(default)]
    pub bantime_increment: bool,
    /// Factor for bantime increment.
    #[serde(default = "default_bantime_factor")]
    pub bantime_factor: u32,
    /// Max bantime when incrementing.
    #[serde(default)]
    pub bantime_maxtime: Option<TimeValue>,
    /// Random jitter to add to bantime (dodge synchronized retries).
    #[serde(default)]
    pub bantime_rndtime: Option<TimeValue>,
    /// DNS usage mode for `<HOST>` hostnames: `yes` | `warn` | `no` | `raw`.
    #[serde(default = "default_usedns")]
    pub usedns: String,
    /// Whether to ignore own IPs.
    #[serde(default = "default_ignoreself")]
    pub ignoreself: bool,
    /// Whitelist IPs / CIDRs / hostnames / `file:` references.
    #[serde(default)]
    pub ignoreip: IgnoreList,
    /// External command to determine whether to ignore an IP.
    #[serde(default)]
    pub ignorecommand: Option<String>,
    /// Ignore cache spec: `key="...", max-count=N, max-time=Tm`.
    #[serde(default)]
    pub ignorecache: Option<String>,
    /// Action definitions as written in `jail.conf`, e.g.
    /// `iptables-multiport[name=%(__name__)s, port=%(port)s]`.
    #[serde(default)]
    pub actions: Vec<String>,
    /// `actionstart_on_demand` — defer `actionstart` until first ban.
    #[serde(default)]
    pub actionstart_on_demand: bool,
    /// `maxlines` — number of lines buffered for multi-line regex matching.
    #[serde(default = "default_maxlines")]
    pub maxlines: u32,
    /// `maxmatches` — max matched lines kept per ticket in memory.
    #[serde(default = "default_maxmatches")]
    pub maxmatches: u32,
    /// `skip_if_nologs` — start failure tolerated when no logs found.
    #[serde(default)]
    pub skip_if_nologs: bool,
    /// `systemd_if_nologs` — switch backend to `systemd` when no logs found.
    #[serde(default = "default_systemd_if_nologs")]
    pub systemd_if_nologs: bool,
    /// Extra arbitrary parameters (for variable interpolation).
    #[serde(flatten)]
    pub extra: IndexMap<String, String>,
}

impl JailConfig {
    /// Parse a single `[<name>]` section into a `JailConfig`, applying
    /// defaults from the `defaults` map.
    pub fn from_section(
        name: &str,
        section: &crate::config::IniSection,
        defaults: &IndexMap<String, String>,
    ) -> Result<Self> {
        let get = |key: &str| -> Option<String> {
            section
                .get(key)
                .map(|s| s.to_string())
                .or_else(|| defaults.get(key).cloned())
        };
        let get_or = |key: &str, default: &str| -> String {
            get(key).unwrap_or_else(|| default.to_string())
        };

        let enabled = parse_bool(&get_or("enabled", "false"))?;
        let filter_str = get_or("filter", "");
        let (filter, filter_params) = parse_filter_spec(&filter_str)?;
        let logpath = parse_list(&get_or("logpath", ""));
        let backend = get_or("backend", "auto");
        let logencoding = get_or("logencoding", "auto");
        let logtimezone = get("logtimezone");
        let journalmatch = parse_list(&get_or("journalmatch", ""));
        let maxretry = get_or("maxretry", "5")
            .parse::<u32>()
            .map_err(|e| Error::config(format!("maxretry: {e}")))?;
        let findtime = TimeValue::parse(&get_or("findtime", "10m"))?;
        let bantime = TimeValue::parse(&get_or("bantime", "10m"))?;
        let bantime_increment = parse_bool(&get_or("bantime_increment", "false"))?;
        let bantime_factor = get_or("bantime.factor", "1")
            .parse::<u32>()
            .map_err(|e| Error::config(format!("bantime.factor: {e}")))?;
        let bantime_maxtime = match get("bantime.maxtime") {
            Some(s) => Some(TimeValue::parse(&s)?),
            None => None,
        };
        let bantime_rndtime = match get("bantime.rndtime") {
            Some(s) => Some(TimeValue::parse(&s)?),
            None => None,
        };
        let usedns = get_or("usedns", "warn");
        let ignoreself = parse_bool(&get_or("ignoreself", "true"))?;
        let ignoreip_str = get_or("ignoreip", "");
        let ignoreip = if ignoreip_str.is_empty() {
            IgnoreList::new()
        } else {
            IgnoreList::parse(&ignoreip_str)?
        };
        let ignorecommand = get("ignorecommand");
        let ignorecache = get("ignorecache");
        let mut actions = Vec::new();
        if let Some(a) = get("action") {
            // `action = a[x=y]\n         b[z=w]` is multi-line.
            for line in a.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    actions.push(line.to_string());
                }
            }
        }
        if let Some(ba) = get("banaction") {
            actions.push(ba);
        }
        if let Some(ba) = get("banaction_allports") {
            actions.push(ba);
        }
        let actionstart_on_demand = parse_bool(&get_or("actionstart_on_demand", "false"))?;
        let maxlines = get_or("maxlines", "1")
            .parse::<u32>()
            .map_err(|e| Error::config(format!("maxlines: {e}")))?;
        let maxmatches = get_or("maxmatches", "10")
            .parse::<u32>()
            .map_err(|e| Error::config(format!("maxmatches: {e}")))?;
        let skip_if_nologs = parse_bool(&get_or("skip_if_nologs", "false"))?;
        let systemd_if_nologs = parse_bool(&get_or("systemd_if_nologs", "true"))?;

        // Collect extra keys not consumed above.
        let mut extra = IndexMap::new();
        for (k, v) in &section.entries {
            if !is_known_jail_key(k) {
                extra.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in defaults {
            if !is_known_jail_key(k) && !extra.contains_key(k) {
                extra.insert(k.clone(), v.clone());
            }
        }

        Ok(JailConfig {
            name: name.into(),
            enabled,
            filter,
            filter_params,
            logpath,
            logpath_tail: vec![],
            backend,
            logencoding,
            logtimezone,
            journalmatch,
            maxretry,
            findtime,
            bantime,
            bantime_increment,
            bantime_factor,
            bantime_maxtime,
            bantime_rndtime,
            usedns,
            ignoreself,
            ignoreip,
            ignorecommand,
            ignorecache,
            actions,
            actionstart_on_demand,
            maxlines,
            maxmatches,
            skip_if_nologs,
            systemd_if_nologs,
            extra,
        })
    }
}

/// The full set of jails loaded from `jail.conf`/`jail.d/*.conf`/`jail.local`.
#[derive(Debug, Default, Clone)]
pub struct JailSet {
    /// Default values (from `[DEFAULT]` and global config).
    pub defaults: IndexMap<String, String>,
    /// Jails, keyed by name.
    pub jails: IndexMap<String, JailConfig>,
}

fn default_backend() -> String {
    "auto".into()
}
fn default_logencoding() -> String {
    "auto".into()
}
fn default_maxretry() -> u32 {
    5
}
fn default_findtime() -> TimeValue {
    TimeValue::from(600)
}
fn default_bantime() -> TimeValue {
    TimeValue::from(600)
}
fn default_bantime_factor() -> u32 {
    1
}
fn default_usedns() -> String {
    "warn".into()
}
fn default_ignoreself() -> bool {
    true
}
fn default_maxlines() -> u32 {
    1
}
fn default_maxmatches() -> u32 {
    10
}
fn default_systemd_if_nologs() -> bool {
    true
}

/// Parse a filter spec like `sshd[mode=normal, sig="6"]` into `(name, params)`.
pub fn parse_filter_spec(spec: &str) -> Result<(String, IndexMap<String, String>)> {
    let spec = spec.trim();
    if let Some(bracket) = spec.find('[') {
        let name = spec[..bracket].trim().to_string();
        let rest = &spec[bracket + 1..];
        let end = rest
            .rfind(']')
            .ok_or_else(|| Error::config(format!("missing ']' in filter spec: {spec}")))?;
        let body = &rest[..end];
        let mut params = IndexMap::new();
        for kv in split_top_level(body, ',') {
            let kv = kv.trim();
            if kv.is_empty() {
                continue;
            }
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| Error::config(format!("bad filter param: {kv}")))?;
            let k = k.trim().to_string();
            let v = strip_quotes(v.trim());
            params.insert(k, v);
        }
        Ok((name, params))
    } else {
        Ok((spec.to_string(), IndexMap::new()))
    }
}

/// Split a string on `sep` but respect double-quoted segments.
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                buf.push(c);
            }
            c if c == sep && !in_quote => {
                out.push(std::mem::take(&mut buf));
            }
            c => buf.push(c),
        }
    }
    out.push(buf);
    out
}

fn strip_quotes(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Parse fail2ban-style boolean: `true`/`yes`/`on`/`1` → true,
/// `false`/`no`/`off`/`0` → false.
pub fn parse_bool(s: &str) -> Result<bool> {
    let s = s.trim().to_ascii_lowercase();
    match s.as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(Error::config(format!("invalid boolean: {s}"))),
    }
}

/// Parse whitespace/comma separated list.
fn parse_list(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// Whether a key is a known jail-level option (used to filter `extra`).
fn is_known_jail_key(k: &str) -> bool {
    matches!(
        k,
        "enabled"
            | "filter"
            | "logpath"
            | "backend"
            | "logencoding"
            | "logtimezone"
            | "journalmatch"
            | "maxretry"
            | "findtime"
            | "bantime"
            | "bantime_increment"
            | "bantime.factor"
            | "bantime.maxtime"
            | "bantime.rndtime"
            | "usedns"
            | "ignoreself"
            | "ignoreip"
            | "ignorecommand"
            | "ignorecache"
            | "action"
            | "banaction"
            | "banaction_allports"
            | "actionstart_on_demand"
            | "maxlines"
            | "maxmatches"
            | "skip_if_nologs"
            | "systemd_if_nologs"
            | "port"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IniSection;

    #[test]
    fn parses_filter_spec_simple() {
        let (n, p) = parse_filter_spec("sshd").unwrap();
        assert_eq!(n, "sshd");
        assert!(p.is_empty());
    }

    #[test]
    fn parses_filter_spec_params() {
        let (n, p) = parse_filter_spec("sshd[mode=normal, sig=\"6\"]").unwrap();
        assert_eq!(n, "sshd");
        assert_eq!(p.get("mode").unwrap(), "normal");
        assert_eq!(p.get("sig").unwrap(), "6");
    }

    #[test]
    fn builds_from_section() {
        let mut sec = IniSection::default();
        sec.name = "sshd".into();
        sec.set("enabled", "true");
        sec.set("filter", "sshd");
        sec.set("logpath", "/var/log/auth.log");
        sec.set("maxretry", "3");
        sec.set("bantime", "1h");
        sec.set("findtime", "10m");

        let defaults = IndexMap::new();
        let j = JailConfig::from_section("sshd", &sec, &defaults).unwrap();
        assert!(j.enabled);
        assert_eq!(j.filter, "sshd");
        assert_eq!(j.logpath, vec!["/var/log/auth.log"]);
        assert_eq!(j.maxretry, 3);
        assert_eq!(j.bantime.seconds, Some(3600));
        assert_eq!(j.findtime.seconds, Some(600));
    }

    #[test]
    fn parses_bool() {
        assert!(parse_bool("yes").unwrap());
        assert!(parse_bool("on").unwrap());
        assert!(parse_bool("1").unwrap());
        assert!(!parse_bool("no").unwrap());
        assert!(parse_bool("invalid").is_err());
    }
}
