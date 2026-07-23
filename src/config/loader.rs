//! High-level configuration loader: walks the search dirs, merges
//! `jail.conf`/`jail.d/*.conf`/`jail.local`/`jail.d/*.local`, then loads
//! referenced filters and actions.

use crate::config::{
    parse_ini_file, ActionDefinition, FilterDefinition, IniDocument, JailConfig, JailSet,
    interpolate, InterpolationContext, builtin_defaults,
};
use crate::error::{Error, Result};
use indexmap::IndexMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The fully loaded configuration.
#[derive(Debug, Default, Clone)]
pub struct LoadedConfig {
    /// Global defaults (from `[DEFAULT]` sections + builtins).
    pub defaults: IndexMap<String, String>,
    /// All jails.
    pub jails: JailSet,
    /// Loaded filter definitions (raw).
    pub filters: IndexMap<String, FilterDefinition>,
    /// Loaded action definitions (raw).
    pub actions: IndexMap<String, ActionDefinition>,
    /// Global fail2ban.conf settings.
    pub global: GlobalConfig,
}

/// Global (`fail2ban.conf`) settings.
#[derive(Debug, Clone, Default)]
pub struct GlobalConfig {
    /// Log level.
    pub loglevel: String,
    /// Log target.
    pub logtarget: String,
    /// Unix socket path.
    pub socket: String,
    /// PID file path.
    pub pidfile: String,
    /// Database file path.
    pub dbfile: String,
    /// Maximum matches stored per ticket in DB.
    pub dbmaxmatches: u32,
    /// Ban history purge age (seconds).
    pub dbpurgeage: u64,
    /// Allow IPv6.
    pub allowipv6: String,
    /// Per-thread stack size (KiB).
    pub stacksize: u32,
}

impl GlobalConfig {
    /// Defaults matching fail2ban upstream.
    pub fn defaults() -> Self {
        Self {
            loglevel: "INFO".into(),
            logtarget: "STDOUT".into(),
            socket: "/var/run/rail2ban/rail2ban.sock".into(),
            pidfile: "/var/run/rail2ban/rail2ban.pid".into(),
            dbfile: "/var/lib/rail2ban/rail2ban.sqlite3".into(),
            dbmaxmatches: 10,
            dbpurgeage: 86400,
            allowipv6: "auto".into(),
            stacksize: 0,
        }
    }
}

/// Walks the configuration tree and assembles a [`LoadedConfig`].
pub struct ConfigLoader {
    search_dirs: Vec<PathBuf>,
}

impl ConfigLoader {
    /// Create a new loader with the given search directories (in priority
    /// order; later dirs override earlier).
    pub fn new(search_dirs: Vec<PathBuf>) -> Self {
        Self { search_dirs }
    }

    /// Load everything.
    pub fn load(&self) -> Result<LoadedConfig> {
        let global = self.load_global()?;
        let jails = self.load_jails()?;
        let mut defaults = jails.defaults.clone();
        for (k, v) in builtin_defaults() {
            defaults.entry(k).or_insert(v);
        }

        // Load filter/action definitions referenced by jails.
        let mut filters: IndexMap<String, FilterDefinition> = IndexMap::new();
        let mut actions: IndexMap<String, ActionDefinition> = IndexMap::new();
        for j in jails.jails.values() {
            if !j.filter.is_empty() && !filters.contains_key(&j.filter) {
                let f = FilterDefinition::load(&j.filter, &self.search_dirs)?;
                filters.insert(j.filter.clone(), f);
            }
            for action_spec in &j.actions {
                let name = action_name(action_spec);
                if !name.is_empty() && !actions.contains_key(name) {
                    match ActionDefinition::load(name, &self.search_dirs) {
                        Ok(a) => {
                            actions.insert(name.into(), a);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "could not load action {name:?}: {e}; jail {} will skip it",
                                j.name
                            );
                        }
                    }
                }
            }
        }

        Ok(LoadedConfig {
            defaults,
            jails,
            filters,
            actions,
            global,
        })
    }

    fn load_global(&self) -> Result<GlobalConfig> {
        let mut g = GlobalConfig::defaults();
        let mut doc = IniDocument::new();
        let mut loaded = HashSet::new();
        for d in &self.search_dirs {
            for fname in &["fail2ban.conf", "rail2ban.conf"] {
                let p = d.join(fname);
                if p.exists() {
                    let d2 = parse_ini_file(&p)?;
                    let d2 =
                        crate::config::resolve_includes(d2, &p, &self.search_dirs, &mut loaded)?;
                    doc.merge(d2);
                }
            }
            let dd = d.join("fail2ban.d");
            if let Ok(entries) = std::fs::read_dir(&dd) {
                let mut files: Vec<PathBuf> = entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("conf"))
                    .collect();
                files.sort();
                for f in files {
                    let d2 = parse_ini_file(&f)?;
                    let d2 =
                        crate::config::resolve_includes(d2, &f, &self.search_dirs, &mut loaded)?;
                    doc.merge(d2);
                }
            }
        }
        if let Some(def) = doc.section("Definition") {
            if let Some(v) = def.get("loglevel") {
                g.loglevel = v.into();
            }
            if let Some(v) = def.get("logtarget") {
                g.logtarget = v.into();
            }
            if let Some(v) = def.get("socket") {
                g.socket = v.into();
            }
            if let Some(v) = def.get("pidfile") {
                g.pidfile = v.into();
            }
            if let Some(v) = def.get("dbfile") {
                g.dbfile = v.into();
            }
            if let Some(v) = def.get("dbmaxmatches") {
                g.dbmaxmatches = v.parse().unwrap_or(g.dbmaxmatches);
            }
            if let Some(v) = def.get("dbpurgeage") {
                g.dbpurgeage = crate::time::TimeValue::parse(v)?
                    .to_seconds_or_max();
            }
            if let Some(v) = def.get("allowipv6") {
                g.allowipv6 = v.into();
            }
        }
        if let Some(t) = doc.section("Thread") {
            if let Some(v) = t.get("stacksize") {
                g.stacksize = v.parse().unwrap_or(0);
            }
        }
        Ok(g)
    }

    fn load_jails(&self) -> Result<JailSet> {
        let mut doc = IniDocument::new();
        let mut loaded = HashSet::new();
        let mut merge_from = |path: &Path| -> Result<()> {
            if path.exists() {
                let d = parse_ini_file(path)?;
                let d =
                    crate::config::resolve_includes(d, path, &self.search_dirs, &mut loaded)?;
                doc.merge(d);
            }
            Ok(())
        };
        for d in &self.search_dirs {
            merge_from(&d.join("jail.conf"))?;
            merge_from(&d.join("rail2ban.conf"))?;
            // jail.d/*.conf
            let dd = d.join("jail.d");
            if let Ok(entries) = std::fs::read_dir(&dd) {
                let mut files: Vec<PathBuf> = entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("conf"))
                    .collect();
                files.sort();
                for f in files {
                    merge_from(&f)?;
                }
            }
            merge_from(&d.join("jail.local"))?;
            merge_from(&d.join("rail2ban.local"))?;
            // jail.d/*.local
            let dd = d.join("jail.d");
            if let Ok(entries) = std::fs::read_dir(&dd) {
                let mut files: Vec<PathBuf> = entries
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("local"))
                    .collect();
                files.sort();
                for f in files {
                    merge_from(&f)?;
                }
            }
        }

        // Pull [DEFAULT] entries.
        let mut defaults = IndexMap::new();
        for sec in doc.sections_named("DEFAULT") {
            for (k, v) in &sec.entries {
                defaults.insert(k.clone(), v.clone());
            }
        }
        // Interpolate default values against each other.
        let builtins = builtin_defaults();
        let ctx = InterpolationContext {
            doc: &doc,
            defaults: &IndexMap::new(),
            builtins: &builtins,
            current_section: Some("DEFAULT".into()),
            init: &IndexMap::new(),
            known: &IndexMap::new(),
        };
        let mut interpolated_defaults = IndexMap::new();
        for (k, v) in &defaults {
            let val = interpolate(v, &ctx).unwrap_or_else(|e| {
                tracing::warn!("interpolating default {k}: {e}; using raw value");
                v.clone()
            });
            interpolated_defaults.insert(k.clone(), val);
        }

        // Build each jail.
        let mut jails = IndexMap::new();
        for sec in &doc.sections {
            if sec.name == "DEFAULT" || sec.name == "INCLUDES" || sec.name.starts_with("Init") {
                continue;
            }
            // Skip sections that are sub-sections like `lt_file`, `ipt_*`.
            if sec.name.starts_with("lt_") || sec.name.starts_with("ipt_") {
                continue;
            }
            if sec.entries.is_empty() {
                continue;
            }
            match JailConfig::from_section(&sec.name, sec, &interpolated_defaults) {
                Ok(j) => {
                    jails.insert(sec.name.clone(), j);
                }
                Err(e) => {
                    tracing::error!("failed to build jail {}: {e}", sec.name);
                    return Err(e);
                }
            }
        }

        Ok(JailSet {
            defaults: interpolated_defaults,
            jails,
        })
    }
}

/// Extract the action name from a spec like `iptables-multiport[name=sshd, port=ssh]`.
pub fn action_name(spec: &str) -> &str {
    let spec = spec.trim();
    match spec.find('[') {
        Some(i) => spec[..i].trim(),
        None => spec,
    }
}

/// Extract the jail-supplied parameters from a spec like
/// `iptables-multiport[name=sshd, port=ssh]`.
pub fn action_params(spec: &str) -> Result<IndexMap<String, String>> {
    let spec = spec.trim();
    let bracket = match spec.find('[') {
        Some(i) => i,
        None => return Ok(IndexMap::new()),
    };
    let rest = &spec[bracket + 1..];
    let end = rest
        .rfind(']')
        .ok_or_else(|| Error::config(format!("missing ] in action spec: {spec}")))?;
    let body = &rest[..end];
    let mut params = IndexMap::new();
    for kv in split_top_level(body, ',') {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| Error::config(format!("bad action param: {kv}")))?
            ;
        let k = k.trim().to_string();
        let v = strip_quotes(v.trim());
        params.insert(k, v);
    }
    Ok(params)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_name_simple() {
        assert_eq!(action_name("iptables-multiport"), "iptables-multiport");
    }

    #[test]
    fn action_name_with_params() {
        assert_eq!(action_name("iptables-multiport[name=sshd]"), "iptables-multiport");
    }

    #[test]
    fn action_params_parse() {
        let p = action_params("foo[a=1, b=\"x,y\", c=2]").unwrap();
        assert_eq!(p.get("a").unwrap(), "1");
        assert_eq!(p.get("b").unwrap(), "x,y");
        assert_eq!(p.get("c").unwrap(), "2");
    }
}
