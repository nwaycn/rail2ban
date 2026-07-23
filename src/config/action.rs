//! Action configuration model (`action.d/<name>.conf`).

use crate::error::{Error, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The runtime parameters of an action (interpolated, ready to execute).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionConfig {
    /// Action name (e.g. `iptables-multiport`).
    pub name: String,
    /// `actionstart` command (jail start).
    #[serde(default)]
    pub actionstart: Option<String>,
    /// `actionstop` command (jail stop).
    #[serde(default)]
    pub actionstop: Option<String>,
    /// `actioncheck` command (run before ban/unban to verify environment).
    #[serde(default)]
    pub actioncheck: Option<String>,
    /// `actionrepair` command (run when `actioncheck` fails, to repair state).
    #[serde(default)]
    pub actionrepair: Option<String>,
    /// `actionflush` command (clear all bans at once).
    #[serde(default)]
    pub actionflush: Option<String>,
    /// `actionban` command.
    #[serde(default)]
    pub actionban: Option<String>,
    /// `actionunban` command.
    #[serde(default)]
    pub actionunban: Option<String>,
    /// `actionstart_on_demand`.
    #[serde(default)]
    pub actionstart_on_demand: bool,
    /// Command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Resolved init parameters (after family selection, type selection, etc.).
    #[serde(default)]
    pub init: IndexMap<String, String>,
}

fn default_timeout() -> u64 {
    60
}

/// The raw definition loaded from disk.
#[derive(Debug, Clone, Default)]
pub struct ActionDefinition {
    /// Action name.
    pub name: String,
    /// Parsed INI document.
    pub doc: crate::config::IniDocument,
}

impl ActionDefinition {
    /// Load and resolve an action from `action.d/<name>.conf` (+`.local`).
    pub fn load(
        name: &str,
        search_dirs: &[std::path::PathBuf],
    ) -> Result<Self> {
        let mut doc = crate::config::IniDocument::new();
        let mut loaded = std::collections::HashSet::new();
        for d in search_dirs {
            let conf = d.join("action.d").join(format!("{name}.conf"));
            let local = d.join("action.d").join(format!("{name}.local"));
            if conf.exists() {
                let d2 = crate::config::parse_ini_file(&conf)?;
                let d2 = crate::config::resolve_includes(d2, &conf, search_dirs, &mut loaded)?;
                doc.merge(d2);
            }
            if local.exists() {
                let d2 = crate::config::parse_ini_file(&local)?;
                let d2 = crate::config::resolve_includes(d2, &local, search_dirs, &mut loaded)?;
                doc.merge(d2);
            }
        }
        if doc.sections.is_empty() {
            return Err(Error::config(format!(
                "action {name:?} not found in {:?}",
                search_dirs
            )));
        }
        Ok(ActionDefinition {
            name: name.into(),
            doc,
        })
    }

    /// Materialize an [`ActionConfig`], applying init parameters from the
    /// jail's `action[name=key, ...]` invocation.
    ///
    /// `family` selects between `[Init]` and `[Init?family=inet6]`.
    pub fn materialize(
        &self,
        jail_params: &IndexMap<String, String>,
        defaults: &IndexMap<String, String>,
        builtins: &IndexMap<String, String>,
        family: Option<&str>,
    ) -> Result<ActionConfig> {
        let def_sec = self
            .doc
            .section("Definition")
            .ok_or_else(|| Error::config(format!("action {} missing [Definition]", self.name)))?;

        // Build init parameters: start with [Init] section, then apply
        // family-specific overrides `[Init?family=inet6]`, then apply
        // `key?family=inet6=value` overrides inside [Init], then apply jail
        // params (which themselves may be `key?family=inet6=value`).
        let mut merged = IndexMap::new();
        for sec in self.doc.sections_named("Init") {
            for (k, v) in &sec.entries {
                merged.insert(k.clone(), v.clone());
            }
        }
        if let Some(fam) = family {
            let family_section = format!("Init?family={fam}");
            for sec in self.doc.sections_named(&family_section) {
                for (k, v) in &sec.entries {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        // Apply inline `key?family=inet6=value` from [Init] (already merged
        // above as separate keys; here we re-key by stripping family suffix
        // when the family matches).
        let mut family_specific = IndexMap::new();
        for (k, v) in merged.clone() {
            if let Some(rest) = k.strip_suffix("?family=inet6") {
                if family == Some("inet6") {
                    family_specific.insert(rest.to_string(), v);
                }
            } else if let Some(rest) = k.strip_suffix("?family=inet4") {
                if family == Some("inet4") {
                    family_specific.insert(rest.to_string(), v);
                }
            }
        }
        for (k, v) in family_specific {
            merged.insert(k, v);
        }
        // Apply jail-provided params (after interpolation against defaults).
        for (k, v) in jail_params {
            if let Some(rest) = k.strip_suffix("?family=inet6") {
                if family == Some("inet6") {
                    merged.insert(rest.to_string(), v.clone());
                }
            } else if let Some(rest) = k.strip_suffix("?family=inet4") {
                if family == Some("inet4") {
                    merged.insert(rest.to_string(), v.clone());
                }
            } else {
                merged.insert(k.clone(), v.clone());
            }
        }

        let known = IndexMap::new();
        let ctx = crate::config::InterpolationContext {
            doc: &self.doc,
            defaults,
            builtins,
            current_section: Some("Definition".into()),
            init: &merged,
            known: &known,
        };

        let get = |key: &str| -> Option<String> {
            def_sec.get(key).map(|s| {
                crate::config::interpolate(s, &ctx).unwrap_or_else(|_| s.to_string())
            })
        };

        let timeout = merged
            .get("timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(default_timeout());
        let actionstart_on_demand = merged
            .get("actionstart_on_demand")
            .map(|s| crate::config::jail::parse_bool(s).unwrap_or(false))
            .unwrap_or(false);

        Ok(ActionConfig {
            name: self.name.clone(),
            actionstart: get("actionstart"),
            actionstop: get("actionstop"),
            actioncheck: get("actioncheck"),
            actionrepair: get("actionrepair"),
            actionflush: get("actionflush"),
            actionban: get("actionban"),
            actionunban: get("actionunban"),
            actionstart_on_demand,
            timeout,
            init: merged,
        })
    }
}
