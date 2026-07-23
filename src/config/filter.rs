//! Filter configuration model (`filter.d/<name>.conf`).

use crate::error::{Error, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The runtime parameters of a filter (interpolated & ready to compile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Filter name.
    pub name: String,
    /// `prefregex` (pre-filter regex).
    #[serde(default)]
    pub prefregex: Option<String>,
    /// `failregex` list (one entry per line).
    #[serde(default)]
    pub failregex: Vec<String>,
    /// `ignoreregex` list.
    #[serde(default)]
    pub ignoreregex: Vec<String>,
    /// `datepattern` (explicit or `None` for auto-detection).
    #[serde(default)]
    pub datepattern: Option<String>,
    /// `maxlines` (override from jail).
    #[serde(default = "default_maxlines")]
    pub maxlines: u32,
    /// `logtype` (`file`/`short`/`journal`/`rfc5424`).
    #[serde(default = "default_logtype")]
    pub logtype: String,
    /// `journalmatch` expressions.
    #[serde(default)]
    pub journalmatch: Vec<String>,
    /// Init parameters (from `[Init]` and overridden by jail's `filter[...]`).
    #[serde(default)]
    pub init: IndexMap<String, String>,
}

/// The raw definition as loaded from disk (before interpolation).
#[derive(Debug, Clone, Default)]
pub struct FilterDefinition {
    /// Filter name.
    pub name: String,
    /// Raw sections (Definition, Init, Includes, lt_*, ...).
    pub doc: crate::config::IniDocument,
}

fn default_maxlines() -> u32 {
    1
}
fn default_logtype() -> String {
    "file".into()
}

impl FilterDefinition {
    /// Load and resolve a filter from `filter.d/<name>.conf` (+`.local`).
    pub fn load(
        name: &str,
        search_dirs: &[std::path::PathBuf],
    ) -> Result<Self> {
        let mut doc = crate::config::IniDocument::new();
        let mut loaded = std::collections::HashSet::new();
        for d in search_dirs {
            let conf = d.join("filter.d").join(format!("{name}.conf"));
            let local = d.join("filter.d").join(format!("{name}.local"));
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
                "filter {name:?} not found in {:?}",
                search_dirs
            )));
        }
        Ok(FilterDefinition {
            name: name.into(),
            doc,
        })
    }

    /// Materialize a [`FilterConfig`] by interpolating the `[Definition]`
    /// section, applying init parameters from the jail.
    pub fn materialize(
        &self,
        init: &IndexMap<String, String>,
        defaults: &IndexMap<String, String>,
        builtins: &IndexMap<String, String>,
    ) -> Result<FilterConfig> {
        let def_sec = self
            .doc
            .section("Definition")
            .ok_or_else(|| Error::config(format!("filter {} missing [Definition]", self.name)))?;

        // Build the init parameter map: start from the filter's [Init] section,
        // then apply the overrides from the jail's `filter[...]`.
        let mut merged_init = IndexMap::new();
        if let Some(init_sec) = self.doc.section("Init") {
            for (k, v) in &init_sec.entries {
                merged_init.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in init {
            merged_init.insert(k.clone(), v.clone());
        }

        // Known map: for `%(known/parameter)s` lookups we use the merged init
        // plus any keys defined under [Definition] (since `%(known/failregex)s`
        // is common).
        let mut known = IndexMap::new();
        for (k, v) in &def_sec.entries {
            known.insert(k.clone(), v.clone());
        }
        for (k, v) in &merged_init {
            known.insert(k.clone(), v.clone());
        }

        // Interpolate every [Definition] entry under current_section = "Definition".
        let ctx = crate::config::InterpolationContext {
            doc: &self.doc,
            defaults,
            builtins,
            current_section: Some("Definition".into()),
            init: &merged_init,
            known: &known,
        };

        let get = |key: &str| -> Option<String> {
            def_sec.get(key).map(|s| {
                crate::config::interpolate(s, &ctx)
                    .unwrap_or_else(|_| s.to_string())
            })
        };

        let prefregex = get("prefregex");
        let failregex = get("failregex")
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let ignoreregex = get("ignoreregex")
            .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let datepattern = get("datepattern");
        let maxlines = get("maxlines")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(default_maxlines);
        let logtype = get("logtype").unwrap_or_else(default_logtype);
        let journalmatch = get("journalmatch")
            .map(|s| {
                s.split('+')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(FilterConfig {
            name: self.name.clone(),
            prefregex,
            failregex,
            ignoreregex,
            datepattern,
            maxlines,
            logtype,
            journalmatch,
            init: merged_init,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_filter() {
        let r = FilterDefinition::load("does-not-exist", &[]);
        assert!(r.is_err());
    }
}
