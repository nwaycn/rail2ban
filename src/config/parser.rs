//! INI-style configuration file parser.
//!
//! Implements fail2ban-compatible INI syntax:
//! - `[section]` headers
//! - `key = value` pairs
//! - `#` line comments
//! - `; ` inline comments (must be preceded by whitespace)
//! - Continuation lines (leading whitespace, no `key =`)
//! - Comma/space separated multi-values

use crate::error::{Error, Result};
use indexmap::IndexMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// A single INI section (ordered map of key → value).
#[derive(Debug, Default, Clone)]
pub struct IniSection {
    /// The section name (e.g. `DEFAULT`, `sshd`, `Definition`, `Init`).
    pub name: String,
    /// Key-value pairs (insertion-ordered).
    pub entries: IndexMap<String, String>,
}

impl IniSection {
    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Get a value or return a default.
    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }

    /// Set a value.
    pub fn set<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.entries.insert(key.into(), value.into());
    }

    /// Append to an existing value (multi-line continuation).
    pub fn append<K: Into<String>>(&mut self, key: K, suffix: &str) {
        let key = key.into();
        let entry = self.entries.entry(key).or_default();
        if entry.is_empty() {
            entry.push_str(suffix);
        } else {
            entry.push('\n');
            entry.push_str(suffix);
        }
    }

    /// Returns whether the section is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A parsed INI document: a list of sections (preserving order; duplicate
/// section names are allowed for `[Init?family=inet6]`-style overrides).
#[derive(Debug, Default, Clone)]
pub struct IniDocument {
    /// Sections, in file order.
    pub sections: Vec<IniSection>,
}

impl IniDocument {
    /// Create an empty document.
    pub fn new() -> Self {
        Self::default()
    }

    /// Find the first section with the given name.
    pub fn section(&self, name: &str) -> Option<&IniSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find the first mutable section with the given name.
    pub fn section_mut(&mut self, name: &str) -> Option<&mut IniSection> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    /// All sections with the given name.
    pub fn sections_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a IniSection> + 'a {
        self.sections.iter().filter(move |s| s.name == name)
    }

    /// Get or insert a section.
    pub fn section_or_insert(&mut self, name: &str) -> &mut IniSection {
        if let Some(idx) = self.sections.iter().position(|s| s.name == name) {
            return &mut self.sections[idx];
        }
        self.sections.push(IniSection {
            name: name.into(),
            entries: IndexMap::new(),
        });
        self.sections.last_mut().unwrap()
    }

    /// Merge another document into this one. Sections with the same name have
    /// their entries overwritten (later wins).
    pub fn merge(&mut self, other: IniDocument) {
        for sec in other.sections {
            let target = self.section_or_insert(&sec.name);
            for (k, v) in sec.entries {
                target.entries.insert(k, v);
            }
        }
    }
}

/// Parse an INI string.
pub fn parse_ini(input: &str) -> Result<IniDocument> {
    let mut doc = IniDocument::new();
    let mut current: Option<String> = None;

    for (lineno, raw_line) in input.lines().enumerate() {
        let line_no_nl = raw_line.trim_end_matches('\r');
        // Detect continuation: starts with whitespace AND we have a current key
        // AND the trimmed line is non-empty AND it does not start with `#`.
        let is_continuation = line_no_nl
            .chars()
            .next()
            .map(|c| c == ' ' || c == '\t')
            .unwrap_or(false);

        let trimmed = line_no_nl.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        // inline `;` comment requires whitespace before it
        let trimmed_inline = strip_inline_comment(trimmed);

        if is_continuation {
            if let Some(key) = current.as_ref() {
                if let Some(sec) = doc.sections.last_mut() {
                    sec.append(key, trimmed_inline.trim());
                }
                continue;
            }
        }

        // Section header
        if trimmed_inline.starts_with('[') {
            let end = trimmed_inline
                .find(']')
                .ok_or_else(|| Error::config(format!("line {}: missing ] in header", lineno + 1)))?;
            let name = trimmed_inline[1..end].trim().to_string();
            doc.sections.push(IniSection {
                name,
                entries: IndexMap::new(),
            });
            current = None;
            continue;
        }

        // key = value
        let (key, value) = split_key_value(trimmed_inline)
            .ok_or_else(|| Error::config(format!("line {}: expected key = value", lineno + 1)))?;
        let key = key.trim().to_string();
        let value = strip_inline_comment(value).trim().to_string();

        let sec = doc
            .sections
            .last_mut()
            .ok_or_else(|| Error::config(format!("line {}: entry before any [section]", lineno + 1)))?;
        sec.set(&key, value);
        current = Some(key);
    }

    Ok(doc)
}

/// Parse an INI file from disk.
pub fn parse_ini_file(path: &Path) -> Result<IniDocument> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::config(format!("reading {}: {e}", path.display())))?;
    parse_ini(&content)
}

/// Strip a leading-`;` inline comment, only when preceded by whitespace.
fn strip_inline_comment(s: &str) -> &str {
    // Look for ` ;` (whitespace + semicolon).
    let mut last_ws = false;
    for (i, c) in s.char_indices() {
        if c == ';' && last_ws {
            return s[..i].trim_end();
        }
        last_ws = c == ' ' || c == '\t';
    }
    s
}

/// Split `key = value` into `(key, value)`. Returns `None` if no `=` present.
fn split_key_value(s: &str) -> Option<(&str, &str)> {
    let eq = s.find('=')?;
    Some((&s[..eq], &s[eq + 1..]))
}

/// Resolve `before =` / `after =` includes recursively.
///
/// `before` files are parsed and merged *before* the current document;
/// `after` files are parsed and merged *after*. Both are resolved relative
/// to the directory of `path` and resolved against `search_dirs`.
pub fn resolve_includes(
    doc: IniDocument,
    path: &Path,
    search_dirs: &[PathBuf],
    seen: &mut HashSet<PathBuf>,
) -> Result<IniDocument> {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf());
    if seen.contains(&canonical) {
        return Err(Error::config(format!(
            "cyclic include detected at {}",
            canonical.display()
        )));
    }
    seen.insert(canonical.clone());

    let includes = collect_includes(&doc);
    let mut result = IniDocument::new();

    // before
    for b in &includes.before {
        let p = resolve_include_path(b, path.parent(), search_dirs)?;
        let d = parse_ini_file(&p)?;
        let d = resolve_includes(d, &p, search_dirs, seen)?;
        result.merge(d);
    }

    // self
    result.merge(doc);

    // after
    for a in &includes.after {
        let p = resolve_include_path(a, path.parent(), search_dirs)?;
        let d = parse_ini_file(&p)?;
        let d = resolve_includes(d, &p, search_dirs, seen)?;
        result.merge(d);
    }

    seen.remove(&canonical);
    Ok(result)
}

#[derive(Debug, Default)]
struct Includes {
    before: Vec<String>,
    after: Vec<String>,
}

fn collect_includes(doc: &IniDocument) -> Includes {
    let mut inc = Includes::default();
    for sec in doc.sections_named("INCLUDES") {
        if let Some(b) = sec.get("before") {
            for part in b.split(|c: char| c.is_whitespace() || c == ',') {
                let p = part.trim();
                if !p.is_empty() {
                    inc.before.push(p.to_string());
                }
            }
        }
        if let Some(a) = sec.get("after") {
            for part in a.split(|c: char| c.is_whitespace() || c == ',') {
                let p = part.trim();
                if !p.is_empty() {
                    inc.after.push(p.to_string());
                }
            }
        }
    }
    inc
}

fn resolve_include_path(
    name: &str,
    base: Option<&Path>,
    search_dirs: &[PathBuf],
) -> Result<PathBuf> {
    // Try relative to the parent of the current file.
    if let Some(base) = base {
        let candidate = base.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    // Then search dirs.
    for d in search_dirs {
        let candidate = d.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(Error::config(format!(
        "include not found: {name} (searched {:?})",
        search_dirs
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple() {
        let s = "[sshd]\nenabled = true\nport = ssh\nlogpath = /var/log/auth.log\n";
        let doc = parse_ini(s).unwrap();
        let sec = doc.section("sshd").unwrap();
        assert_eq!(sec.get("enabled"), Some("true"));
        assert_eq!(sec.get("port"), Some("ssh"));
        assert_eq!(sec.get("logpath"), Some("/var/log/auth.log"));
    }

    #[test]
    fn parses_multiline() {
        let s = "[d]\nfailregex = ^Failed\n            ^Invalid\n";
        let doc = parse_ini(s).unwrap();
        let sec = doc.section("d").unwrap();
        assert_eq!(sec.get("failregex"), Some("^Failed\n^Invalid"));
    }

    #[test]
    fn strips_inline_comment() {
        assert_eq!(strip_inline_comment("a = b ; c"), "a = b");
        assert_eq!(strip_inline_comment("a = b;c"), "a = b;c");
        assert_eq!(strip_inline_comment("a = b"), "a = b");
    }

    #[test]
    fn merges_docs() {
        let mut a = parse_ini("[s]\nk1 = v1\nk2 = v2\n").unwrap();
        let b = parse_ini("[s]\nk2 = override\nk3 = v3\n").unwrap();
        a.merge(b);
        let s = a.section("s").unwrap();
        assert_eq!(s.get("k1"), Some("v1"));
        assert_eq!(s.get("k2"), Some("override"));
        assert_eq!(s.get("k3"), Some("v3"));
    }

    #[test]
    fn rejects_entry_before_section() {
        let s = "key = value\n[sec]\n";
        assert!(parse_ini(s).is_err());
    }
}
