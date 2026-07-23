//! Variable interpolation engine.
//!
//! Implements fail2ban's extended interpolation:
//! - `%(name)s` — same-section value
//! - `%(default/parameter)s` — explicit `[DEFAULT]` lookup
//! - `%(section/parameter)s` — cross-section lookup
//! - `%(known/parameter)s` — last known value of `parameter`
//! - `<known/parameter>` — init parameter extension tag
//! - `<lt_<logtype>/...>` and `<ipt_<type>/...>` — dynamic section selection
//! - Variable name interpolation: `<cmnfailre-failed-pub-<publickey>>`
//! - `%%` → literal `%`

use crate::config::IniDocument;
use crate::error::{Error, Result};
use indexmap::IndexMap;
use std::collections::HashSet;

/// Maximum interpolation recursion depth (prevents infinite loops).
pub const MAX_DEPTH: usize = 10;

/// Interpolation context: a fully-parsed configuration document plus a
/// "current section" pointer and a set of init parameters (for `<known/...>`).
#[derive(Debug, Clone)]
pub struct InterpolationContext<'a> {
    /// The full INI document.
    pub doc: &'a IniDocument,
    /// Variables defined in `[DEFAULT]`.
    pub defaults: &'a IndexMap<String, String>,
    /// Built-in variables (`fail2ban_version`, `fq-hostname`, ...).
    pub builtins: &'a IndexMap<String, String>,
    /// The current section name being interpolated (e.g. `sshd`, `Definition`).
    pub current_section: Option<String>,
    /// Init parameters (for `<known/...>` lookups in actions/filters).
    pub init: &'a IndexMap<String, String>,
    /// Last known values for `%(known/parameter)s`.
    pub known: &'a IndexMap<String, String>,
}

/// Interpolate a string using the given context.
pub fn interpolate(input: &str, ctx: &InterpolationContext<'_>) -> Result<String> {
    let mut visited = HashSet::new();
    interpolate_inner(input, ctx, 0, &mut visited)
}

fn interpolate_inner(
    input: &str,
    ctx: &InterpolationContext<'_>,
    depth: usize,
    visited: &mut HashSet<String>,
) -> Result<String> {
    if depth > MAX_DEPTH {
        return Err(Error::config(format!(
            "interpolation recursion limit exceeded ({MAX_DEPTH})"
        )));
    }

    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' if chars.peek() == Some(&'%') => {
                chars.next();
                out.push('%');
            }
            '%' => {
                // Expect `%(name)s`
                if chars.next() != Some('(') {
                    return Err(Error::config(
                        "expected '(' after '%' in interpolation",
                    ));
                }
                let name = read_until(&mut chars, ')')
                    .ok_or_else(|| Error::config("unterminated %(name)"))?;
                // The closing `)s` — fail2ban expects `s` (Python string interp).
                // We tolerate missing `s` but consume it when present.
                if chars.peek() == Some(&'s') {
                    chars.next();
                }
                let key = name.trim();
                let value = lookup_percent(key, ctx)?;
                let resolved = interpolate_inner(&value, ctx, depth + 1, visited)?;
                out.push_str(&resolved);
            }
            '<' => {
                let save = out.len();
                // Try to read a `<...>` tag.
                let mut tag = String::new();
                let mut nested = 0;
                let mut found = false;
                while let Some(&t) = chars.peek() {
                    if t == '<' {
                        nested += 1;
                        tag.push(t);
                        chars.next();
                    } else if t == '>' {
                        if nested == 0 {
                            chars.next();
                            found = true;
                            break;
                        } else {
                            nested -= 1;
                            tag.push(t);
                            chars.next();
                        }
                    } else {
                        tag.push(t);
                        chars.next();
                    }
                }
                if !found {
                    // Not a tag, restore `<` and continue literally.
                    out.push('<');
                    out.push_str(&tag);
                    continue;
                }
                // Check whether this tag is a known interpolation tag.
                match lookup_tag(&tag, ctx, depth, visited) {
                    Ok(Some(value)) => {
                        let resolved = interpolate_inner(&value, ctx, depth + 1, visited)?;
                        out.push_str(&resolved);
                    }
                    Ok(None) => {
                        // Not an interpolation tag — restore as literal.
                        out.truncate(save);
                        out.push('<');
                        out.push_str(&tag);
                        out.push('>');
                    }
                    Err(e) => return Err(e),
                }
            }
            _ => out.push(c),
        }
    }
    Ok(out)
}

fn read_until<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
    end: char,
) -> Option<String> {
    let mut s = String::new();
    while let Some(&c) = chars.peek() {
        if c == end {
            chars.next();
            return Some(s);
        }
        s.push(c);
        chars.next();
    }
    None
}

/// Resolve a `%(name)s` lookup. Returns the raw value (caller will recursively
/// interpolate it).
fn lookup_percent(key: &str, ctx: &InterpolationContext<'_>) -> Result<String> {
    if let Some(rest) = key.strip_prefix("default/") {
        return ctx
            .defaults
            .get(rest)
            .or_else(|| ctx.builtins.get(rest))
            .cloned()
            .ok_or_else(|| Error::config(format!("unknown default variable {rest:?}")));
    }
    if let Some(rest) = key.strip_prefix("known/") {
        return ctx
            .known
            .get(rest)
            .cloned()
            .or_else(|| ctx.init.get(rest).cloned())
            .ok_or_else(|| Error::config(format!("unknown known variable {rest:?}")));
    }
    if let Some((section, parameter)) = key.split_once('/') {
        if let Some(sec) = ctx.doc.section(section) {
            if let Some(v) = sec.get(parameter) {
                return Ok(v.to_string());
            }
        }
        return Err(Error::config(format!(
            "unknown cross-section variable {key:?}"
        )));
    }
    // Same-section lookup.
    if let Some(sec_name) = &ctx.current_section {
        if let Some(sec) = ctx.doc.section(sec_name) {
            if let Some(v) = sec.get(key) {
                return Ok(v.to_string());
            }
        }
    }
    if let Some(v) = ctx.defaults.get(key) {
        return Ok(v.clone());
    }
    if let Some(v) = ctx.builtins.get(key) {
        return Ok(v.clone());
    }
    Err(Error::config(format!("unknown variable %({key})s")))
}

/// Resolve a `<...>` interpolation tag. Returns:
/// - `Ok(Some(value))` — recognized interpolation tag with a value
/// - `Ok(None)` — not an interpolation tag (caller should emit literally)
/// - `Err(_)` — recognized but unresolvable
fn lookup_tag(
    tag: &str,
    ctx: &InterpolationContext<'_>,
    depth: usize,
    visited: &mut HashSet<String>,
) -> Result<Option<String>> {
    // First, recursively interpolate any nested `<...>` tags within this tag
    // content (e.g. `<lt_<logtype>/__prefix_line>` → `<lt_journal/__prefix_line>`).
    let tag = if tag.contains('<') {
        interpolate_inner(tag, ctx, depth + 1, visited)?
    } else {
        tag.to_string()
    };
    let tag = tag.as_str();

    // <known/parameter>
    if let Some(rest) = tag.strip_prefix("known/") {
        if let Some(v) = ctx.init.get(rest) {
            return Ok(Some(v.clone()));
        }
        if let Some(v) = ctx.known.get(rest) {
            return Ok(Some(v.clone()));
        }
        return Err(Error::config(format!(
            "unknown <known/{rest}> init parameter"
        )));
    }
    // <lt_<logtype>/...> dynamic section selection
    if let Some(rest) = tag.strip_prefix("lt_") {
        // rest = "<logtype>/__prefix_line" where <logtype> is a variable name
        // (already interpolated above if it contained `<...>`).
        let (var_name, param) = rest
            .split_once('/')
            .ok_or_else(|| Error::config(format!("malformed <lt_...> tag: {tag}")))?;
        // The var_name may already be a resolved value (e.g. "journal") or a
        // plain variable name to look up in init/defaults.
        let logtype = ctx
            .init
            .get(var_name)
            .or_else(|| ctx.defaults.get(var_name))
            .map(|s| s.as_str())
            .unwrap_or(var_name);
        let section = format!("lt_{logtype}");
        if let Some(sec) = ctx.doc.section(&section) {
            if let Some(v) = sec.get(param) {
                return Ok(Some(v.to_string()));
            }
        }
        return Ok(Some(String::new()));
    }
    // <ipt_<type>/...> dynamic section selection
    if let Some(rest) = tag.strip_prefix("ipt_") {
        let (var_name, param) = rest
            .split_once('/')
            .ok_or_else(|| Error::config(format!("malformed <ipt_...> tag: {tag}")))?;
        let ty = ctx
            .init
            .get(var_name)
            .or_else(|| ctx.defaults.get(var_name))
            .map(|s| s.as_str())
            .unwrap_or(var_name);
        let section = format!("ipt_{ty}");
        if let Some(sec) = ctx.doc.section(&section) {
            if let Some(v) = sec.get(param) {
                return Ok(Some(v.to_string()));
            }
        }
        return Ok(Some(String::new()));
    }
    // Plain variable name: <varname> resolves from init, defaults, or builtins.
    if let Some(v) = ctx.init.get(tag) {
        return Ok(Some(v.clone()));
    }
    if let Some(v) = ctx.defaults.get(tag) {
        return Ok(Some(v.clone()));
    }
    if let Some(v) = ctx.builtins.get(tag) {
        return Ok(Some(v.clone()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IniSection;
    use indexmap::IndexMap;

    fn make_ctx<'a>(
        doc: &'a IniDocument,
        defaults: &'a IndexMap<String, String>,
        builtins: &'a IndexMap<String, String>,
        current_section: Option<&'a str>,
        init: &'a IndexMap<String, String>,
        known: &'a IndexMap<String, String>,
    ) -> InterpolationContext<'a> {
        InterpolationContext {
            doc,
            defaults,
            builtins,
            current_section: current_section.map(|s| s.to_string()),
            init,
            known,
        }
    }

    #[test]
    fn interpolates_simple() {
        let mut doc = IniDocument::new();
        let mut sec = IniSection::default();
        sec.name = "s".into();
        sec.set("name", "world");
        sec.set("greeting", "hello %(name)s");
        doc.sections.push(sec);

        let defaults = IndexMap::new();
        let builtins = IndexMap::new();
        let init = IndexMap::new();
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, Some("s"), &init, &known);

        let r = interpolate("greeting=%(name)s", &ctx).unwrap();
        assert_eq!(r, "greeting=world");
    }

    #[test]
    fn interpolates_default() {
        let doc = IniDocument::new();
        let mut defaults = IndexMap::new();
        defaults.insert("port".into(), "ssh".into());
        let builtins = IndexMap::new();
        let init = IndexMap::new();
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, None, &init, &known);

        let r = interpolate("port=%(default/port)s", &ctx).unwrap();
        assert_eq!(r, "port=ssh");
    }

    #[test]
    fn interpolates_cross_section() {
        let mut doc = IniDocument::new();
        let mut sec_a = IniSection::default();
        sec_a.name = "a".into();
        sec_a.set("v", "from-a");
        doc.sections.push(sec_a);
        let mut sec_b = IniSection::default();
        sec_b.name = "b".into();
        sec_b.set("ref", "%(a/v)s");
        doc.sections.push(sec_b);

        let defaults = IndexMap::new();
        let builtins = IndexMap::new();
        let init = IndexMap::new();
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, Some("b"), &init, &known);

        let r = interpolate("%(a/v)s", &ctx).unwrap();
        assert_eq!(r, "from-a");
    }

    #[test]
    fn interpolates_known_tag() {
        let doc = IniDocument::new();
        let defaults = IndexMap::new();
        let builtins = IndexMap::new();
        let mut init = IndexMap::new();
        init.insert("agent".into(), "IE|wget".into());
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, None, &init, &known);

        let r = interpolate("agents=<known/agent>", &ctx).unwrap();
        assert_eq!(r, "agents=IE|wget");
    }

    #[test]
    fn interpolates_dynamic_logtype() {
        let mut doc = IniDocument::new();
        let mut lt_file = IniSection::default();
        lt_file.name = "lt_file".into();
        lt_file.set("__prefix_line", "FILE_PREFIX");
        doc.sections.push(lt_file);
        let mut lt_journal = IniSection::default();
        lt_journal.name = "lt_journal".into();
        lt_journal.set("__prefix_line", "JOURNAL_PREFIX");
        doc.sections.push(lt_journal);

        let defaults = IndexMap::new();
        let builtins = IndexMap::new();
        let mut init = IndexMap::new();
        init.insert("logtype".into(), "journal".into());
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, None, &init, &known);

        let r = interpolate("<lt_<logtype>/__prefix_line>", &ctx).unwrap();
        assert_eq!(r, "JOURNAL_PREFIX");
    }

    #[test]
    fn escapes_percent() {
        let doc = IniDocument::new();
        let defaults = IndexMap::new();
        let builtins = IndexMap::new();
        let init = IndexMap::new();
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, None, &init, &known);

        let r = interpolate("100%% done", &ctx).unwrap();
        assert_eq!(r, "100% done");
    }

    #[test]
    fn detects_recursion() {
        let mut doc = IniDocument::new();
        let mut sec = IniSection::default();
        sec.name = "s".into();
        sec.set("a", "%(b)s");
        sec.set("b", "%(a)s");
        doc.sections.push(sec);

        let defaults = IndexMap::new();
        let builtins = IndexMap::new();
        let init = IndexMap::new();
        let known = IndexMap::new();
        let ctx = make_ctx(&doc, &defaults, &builtins, Some("s"), &init, &known);

        assert!(interpolate("%(a)s", &ctx).is_err());
    }
}
