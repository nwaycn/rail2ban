//! F-* tag system: compiles fail2ban's `<HOST>`, `<F-USER>`, `<F-MLFID>` and
//! friends into regex groups with control signals.

use crate::error::{Error, Result};

/// One of fail2ban's `<F-...>` tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTag {
    /// `<HOST>` — IP/IPv6/hostname capture group.
    Host,
    /// `<ADDR>` — looser address placeholder.
    Addr,
    /// `<F-USER>...</F-USER>` — username capture group.
    FUser,
    /// `<F-ALT_USER>...</F-ALT_USER>` — alternate user capture group.
    FAltUser,
    /// `<F-NOFAIL>...</F-NOFAIL>` — match but don't count as failure.
    FNoFail,
    /// `<F-MLFID>...</F-MLFID>` — multi-line failure ID.
    FMlfid,
    /// `<F-MLFFORGET>...</F-MLFFORGET>` — reset MLFID context.
    FMlfforget,
    /// `<F-MLFGAINED>...</F-MLFGAINED>` — success event (clears failure count).
    FMlfgained,
    /// `<F-CONTENT>...</F-CONTENT>` — content for failregex (in prefregex).
    FContent,
}

impl FTag {
    /// The textual tag name without `F-` prefix.
    pub fn name(self) -> &'static str {
        match self {
            FTag::Host => "HOST",
            FTag::Addr => "ADDR",
            FTag::FUser => "F-USER",
            FTag::FAltUser => "F-ALT_USER",
            FTag::FNoFail => "F-NOFAIL",
            FTag::FMlfid => "F-MLFID",
            FTag::FMlfforget => "F-MLFFORGET",
            FTag::FMlfgained => "F-MLFGAINED",
            FTag::FContent => "F-CONTENT",
        }
    }
}

/// The result of compiling a failregex pattern: the expanded regex string
/// plus a list of tags that were referenced.
#[derive(Debug, Clone)]
pub struct CompiledTag {
    /// The expanded regex (without anchors / wrapping).
    pub pattern: String,
    /// Tags referenced in the pattern (in order of appearance).
    pub tags: Vec<FTag>,
}

/// Default `<HOST>` expansion (matches IPv4, IPv6, hostname, IPv6-mapped IPv4).
pub const HOST_REGEX: &str =
    r"(?P<host>(?:::f{4,6}:)?[\w\-.^_]*\w)";

/// Compile a failregex/prefregex pattern into a final regex string with F-*
/// tags expanded into named groups.
///
/// Supported tags (in priority order, longest first):
/// - `<F-ALT_USER>...</F-ALT_USER>` → `(?P<alt_user>...)`
/// - `<F-MLFFORGET>...</F-MLFFORGET>` → `(?P<mlfforget>...)`
/// - `<F-MLFGAINED>...</F-MLFGAINED>` → `(?P<mlfgained>...)`
/// - `<F-MLFID>...</F-MLFID>` → `(?P<mlfid>...)`
/// - `<F-CONTENT>...</F-CONTENT>` → `(?P<content>...)`
/// - `<F-NOFAIL>...</F-NOFAIL>` → `(?P<nofail>...)`
/// - `<F-USER>...</F-USER>` → `(?P<user>...)`
/// - `<HOST>` → `(?:::f{4,6}:)?(?P<host>[\w\-.^_]*\w)`
/// - `<ADDR>` → `(?P<addr>[\w\-.^_]*)`
pub fn compile_tags(input: &str) -> Result<CompiledTag> {
    let mut out = String::with_capacity(input.len() + 64);
    let mut tags = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some((tag, inner, end)) = match_tag(&input[i..])? {
                out.push_str(&expand_tag(tag, &inner)?);
                tags.push(tag);
                i += end;
                continue;
            }
        }
        // Copy one UTF-8 character.
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&input[i..i + ch_len]);
        i += ch_len;
    }
    Ok(CompiledTag { pattern: out, tags })
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

/// Try to match a tag at the start of `s`. Returns `(tag, inner, consumed_len)`
/// where `consumed_len` is the number of bytes consumed from `s`.
fn match_tag(s: &str) -> Result<Option<(FTag, String, usize)>> {
    // Pair tags with closing `</F-NAME>`.
    if let Some(rest) = s.strip_prefix('<') {
        // Find the matching closing `>` for the opening tag.
        let open_end = rest
            .find('>')
            .ok_or_else(|| Error::regex("unterminated tag"))?;
        let tag_name = &rest[..open_end];
        // Identify which F-* tag this is.
        let tag = match tag_name {
            "F-ALT_USER" => FTag::FAltUser,
            "F-MLFFORGET" => FTag::FMlfforget,
            "F-MLFGAINED" => FTag::FMlfgained,
            "F-MLFID" => FTag::FMlfid,
            "F-CONTENT" => FTag::FContent,
            "F-NOFAIL" => FTag::FNoFail,
            "F-USER" => FTag::FUser,
            "HOST" => FTag::Host,
            "ADDR" => FTag::Addr,
            _ => return Ok(None),
        };
        let open_len = 1 + open_end + 1; // `<NAME>`
        if tag == FTag::Host || tag == FTag::Addr {
            // Single tag, no closing.
            return Ok(Some((tag, String::new(), open_len)));
        }
        // Find closing `</F-NAME>`.
        let close = format!("</{tag_name}>");
        let after_open = &s[open_len..];
        let close_pos = after_open
            .find(&close)
            .ok_or_else(|| Error::regex(format!("missing closing </{tag_name}>")))?;
        let inner = after_open[..close_pos].to_string();
        let total = open_len + close_pos + close.len();
        return Ok(Some((tag, inner, total)));
    }
    Ok(None)
}

fn expand_tag(tag: FTag, inner: &str) -> Result<String> {
    Ok(match tag {
        FTag::Host => HOST_REGEX.to_string(),
        FTag::Addr => r"(?P<addr>[\w\-.^_]*)".to_string(),
        // For pair tags, recursively expand any nested F-* tags inside.
        FTag::FUser => format!(r"(?P<user>{})", compile_tags(inner)?.pattern),
        FTag::FAltUser => format!(r"(?P<alt_user>{})", compile_tags(inner)?.pattern),
        FTag::FNoFail => format!(r"(?P<nofail>{})", compile_tags(inner)?.pattern),
        FTag::FMlfid => format!(r"(?P<mlfid>{})", compile_tags(inner)?.pattern),
        FTag::FMlfforget => format!(r"(?P<mlfforget>{})", compile_tags(inner)?.pattern),
        FTag::FMlfgained => format!(r"(?P<mlfgained>{})", compile_tags(inner)?.pattern),
        FTag::FContent => format!(r"(?P<content>{})", compile_tags(inner)?.pattern),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn expands_host() {
        let c = compile_tags("Failed password from <HOST>").unwrap();
        assert!(c.pattern.contains("(?P<host>"));
        assert!(c.tags.contains(&FTag::Host));
    }

    #[test]
    fn expands_fuser() {
        let c = compile_tags(r"user <F-USER>\w+</F-USER>").unwrap();
        assert!(c.pattern.contains("(?P<user>\\w+)"));
        assert!(c.tags.contains(&FTag::FUser));
    }

    #[test]
    fn expands_nested_tags() {
        let c = compile_tags("<F-NOFAIL><F-MLFFORGET>Disconnected</F-MLFFORGET></F-NOFAIL>").unwrap();
        assert!(c.pattern.contains("(?P<nofail>"));
        assert!(c.pattern.contains("(?P<mlfforget>"));
    }

    #[test]
    fn compiles_to_valid_regex() {
        let c = compile_tags(r"^Failed \S+ for invalid user \S+ from <HOST> port \d+").unwrap();
        Regex::new(&c.pattern).unwrap();
    }

    #[test]
    fn matches_real_line() {
        let c = compile_tags(r"^Failed password for invalid user admin from <HOST> port 12345").unwrap();
        let r = Regex::new(&c.pattern).unwrap();
        let caps = r
            .captures("Failed password for invalid user admin from 192.0.2.10 port 12345")
            .unwrap();
        assert_eq!(caps.name("host").unwrap().as_str(), "192.0.2.10");
    }

    #[test]
    fn handles_ipv6_mapped_ipv4() {
        let c = compile_tags(r"from <HOST>").unwrap();
        let r = Regex::new(&c.pattern).unwrap();
        let caps = r.captures("from ::ffff:192.0.2.10").unwrap();
        assert_eq!(caps.name("host").unwrap().as_str(), "::ffff:192.0.2.10");
    }
}
