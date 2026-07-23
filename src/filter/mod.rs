//! Filter compilation & matching.
//!
//! Implements the fail2ban filter pipeline:
//!
//! 1. Parse the date (`datepattern` or auto-detect).
//! 2. Strip the date prefix from the line.
//! 3. Apply `prefregex` (if present) to extract `mlfid` and `content`.
//! 4. Apply `failregex` against the (content portion of the) line.
//! 5. Apply `ignoreregex` to filter out matches.
//! 6. Extract `<HOST>` IP/failure-ID, `<F-USER>`, `<F-ALT_USER>`.

pub mod tags;
pub mod datepattern;

use crate::config::FilterConfig;
use crate::error::{Error, Result};
use chrono::{DateTime, Local, Utc};
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;
use tags::{CompiledTag, FTag, compile_tags};

/// A successfully compiled filter, ready to match log lines.
#[derive(Debug)]
pub struct CompiledFilter {
    /// Source config.
    pub config: FilterConfig,
    /// Compiled `prefregex` (optional).
    pub prefregex: Option<Regex>,
    /// Compiled `failregex` patterns (with F-* tags expanded).
    pub failregex: Vec<Regex>,
    /// Compiled `ignoreregex` patterns.
    pub ignoreregex: Vec<Regex>,
    /// Compiled `datepattern` (optional explicit).
    pub datepattern: Option<DateMatcher>,
    /// `maxlines` for multi-line buffering.
    pub maxlines: u32,
}

/// A compiled date matcher.
#[derive(Debug)]
pub struct DateMatcher {
    /// The underlying regex.
    pub regex: Regex,
    /// A function pointer-like enum describing how to convert the captured
    /// date string into a `DateTime<Utc>`.
    pub kind: DateKind,
}

/// Date conversion strategy.
#[derive(Debug, Clone, Copy)]
pub enum DateKind {
    /// `chrono::DateTime::parse_from_str` with the given format (boxed elsewhere).
    Strftime,
    /// Epoch seconds.
    EpochSecs,
    /// Epoch milliseconds.
    EpochMillis,
    /// Epoch microseconds.
    EpochMicros,
    /// ISO8601 / RFC3339 (default chrono parser).
    Iso8601,
    /// Syslog `Mon DD HH:MM:SS` (assume current year).
    Syslog,
    /// Tai64n (rarely used).
    Tai64n,
}

/// The result of matching a single log line.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The extracted failure ID (IP address as string, or raw failure ID).
    pub host: String,
    /// Parsed IP address, if applicable.
    pub ip: Option<IpAddr>,
    /// Captured user (from `<F-USER>`).
    pub user: Option<String>,
    /// Captured alt user (from `<F-ALT_USER>`).
    pub alt_user: Option<String>,
    /// Multi-line failure ID (from `<F-MLFID>`).
    pub mlfid: Option<String>,
    /// Parsed timestamp.
    pub timestamp: Option<DateTime<Utc>>,
    /// Whether this match should be counted as a failure (false when
    /// `<F-NOFAIL>` was used).
    pub nofail: bool,
    /// Control signal: forget the MLFID context.
    pub mlfforget: bool,
    /// Control signal: success event (resets failure count for this MLFID).
    pub mlfgained: bool,
    /// The matched log line (for ticket storage).
    pub line: String,
    /// Which failregex index matched.
    pub regex_index: usize,
}

/// Multi-line buffer: holds up to `maxlines` recent log lines so that
/// failregexes spanning multiple lines can match.
#[derive(Debug)]
pub struct LineBuffer {
    /// Maximum number of lines to keep (>= 1).
    pub maxlines: u32,
    lines: Vec<String>,
}

impl LineBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(maxlines: u32) -> Self {
        Self {
            maxlines: maxlines.max(1),
            lines: Vec::new(),
        }
    }

    /// Append a line, evicting the oldest when over capacity.
    pub fn push(&mut self, line: String) {
        self.lines.push(line);
        let cap = self.maxlines as usize;
        while self.lines.len() > cap {
            self.lines.remove(0);
        }
    }

    /// Join the buffered lines with `\n` for regex matching.
    pub fn joined(&self) -> String {
        self.lines.join("\n")
    }

    /// Clear the buffer (after a successful match).
    pub fn clear(&mut self) {
        self.lines.clear();
    }

    /// Number of lines currently buffered.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

impl CompiledFilter {
    /// Compile a [`FilterConfig`] into a [`CompiledFilter`].
    pub fn compile(cfg: FilterConfig) -> Result<Self> {
        let maxlines = cfg.maxlines.max(1);
        let prefregex = match &cfg.prefregex {
            Some(s) if !s.is_empty() => Some(compile_pattern(s)?),
            None => None,
            _ => None,
        };
        let mut failregex = Vec::with_capacity(cfg.failregex.len());
        for pat in &cfg.failregex {
            if pat.is_empty() {
                continue;
            }
            failregex.push(compile_pattern(pat)?);
        }
        let mut ignoreregex = Vec::with_capacity(cfg.ignoreregex.len());
        for pat in &cfg.ignoreregex {
            if pat.is_empty() {
                continue;
            }
            ignoreregex.push(compile_pattern(pat)?);
        }
        let datepattern = match &cfg.datepattern {
            Some(s) if !s.is_empty() => Some(datepattern::compile(s)?),
            _ => None,
        };
        Ok(Self {
            config: cfg,
            prefregex,
            failregex,
            ignoreregex,
            datepattern,
            maxlines,
        })
    }

    /// Process a single log line.
    ///
    /// Returns `Ok(Some(result))` on a match, `Ok(None)` if no match.
    pub fn process_line(&self, line: &str) -> Result<Option<MatchResult>> {
        // 1. Parse & strip date.
        let (rest, timestamp) = match self.extract_date(line) {
            Some((rest, ts)) => (rest, Some(ts)),
            None => (line.to_string(), None),
        };

        // 2. Apply ignoreregex first — if any matches, drop the line entirely.
        for r in &self.ignoreregex {
            if r.is_match(&rest) {
                return Ok(None);
            }
        }

        // 3. Apply prefregex if present.
        let (content, mlfid_pref) = match &self.prefregex {
            Some(pre) => match pre.captures(&rest) {
                Some(caps) => {
                    let content = caps
                        .name("content")
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| rest.clone());
                    let mlfid = caps.name("mlfid").map(|m| m.as_str().to_string());
                    (content, mlfid)
                }
                None => return Ok(None),
            },
            None => (rest.clone(), None),
        };

        // 4. Apply each failregex.
        for (i, r) in self.failregex.iter().enumerate() {
            if let Some(caps) = r.captures(&content) {
                let host = caps
                    .name("host")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let ip = parse_ip(&host);
                let user = caps.name("user").map(|m| m.as_str().to_string());
                let alt_user = caps.name("alt_user").map(|m| m.as_str().to_string());
                let mlfid = caps
                    .name("mlfid")
                    .map(|m| m.as_str().to_string())
                    .or(mlfid_pref.clone());
                let nofail = caps.name("nofail").is_some();
                let mlfforget = caps.name("mlfforget").is_some();
                let mlfgained = caps.name("mlfgained").is_some();

                return Ok(Some(MatchResult {
                    host,
                    ip,
                    user,
                    alt_user,
                    mlfid,
                    timestamp,
                    nofail,
                    mlfforget,
                    mlfgained,
                    line: line.to_string(),
                    regex_index: i,
                }));
            }
        }
        Ok(None)
    }

    /// Process a line using a multi-line buffer.
    ///
    /// When `maxlines > 1`, lines are accumulated in `buf`; the joined buffer
    /// is matched against the failregexes (which may span lines via `\n`).
    /// On a match, the buffer is cleared and the result's `line` field holds
    /// the joined buffer. On no match, the buffer is retained for the next
    /// call (old lines are evicted beyond `maxlines`).
    pub fn process_buffered(
        &self,
        buf: &mut LineBuffer,
        line: &str,
    ) -> Result<Option<MatchResult>> {
        buf.push(line.to_string());
        let joined = buf.joined();
        let result = self.process_line(&joined)?;
        if result.is_some() {
            buf.clear();
        }
        Ok(result)
    }

    fn extract_date(&self, line: &str) -> Option<(String, DateTime<Utc>)> {
        if let Some(m) = &self.datepattern {
            if let Some(caps) = m.regex.captures(line) {
                if let Some(m1) = caps.get(1) {
                    let raw = m1.as_str();
                    if let Some(ts) = datepattern::convert(raw, m.kind) {
                        let stripped = line.replace(raw, "");
                        return Some((stripped.trim_start().to_string(), ts));
                    }
                }
            }
        }
        // Auto-detect.
        if let Some((raw, ts, kind)) = datepattern::auto_detect(line) {
            let _ = kind;
            let stripped = line.replace(raw.as_str(), "");
            return Some((stripped.trim_start().to_string(), ts));
        }
        None
    }
}

/// Compile a failregex/prefregex pattern, expanding F-* tags.
pub fn compile_pattern(input: &str) -> Result<Regex> {
    let compiled = compile_tags(input)?;
    let mut final_pat = String::with_capacity(compiled.pattern.len() + 8);
    final_pat.push_str(&compiled.pattern);
    Regex::new(&final_pat).map_err(|e| Error::regex(format!("compiling {input:?}: {e}")))
}

/// Get the list of F-* tags referenced in the pattern (useful for diagnostics).
pub fn referenced_tags(input: &str) -> Vec<FTag> {
    compile_tags(input)
        .map(|c| c.tags.to_vec())
        .unwrap_or_default()
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Strip IPv6-mapped IPv4 prefix `::ffff:1.2.3.4` → `1.2.3.4`.
    let s = s
        .strip_prefix("::ffff:")
        .or_else(|| s.strip_prefix("::f{4,6}:"))
        .unwrap_or(s);
    IpAddr::from_str(s).ok()
}

#[allow(dead_code)]
fn now_local() -> DateTime<Local> {
    Local::now()
}

#[allow(dead_code)]
fn unused_compiled_tag() -> CompiledTag {
    CompiledTag {
        pattern: String::new(),
        tags: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_buffer_evicts_oldest() {
        let mut b = LineBuffer::new(2);
        b.push("a".into());
        b.push("b".into());
        b.push("c".into());
        assert_eq!(b.joined(), "b\nc");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn line_buffer_clear() {
        let mut b = LineBuffer::new(3);
        b.push("a".into());
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn process_buffered_multiline_match() {
        let cfg = FilterConfig {
            name: "test".into(),
            prefregex: None,
            failregex: vec!["connection from <HOST> failed\n.*again".into()],
            ignoreregex: vec![],
            datepattern: None,
            maxlines: 2,
            logtype: "file".into(),
            journalmatch: vec![],
            init: indexmap::IndexMap::new(),
        };
        let f = CompiledFilter::compile(cfg).unwrap();
        let mut buf = LineBuffer::new(2);
        // First line alone doesn't match (regex requires a second line).
        assert!(f.process_buffered(&mut buf, "connection from 1.2.3.4 failed").unwrap().is_none());
        // Now the buffer holds 2 lines and the regex matches.
        let r = f
            .process_buffered(&mut buf, "again")
            .unwrap()
            .expect("should match");
        assert_eq!(r.host, "1.2.3.4");
        assert!(buf.is_empty(), "buffer cleared after match");
    }
}
