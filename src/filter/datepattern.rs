//! Date pattern compilation and auto-detection.
//!
//! fail2ban supports both explicit `datepattern` values (strftime-like or
//! named) and automatic detection of common formats. This module implements
//! a pragmatic subset covering the most common patterns.

use crate::error::{Error, Result};
use crate::filter::DateKind;
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use std::str::FromStr;

/// Compile an explicit `datepattern` value.
///
/// Accepted syntax:
/// - `%%Y-%%m-%%d %%H:%%M:%%S` (strftime-like, doubled percent)
/// - `%Y-%m-%d %H:%M:%S` (strftime-like)
/// - `Epoch` / `EpochMilli` / `EpochMicro`
/// - `ISO8601`
/// - `Tai64n`
/// - A regex prefixed with `%%`... actually fail2ban uses `{^LN-BEG}` and
///   `{UNB}` anchors; we accept a raw regex when it does not match any of the
///   named patterns above.
pub fn compile(pattern: &str) -> Result<super::DateMatcher> {
    // Strip anchors.
    let pat = pattern
        .trim_start_matches("{^LN-BEG}")
        .trim_start_matches("{UNB}")
        .trim();

    // Named patterns.
    if pat.eq_ignore_ascii_case("epoch") {
        return Ok(super::DateMatcher {
            regex: Regex::new(r"(\d{10})").unwrap(),
            kind: DateKind::EpochSecs,
        });
    }
    if pat.eq_ignore_ascii_case("epochmilli") || pat.eq_ignore_ascii_case("epoch_milli") {
        return Ok(super::DateMatcher {
            regex: Regex::new(r"(\d{13})").unwrap(),
            kind: DateKind::EpochMillis,
        });
    }
    if pat.eq_ignore_ascii_case("epochmicro") || pat.eq_ignore_ascii_case("epoch_micro") {
        return Ok(super::DateMatcher {
            regex: Regex::new(r"(\d{16})").unwrap(),
            kind: DateKind::EpochMicros,
        });
    }
    if pat.eq_ignore_ascii_case("iso8601") || pat.eq_ignore_ascii_case("rfc3339") {
        return Ok(super::DateMatcher {
            regex: Regex::new(
                r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
            )
            .unwrap(),
            kind: DateKind::Iso8601,
        });
    }
    if pat.eq_ignore_ascii_case("tai64n") {
        return Ok(super::DateMatcher {
            regex: Regex::new(r"(@40000000[0-9a-f]{8})").unwrap(),
            kind: DateKind::Tai64n,
        });
    }

    // strftime-like: build a regex from the format string.
    if pat.contains('%') {
        return compile_strftime(pat);
    }

    // Otherwise treat as a raw regex with one capture group.
    let regex = Regex::new(pat)
        .map_err(|e| Error::regex(format!("invalid datepattern {pat:?}: {e}")))?;
    Ok(super::DateMatcher {
        regex,
        kind: DateKind::Iso8601,
    })
}

/// Compile a strftime-like pattern into a [`super::DateMatcher`].
fn compile_strftime(fmt: &str) -> Result<super::DateMatcher> {
    let mut regex_str = String::new();
    let mut strftime_str = String::new();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            // Skip an optional second `%` (fail2ban uses `%%` for literal).
            let spec = chars.next().unwrap_or('%');
            let (r, s) = strftime_token(spec);
            regex_str.push_str(r);
            strftime_str.push('%');
            strftime_str.push(s);
        } else if c == ' ' {
            regex_str.push_str(r"\s+");
            strftime_str.push(' ');
        } else if regex_syntax::is_meta_character(c) {
            regex_str.push('\\');
            regex_str.push(c);
            strftime_str.push(c);
        } else {
            regex_str.push(c);
            strftime_str.push(c);
        }
    }
    let regex = Regex::new(&format!("({regex_str})"))
        .map_err(|e| Error::regex(format!("compiled datepattern regex: {e}")))?;
    let _ = strftime_str; // kept for future diagnostics
    Ok(super::DateMatcher {
        regex,
        kind: DateKind::Strftime,
    })
}

/// Convert a strftime spec char to a `(regex_fragment, strftime_char)` pair.
fn strftime_token(spec: char) -> (&'static str, char) {
    match spec {
        'Y' => (r"\d{4}", 'Y'),
        'm' => (r"\d{2}", 'm'),
        'd' => (r"\d{2}", 'd'),
        'H' => (r"\d{2}", 'H'),
        'M' => (r"\d{2}", 'M'),
        'S' => (r"\d{2}", 'S'),
        'y' => (r"\d{2}", 'y'),
        'j' => (r"\d{3}", 'j'),
        'b' | 'B' | 'h' => (r"[A-Za-z]{3,9}", spec),
        'a' | 'A' => (r"[A-Za-z]{3,9}", spec),
        'p' => (r"(?:AM|PM)", 'p'),
        'z' => (r"[+-]\d{4}", 'z'),
        'Z' => (r"[A-Za-z/]+", 'Z'),
        '%' => (r"%", '%'),
        _ => (r"\S+", spec),
    }
}

mod regex_syntax {
    pub fn is_meta_character(c: char) -> bool {
        matches!(c, '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$')
    }
}

/// Auto-detect a date in a line.
///
/// Returns `(matched_substring, parsed_timestamp, kind)` if found.
pub fn auto_detect(line: &str) -> Option<(String, DateTime<Utc>, DateKind)> {
    for matcher in AUTO_DETECT_MATCHERS.iter() {
        if let Some(caps) = matcher.regex.captures(line) {
            if let Some(m) = caps.get(1) {
                let raw = m.as_str();
                if let Some(ts) = convert(raw, matcher.kind) {
                    return Some((raw.to_string(), ts, matcher.kind));
                }
            }
        }
    }
    None
}

/// Convert a captured date string into a [`DateTime<Utc>`] using the given
/// [`DateKind`].
pub fn convert(raw: &str, kind: DateKind) -> Option<DateTime<Utc>> {
    match kind {
        DateKind::Iso8601 => {
            // Try chrono's built-in RFC3339 parser first.
            if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
                return Some(dt.with_timezone(&Utc));
            }
            // Allow space separator and missing timezone.
            let normalized = raw.replace(' ', "T");
            if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
                return Some(dt.with_timezone(&Utc));
            }
            // Try without timezone (assume UTC).
            if let Ok(ndt) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S") {
                return Some(Utc.from_utc_datetime(&ndt));
            }
            if let Ok(ndt) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
                return Some(Utc.from_utc_datetime(&ndt));
            }
            None
        }
        DateKind::EpochSecs => raw.parse::<i64>().ok().and_then(|s| {
            DateTime::<Utc>::from_timestamp(s, 0)
        }),
        DateKind::EpochMillis => raw.parse::<i64>().ok().and_then(|ms| {
            DateTime::<Utc>::from_timestamp_millis(ms)
        }),
        DateKind::EpochMicros => {
            let us: i64 = raw.parse().ok()?;
            let secs = us / 1_000_000;
            let nanos = ((us % 1_000_000) * 1_000) as u32;
            DateTime::<Utc>::from_timestamp(secs, nanos)
        }
        DateKind::Strftime => parse_strftime_fallback(raw),
        DateKind::Syslog => parse_syslog(raw),
        DateKind::Tai64n => parse_tai64n(raw),
    }
}

fn parse_strftime_fallback(raw: &str) -> Option<DateTime<Utc>> {
    // Try several common formats.
    for fmt in &[
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
        if let Ok(dt) = DateTime::parse_from_str(raw, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    None
}

fn parse_syslog(raw: &str) -> Option<DateTime<Utc>> {
    // `Mon DD HH:MM:SS` — assume current year, UTC.
    let mut parts = raw.split_whitespace();
    let month = parts.next()?;
    let day = parts.next()?;
    let time = parts.next()?;
    let month_num = match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day_num: u32 = day.parse().ok()?;
    let year = Utc::now().naive_utc().year();
    let ndt = NaiveDate::from_ymd_opt(year, month_num, day_num)?
        .and_time(NaiveTime::parse_from_str(time, "%H:%M:%S").ok()?);
    Some(Utc.from_utc_datetime(&ndt))
}

fn parse_tai64n(_raw: &str) -> Option<DateTime<Utc>> {
    // Rarely used; leave unimplemented.
    None
}

/// Static list of auto-detect matchers.
static AUTO_DETECT_MATCHERS: Lazy<Vec<AutoMatcher>> = Lazy::new(|| {
    vec![
        AutoMatcher {
            regex: Regex::new(
                r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
            )
            .unwrap(),
            kind: DateKind::Iso8601,
        },
        AutoMatcher {
            regex: Regex::new(r"(\d{10})").unwrap(),
            kind: DateKind::EpochSecs,
        },
        AutoMatcher {
            regex: Regex::new(r"(\d{13})").unwrap(),
            kind: DateKind::EpochMillis,
        },
        AutoMatcher {
            regex: Regex::new(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})").unwrap(),
            kind: DateKind::Syslog,
        },
    ]
});

struct AutoMatcher {
    regex: Regex,
    kind: DateKind,
}

#[allow(dead_code)]
fn _ensure_unused_imports() {
    let _ = NaiveDate::from_ymd_opt(1970, 1, 1);
    let _ = DateTime::<Utc>::from_str("1970-01-01T00:00:00Z");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_iso8601() {
        let line = "2026-07-21T12:34:56Z Failed password from 1.2.3.4";
        let (_, ts, _) = auto_detect(line).unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-07-21T12:34:56+00:00");
    }

    #[test]
    fn detects_epoch() {
        let line = "1753108496 something happened";
        let (_, ts, _) = auto_detect(line).unwrap();
        assert_eq!(ts.timestamp(), 1753108496);
    }

    #[test]
    fn detects_syslog() {
        let line = "Jul 21 12:34:56 server sshd[123]: Failed password";
        let r = auto_detect(line);
        assert!(r.is_some(), "should detect syslog date");
    }

    #[test]
    fn compiles_strftime() {
        let m = compile("%Y-%m-%d %H:%M:%S").unwrap();
        let caps = m.regex.captures("2026-07-21 12:34:56 hello").unwrap();
        let raw = caps.get(1).unwrap().as_str();
        assert_eq!(raw, "2026-07-21 12:34:56");
        let ts = convert(raw, m.kind).unwrap();
        assert_eq!(ts.to_rfc3339(), "2026-07-21T12:34:56+00:00");
    }

    #[test]
    fn compiles_epoch() {
        let m = compile("Epoch").unwrap();
        let caps = m.regex.captures("1753108496 hi").unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "1753108496");
    }
}
