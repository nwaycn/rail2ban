//! Time abbreviation parsing compatible with fail2ban.
//!
//! fail2ban accepts human-friendly durations like `1y`, `12mo`, `4w`, `30d`,
//! `1h`, `10m`, `30s` (year/month/week/day/hour/minute/second) for `bantime`,
//! `findtime`, `dbpurgeage`, etc. It also accepts plain integers (seconds) and
//! the special value `-1` meaning "permanent".

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A parsed time value. Negative values (e.g. `-1`) are interpreted as
/// "permanent"/infinite in fail2ban semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeValue {
    /// The duration in seconds. `None` means "permanent" (negative input).
    pub seconds: Option<u64>,
    /// Whether the value was originally negative.
    pub permanent: bool,
}

impl TimeValue {
    /// Parse a string into a `TimeValue`.
    ///
    /// Accepted forms:
    /// - `"3600"` → 3600 seconds
    /// - `"-1"` → permanent
    /// - `"1y"` / `"12mo"` / `"4w"` / `"30d"` / `"1h"` / `"10m"` / `"30s"`
    /// - combinations like `"1d12h"`
    /// - `"permanent"`, `"infinite"`, `"never"` → permanent
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::TimeParse("empty time value".into()));
        }

        let lower = trimmed.to_ascii_lowercase();
        if matches!(lower.as_str(), "permanent" | "infinite" | "never") {
            return Ok(Self {
                seconds: None,
                permanent: true,
            });
        }

        // Try plain integer first (possibly negative).
        if let Ok(n) = trimmed.parse::<i64>() {
            if n < 0 {
                return Ok(Self {
                    seconds: None,
                    permanent: true,
                });
            }
            return Ok(Self {
                seconds: Some(n as u64),
                permanent: false,
            });
        }

        // Otherwise walk the string consuming <number><unit> pairs.
        let mut total: u64 = 0;
        let mut chars = lower.chars().peekable();
        let mut consumed_unit = false;
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
                continue;
            }
            // collect digits
            let mut num = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    num.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            if num.is_empty() {
                return Err(Error::TimeParse(format!(
                    "expected number at position in {input:?}"
                )));
            }
            let n: u64 = num
                .parse()
                .map_err(|e| Error::TimeParse(format!("invalid number {num}: {e}")))?;

            // collect unit letters until next digit or whitespace or end.
            let mut unit = String::new();
            while let Some(&u) = chars.peek() {
                if u.is_ascii_alphabetic() {
                    unit.push(u);
                    chars.next();
                } else {
                    break;
                }
            }
            if unit.is_empty() {
                // bare integer seconds (suffix-less remainder)
                total = total.saturating_add(n);
                consumed_unit = true;
                break;
            }
            let secs = match unit.as_str() {
                "y" | "year" | "years" => n.saturating_mul(365 * 86400),
                "mo" | "month" | "months" => n.saturating_mul(30 * 86400),
                "w" | "week" | "weeks" => n.saturating_mul(7 * 86400),
                "d" | "day" | "days" => n.saturating_mul(86400),
                "h" | "hour" | "hours" => n.saturating_mul(3600),
                "m" | "min" | "minute" | "minutes" => n.saturating_mul(60),
                "s" | "sec" | "second" | "seconds" => n,
                other => {
                    return Err(Error::TimeParse(format!(
                        "unknown time unit {other:?} in {input:?}"
                    )))
                }
            };
            total = total.saturating_add(secs);
            consumed_unit = true;
        }

        if !consumed_unit {
            return Err(Error::TimeParse(format!(
                "no time unit consumed in {input:?}"
            )));
        }

        Ok(Self {
            seconds: Some(total),
            permanent: false,
        })
    }

    /// Return the duration, or `None` if permanent.
    pub fn to_duration(self) -> Option<Duration> {
        self.seconds.map(Duration::from_secs)
    }

    /// Return seconds, or `u64::MAX` for permanent.
    pub fn to_seconds_or_max(self) -> u64 {
        self.seconds.unwrap_or(u64::MAX)
    }
}

impl From<u64> for TimeValue {
    fn from(s: u64) -> Self {
        Self {
            seconds: Some(s),
            permanent: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_int() {
        assert_eq!(TimeValue::parse("3600").unwrap().seconds, Some(3600));
    }

    #[test]
    fn parses_negative_as_permanent() {
        let v = TimeValue::parse("-1").unwrap();
        assert!(v.permanent);
        assert_eq!(v.seconds, None);
    }

    #[test]
    fn parses_permanent_keyword() {
        let v = TimeValue::parse("permanent").unwrap();
        assert!(v.permanent);
    }

    #[test]
    fn parses_units() {
        assert_eq!(TimeValue::parse("1y").unwrap().seconds, Some(365 * 86400));
        assert_eq!(TimeValue::parse("12mo").unwrap().seconds, Some(12 * 30 * 86400));
        assert_eq!(TimeValue::parse("4w").unwrap().seconds, Some(4 * 7 * 86400));
        assert_eq!(TimeValue::parse("30d").unwrap().seconds, Some(30 * 86400));
        assert_eq!(TimeValue::parse("1h").unwrap().seconds, Some(3600));
        assert_eq!(TimeValue::parse("10m").unwrap().seconds, Some(600));
        assert_eq!(TimeValue::parse("30s").unwrap().seconds, Some(30));
    }

    #[test]
    fn parses_combinations() {
        assert_eq!(
            TimeValue::parse("1d12h").unwrap().seconds,
            Some(86400 + 12 * 3600)
        );
        assert_eq!(
            TimeValue::parse("1w 2d 3h 4m 5s").unwrap().seconds,
            Some(7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5)
        );
    }

    #[test]
    fn rejects_invalid() {
        assert!(TimeValue::parse("").is_err());
        assert!(TimeValue::parse("abc").is_err());
        assert!(TimeValue::parse("1x").is_err());
    }
}
