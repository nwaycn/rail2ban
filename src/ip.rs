//! IP / CIDR utilities and ignore lists.

use crate::error::{Error, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

/// IP family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpFamily {
    /// IPv4
    Inet4,
    /// IPv6
    Inet6,
}

impl IpFamily {
    /// Returns `"inet4"` or `"inet6"`.
    pub fn as_str(self) -> &'static str {
        match self {
            IpFamily::Inet4 => "inet4",
            IpFamily::Inet6 => "inet6",
        }
    }
}

/// A single entry in an `ignoreip`-style list. May be a single IP, a CIDR, a
/// hostname (raw string), or a `file:` reference (loaded lazily).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IgnoreEntry {
    /// A CIDR or single IP.
    Net(IpNet),
    /// A bare IP (no mask).
    Ip(IpAddr),
    /// A raw string (e.g. hostname or failure ID).
    Raw(String),
}

impl IgnoreEntry {
    /// Parse a single ignoreip entry.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::IpParse("empty entry".into()));
        }
        if let Ok(net) = IpNet::from_str(s) {
            return Ok(Self::Net(net));
        }
        if let Ok(ip) = IpAddr::from_str(s) {
            return Ok(Self::Ip(ip));
        }
        Ok(Self::Raw(s.to_string()))
    }

    /// Returns whether this entry matches the given IP/failure-ID.
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            IgnoreEntry::Net(net) => net.contains(ip),
            IgnoreEntry::Ip(addr) => addr == ip,
            IgnoreEntry::Raw(_) => false,
        }
    }

    /// Returns whether this entry matches the given raw failure ID.
    pub fn matches_raw(&self, raw: &str) -> bool {
        match self {
            IgnoreEntry::Raw(s) => s == raw,
            _ => false,
        }
    }
}

/// A parsed `ignoreip` list (without `file:` references — those are loaded
/// separately by [`IgnoreList::load_file`]).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IgnoreList {
    entries: Vec<IgnoreEntry>,
}

impl IgnoreList {
    /// Build an empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a whitespace/comma separated list.
    pub fn parse(s: &str) -> Result<Self> {
        let mut list = Self::new();
        for part in s.split(|c: char| c.is_whitespace() || c == ',') {
            if part.is_empty() {
                continue;
            }
            // `file:` entries are loaded eagerly here (simple impl).
            if let Some(path) = part.strip_prefix("file:") {
                list.load_file(path)?;
            } else {
                list.entries.push(IgnoreEntry::parse(part)?);
            }
        }
        Ok(list)
    }

    /// Append entries loaded from a file (one per line, `#` comments).
    pub fn load_file(&mut self, path: &str) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::IpParse(format!("loading ignoreip file {path}: {e}")))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.entries.push(IgnoreEntry::parse(line)?);
        }
        Ok(())
    }

    /// Push a single entry.
    pub fn push(&mut self, entry: IgnoreEntry) {
        self.entries.push(entry);
    }

    /// Returns whether any entry matches the given IP.
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.entries.iter().any(|e| e.matches(ip))
    }

    /// Returns whether any entry matches the given raw failure ID.
    pub fn matches_raw(&self, raw: &str) -> bool {
        self.entries.iter().any(|e| e.matches_raw(raw))
    }

    /// Iterate over the entries.
    pub fn iter(&self) -> impl Iterator<Item = &IgnoreEntry> {
        self.entries.iter()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Detect IP family from a parsed [`IpAddr`].
pub fn family_of(ip: IpAddr) -> IpFamily {
    match ip {
        IpAddr::V4(_) => IpFamily::Inet4,
        IpAddr::V6(_) => IpFamily::Inet6,
    }
}

/// Detect IP family from a string; defaults to `Inet4` when parsing fails.
pub fn family_of_or_default(s: &str) -> IpFamily {
    s.parse::<IpAddr>()
        .map(family_of)
        .unwrap_or(IpFamily::Inet4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_cidr() {
        let e = IgnoreEntry::parse("192.0.2.0/24").unwrap();
        assert!(matches!(e, IgnoreEntry::Net(_)));
        assert!(e.matches(&"192.0.2.10".parse().unwrap()));
        assert!(!e.matches(&"192.0.3.10".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6() {
        let e = IgnoreEntry::parse("::1").unwrap();
        assert!(matches!(e, IgnoreEntry::Ip(_)));
        assert!(e.matches(&"::1".parse().unwrap()));
    }

    #[test]
    fn parses_raw() {
        let e = IgnoreEntry::parse("publickey:abc").unwrap();
        assert!(matches!(e, IgnoreEntry::Raw(_)));
    }

    #[test]
    fn parses_list() {
        let l = IgnoreList::parse("127.0.0.1/8 192.0.2.1").unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.matches_ip(&"127.0.0.1".parse().unwrap()));
        assert!(l.matches_ip(&"192.0.2.1".parse().unwrap()));
    }
}
