//! Configuration parsing & interpolation.
//!
//! This module provides fail2ban-compatible parsing of `jail.conf`/`jail.local`
//! /`jail.d/*.conf`, `filter.d/*.conf`, `action.d/*.conf`, and `paths/*.conf`.
//!
//! Supported features:
//! - INI-style sections (`[section]`), `#` line comments, `; ` inline comments
//! - Multi-line continuation (leading whitespace)
//! - `[INCLUDES]` `before=`/`after=`
//! - `.local` overlay on `.conf`
//! - `jail.d/` and `fail2ban.d/` directories
//! - `%(name)s` interpolation, `%(section/parameter)s` cross-section,
//!   `%(default/parameter)s`, `%(known/parameter)s`
//! - `<known/parameter>` init extension tags
//! - `<lt_<logtype>/...>` and `<ipt_<type>/...>` dynamic section selection
//! - Time abbreviation parsing via [`crate::time`]

pub mod interpolator;
pub mod parser;
pub mod jail;
pub mod filter;
pub mod action;
pub mod loader;

pub use action::{ActionConfig, ActionDefinition};
pub use filter::{FilterConfig, FilterDefinition};
pub use interpolator::{InterpolationContext, interpolate};
pub use jail::{JailConfig, JailSet};
pub use loader::{ConfigLoader, GlobalConfig, LoadedConfig};
pub use parser::{IniDocument, IniSection, parse_ini, parse_ini_file, resolve_includes};

use crate::error::Result;

/// Default configuration search paths (mirrors fail2ban).
pub const DEFAULT_CONF_PATHS: &[&str] = &[
    "/etc/rail2ban",
    "/etc/fail2ban",
];

/// Build-in `[DEFAULT]` interpolation variables.
pub fn builtin_defaults() -> indexmap::IndexMap<String, String> {
    let mut m = indexmap::IndexMap::new();
    m.insert("fail2ban_version".into(), env!("CARGO_PKG_VERSION").into());
    m.insert("rail2ban_version".into(), env!("CARGO_PKG_VERSION").into());
    if let Ok(host) = hostname() {
        m.insert("fq-hostname".into(), host);
    } else {
        m.insert("fq-hostname".into(), "localhost".into());
    }
    m
}

fn hostname() -> Result<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let n = nix::unistd::gethostname(&mut buf)
            .map_err(|e| crate::Error::other(format!("gethostname: {e}")))?;
        Ok(String::from_utf8_lossy(&n[..n.len()]).into_owned())
    }
    #[cfg(not(unix))]
    {
        Ok("localhost".into())
    }
}
