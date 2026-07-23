//! Error types used throughout rail2ban.

use thiserror::Error;

/// Top-level rail2ban error.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration parsing / interpolation error.
    #[error("config error: {0}")]
    Config(String),

    /// Regex compilation error.
    #[error("regex error: {0}")]
    Regex(String),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Time parsing error.
    #[error("time parse error: {0}")]
    TimeParse(String),

    /// IP parsing error.
    #[error("ip parse error: {0}")]
    IpParse(String),

    /// Generic protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Action execution error (non-zero exit, etc.).
    #[error("action error: {0}")]
    Action(String),

    /// Jail not found / not running.
    #[error("jail error: {0}")]
    Jail(String),

    /// Any other error wrapped as a string message.
    #[error("{0}")]
    Other(String),

    /// Wrap anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl Error {
    /// Build a config error from any printable value.
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::Config(msg.into())
    }

    /// Build a regex error.
    pub fn regex<S: Into<String>>(msg: S) -> Self {
        Self::Regex(msg.into())
    }

    /// Build a generic "other" error.
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Self::Other(msg.into())
    }
}

/// Convenience `Result` alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_nicely() {
        let e = Error::config("missing bracket");
        assert_eq!(e.to_string(), "config error: missing bracket");
    }
}
