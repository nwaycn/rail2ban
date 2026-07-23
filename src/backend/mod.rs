//! Log acquisition backends.
//!
//! Each backend produces a stream of log lines consumed by the jail's filter
//! pipeline. Three backends are provided:
//!
//! - [`file::FileBackend`] — uses inotify when available, falls back to polling.
//! - [`poll::PollBackend`] — pure polling, always available.
//! - [`journal::JournalBackend`] — reads systemd journal (Linux only; stubbed
//!   elsewhere).
//!
//! All backends implement the [`LogBackend`] trait.

pub mod file;
pub mod poll;
pub mod journal;

use crate::error::Result;
use tokio::sync::mpsc;

/// A single log line acquired from a backend.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// The raw line text (without trailing newline).
    pub text: String,
    /// Source file or journal cursor.
    pub source: String,
}

/// Trait implemented by every log backend.
pub trait LogBackend: Send {
    /// Spawn the backend, returning a receiver of [`LogLine`]s.
    fn run(
        self,
        tx: mpsc::Sender<LogLine>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

    /// Human-readable name of the backend (e.g. `"file"`, `"poll"`, `"journal"`).
    fn name(&self) -> &'static str;
}
