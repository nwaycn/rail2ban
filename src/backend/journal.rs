//! systemd journal backend (Linux only).
//!
//! On non-Linux platforms this is a no-op stub. The Linux implementation
//! shells out to `journalctl` rather than linking against libsystemd; this
//! avoids a C dependency at the cost of some performance. For production use
//! a native `libsystemd` binding should be preferred.

use crate::backend::{LogBackend, LogLine};
use crate::error::Result;
use std::pin::Pin;
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::mpsc;

/// A journal backend that shells out to `journalctl -f -o cat`.
pub struct JournalBackend {
    matches: Vec<String>,
}

impl JournalBackend {
    /// Create a new journal backend. `matches` are systemd journal match
    /// expressions; entries are OR-ed with `+`.
    pub fn new(matches: Vec<String>) -> Self {
        Self { matches }
    }
}

impl LogBackend for JournalBackend {
    fn run(self, tx: mpsc::Sender<LogLine>) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            let mut cmd = Command::new("journalctl");
            cmd.arg("-f").arg("-o").arg("cat").arg("--no-pager");
            if self.matches.is_empty() {
                // No filter.
            } else if self.matches.len() == 1 {
                cmd.arg(&self.matches[0]);
            } else {
                let combined = self.matches.join(" + ");
                cmd.arg(&combined);
            }
            cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            cmd.kill_on_drop(true);

            let mut child = cmd.spawn().map_err(|e| {
                crate::Error::other(format!("spawning journalctl: {e}"))
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                crate::Error::other("journalctl did not produce stdout")
            })?;
            let mut reader = tokio::io::BufReader::new(stdout);
            use tokio::io::AsyncBufReadExt;
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\n', '\r']);
                if trimmed.is_empty() {
                    continue;
                }
                if tx
                    .send(LogLine {
                        text: trimmed.to_string(),
                        source: "journal".into(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = child.wait().await;
            Ok(())
        })
    }

    fn name(&self) -> &'static str {
        "journal"
    }
}
