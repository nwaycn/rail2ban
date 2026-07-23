//! Polling-based file backend.
//!
//! Periodically stats each watched file and reads new bytes. Works on every
//! platform; used as a fallback when inotify is unavailable or for tests.

use crate::backend::{LogBackend, LogLine};
use crate::error::Result;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;

/// A polling backend watching one or more files.
pub struct PollBackend {
    paths: Vec<PathBuf>,
    interval: Duration,
    from_tail: bool,
}

impl PollBackend {
    /// Create a new polling backend.
    pub fn new(paths: Vec<PathBuf>, interval: Duration, from_tail: bool) -> Self {
        Self {
            paths,
            interval,
            from_tail,
        }
    }
}

impl LogBackend for PollBackend {
    fn run(self, tx: mpsc::Sender<LogLine>) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            let mut state: Vec<FileState> = self
                .paths
                .iter()
                .map(|p| FileState::new(p.clone(), self.from_tail))
                .collect();

            loop {
                for s in &mut state {
                    if let Err(e) = poll_one(s, &tx).await {
                        tracing::debug!("poll backend error on {}: {e}", s.path.display());
                    }
                }
                tokio::time::sleep(self.interval).await;
            }
        })
    }

    fn name(&self) -> &'static str {
        "poll"
    }
}

struct FileState {
    path: PathBuf,
    #[allow(dead_code)]
    file: Option<std::fs::File>,
    inode: Option<u64>,
    size: u64,
    reader: Option<BufReader<std::fs::File>>,
}

impl FileState {
    fn new(path: PathBuf, from_tail: bool) -> Self {
        let mut s = Self {
            path,
            file: None,
            inode: None,
            size: if from_tail { u64::MAX } else { 0 },
            reader: None,
        };
        s.try_open();
        s
    }

    fn try_open(&mut self) {
        if let Ok(file) = std::fs::File::open(&self.path) {
            if let Ok(meta) = file.metadata() {
                #[cfg(unix)]
                use std::os::unix::fs::MetadataExt;
                #[cfg(unix)]
                let ino = Some(meta.ino());
                #[cfg(not(unix))]
                let ino = None;
                self.inode = ino;
                let cur_size = meta.len();
                if self.size == u64::MAX {
                    // tail mode: jump to end
                    let _ = (&file).seek(SeekFrom::End(0));
                    self.size = cur_size;
                } else if self.size > cur_size {
                    // truncated (log rotation): reset to head
                    let _ = (&file).seek(SeekFrom::Start(0));
                    self.size = 0;
                } else {
                    let _ = (&file).seek(SeekFrom::Start(self.size));
                }
                self.reader = Some(BufReader::new(file));
            }
        }
    }
}

async fn poll_one(state: &mut FileState, tx: &mpsc::Sender<LogLine>) -> Result<()> {
    // Detect rotation by re-statting.
    if let Ok(meta) = std::fs::metadata(&state.path) {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(unix)]
        let cur_ino = Some(meta.ino());
        #[cfg(not(unix))]
        let cur_ino = None;
        let cur_size = meta.len();
        if state.inode != cur_ino || cur_size < state.size {
            tracing::debug!(
                "rotation detected on {} (ino {:?} -> {:?}, size {} -> {})",
                state.path.display(),
                state.inode,
                cur_ino,
                state.size,
                cur_size
            );
            state.inode = cur_ino;
            state.size = 0;
            state.reader = None;
        }
    }
    if state.reader.is_none() {
        state.try_open();
    }
    if let Some(reader) = state.reader.as_mut() {
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
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
                    source: state.path.to_string_lossy().into_owned(),
                })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        if let Ok(pos) = reader.stream_position() {
            state.size = pos;
        }
    }
    Ok(())
}
