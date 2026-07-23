//! File backend (inotify on Linux, polling fallback elsewhere).

use crate::backend::{LogBackend, LogLine};
use crate::error::Result;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;

/// File backend that uses inotify on Linux and falls back to polling on other
/// platforms.
pub struct FileBackend {
    paths: Vec<PathBuf>,
    interval: Duration,
    from_tail: bool,
}

impl FileBackend {
    /// Create a new file backend.
    pub fn new(paths: Vec<PathBuf>, from_tail: bool) -> Self {
        Self {
            paths,
            interval: Duration::from_secs(1),
            from_tail,
        }
    }

    /// Override the polling interval (used as fallback and as inotify idle).
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

impl LogBackend for FileBackend {
    fn run(self, tx: mpsc::Sender<LogLine>) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = run_inotify(&self.paths, self.from_tail, &tx).await {
                    tracing::warn!(
                        "inotify backend failed ({e}); falling back to polling"
                    );
                } else {
                    return Ok(());
                }
            }
            // Fallback / non-Linux.
            crate::backend::poll::PollBackend::new(self.paths, self.interval, self.from_tail)
                .run(tx)
                .await
        })
    }

    fn name(&self) -> &'static str {
        "file"
    }
}

#[cfg(target_os = "linux")]
async fn run_inotify(
    paths: &[PathBuf],
    from_tail: bool,
    tx: &mpsc::Sender<LogLine>,
) -> Result<()> {
    use inotify::{Inotify, WatchMask};
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;

    let mut inotify = Inotify::init()
        .map_err(|e| crate::Error::other(format!("inotify init: {e}")))?;

    let mut readers: Vec<(PathBuf, std::fs::File, u64, u64)> = Vec::new();
    for p in paths {
        // Open the file and seek to the right position.
        match std::fs::File::open(p) {
            Ok(mut f) => {
                let meta = f.metadata()?;
                let ino = meta.ino();
                let size = meta.len();
                let start = if from_tail { size } else { 0 };
                f.seek(SeekFrom::Start(start))?;
                readers.push((p.clone(), f, ino, size));
                let _ = inotify.watches().add(
                    p,
                    WatchMask::MODIFY | WatchMask::MOVE_SELF | WatchMask::DELETE_SELF,
                );
            }
            Err(e) => {
                tracing::warn!("could not open {}: {e}", p.display());
            }
        }
    }

    let mut buffer = [0u8; 4096];
    let mut events = inotify.into_event_stream(&mut buffer)?;
    while let Some(ev) = events.next().await {
        let ev = match ev {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!("inotify event error: {e}");
                continue;
            }
        };
        // For each event, read new data from the matching file(s).
        for (path, file, ino, last_size) in &mut readers {
            // Re-stat to detect rotation / truncation.
            if let Ok(meta) = file.metadata() {
                let cur_ino = meta.ino();
                let cur_size = meta.len();
                if cur_ino != *ino || cur_size < *last_size {
                    tracing::debug!(
                        "rotation detected on {} (ino {} -> {}, size {} -> {})",
                        path.display(),
                        ino,
                        cur_ino,
                        last_size,
                        cur_size
                    );
                    // Reopen the file.
                    if let Ok(new_file) = std::fs::File::open(path) {
                        *file = new_file;
                        *ino = cur_ino;
                        *last_size = 0;
                        let _ = (&*file).seek(SeekFrom::Start(0));
                    }
                }
            }
            let mut reader = BufReader::new(&*file);
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
                        source: path.to_string_lossy().into_owned(),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            if let Ok(pos) = (&*file).stream_position() {
                *last_size = pos;
            }
        }
        let _ = ev; // event mask not used; we re-read all files on any event.
    }
    Ok(())
}
