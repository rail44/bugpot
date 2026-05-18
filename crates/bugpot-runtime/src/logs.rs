//! Per-container stdout/stderr forwarding.
//!
//! `Runtime::start_app` opens each container's `fd 1` / `fd 2` against
//! `<state>/logs/<app>/{stdout,stderr}.log` in `O_APPEND` mode and
//! spawns one [`forward_log_file`] task per stream. Each task tails
//! its file via `inotify` and re-emits new lines through `tracing`
//! under target `bugpot::app`, with fields `app` and `stream`.
//!
//! `MAX_LOG_BYTES` caps each file's on-disk size. When the file
//! grows past the cap, the tail truncates it in place (`ftruncate(0)`);
//! the container's existing fd keeps working — `O_APPEND` makes the
//! next write seek to the new end (= 0). Bytes written between the
//! size check and the truncate may be lost on disk; everything before
//! that point was already emitted through tracing, so the loss is
//! only visible to operators reading the file directly.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use futures::StreamExt;
use inotify::{Inotify, WatchMask};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tracing::{info, warn};

/// Per-stream cap on the on-disk log file before it gets truncated
/// in place. Sized for "small disk on cheap VM": with N apps × 2
/// streams, total log floor is N × 2 MiB even when truncation kicks
/// in continuously, which fits comfortably on a 10 GiB host.
pub(crate) const MAX_LOG_BYTES: u64 = 1024 * 1024;

async fn truncate_in_place(path: &Path) -> std::io::Result<()> {
    let file = tokio::fs::OpenOptions::new().write(true).open(path).await?;
    file.set_len(0).await
}

/// Follow a per-app log file and forward each new line through tracing.
///
/// Opens at the start of the file so bugpot restarts replay everything
/// the file still holds — that's how the interregnum (bugpot down, app
/// kept writing) gets into the new bugpot's tracing pipeline. Replay
/// is bounded by `MAX_LOG_BYTES` (truncation cap), so the cost is
/// at most one cap-worth of duplicate emissions per restart event.
///
/// Waits for `IN_MODIFY` from inotify between read passes instead of
/// polling — idle apps cost zero CPU on bugpot's side. After each
/// read pass, checks size: when the file has grown past
/// `MAX_LOG_BYTES`, truncates it in place and seeks the reader back
/// to 0. Container `fd 1/2` were opened `O_APPEND`, so writes after
/// truncation resume at offset 0.
///
/// Detached on purpose; cancellation happens when bugpot exits (we
/// hold no `JoinHandle`s).
pub(crate) async fn forward_log_file(path: PathBuf, app: String, stream: &'static str) {
    let inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            warn!(app = %app, stream, error = %e, "inotify init failed; log tail disabled");
            return;
        }
    };
    if let Err(e) = inotify.watches().add(&path, WatchMask::MODIFY) {
        warn!(app = %app, stream, path = %path.display(), error = %e, "inotify watch failed");
        return;
    }
    let buffer = vec![0u8; 1024];
    let mut events = match inotify.into_event_stream(buffer) {
        Ok(s) => s,
        Err(e) => {
            warn!(app = %app, stream, error = %e, "inotify into_event_stream failed");
            return;
        }
    };

    let file = match tokio::fs::OpenOptions::new().read(true).open(&path).await {
        Ok(f) => f,
        Err(e) => {
            warn!(app = %app, stream, path = %path.display(), error = %e, "open log file for tail failed");
            return;
        }
    };
    let mut reader = BufReader::new(file);
    // `line` accumulates bytes across iterations. `read_line` appends
    // to it, and we only emit + clear once we've actually seen a
    // newline — so a container that writes "Hello, w" before flushing
    // doesn't get split into two log entries on the bugpot side.
    let mut line = String::new();

    loop {
        // Drain everything currently in the file.
        loop {
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if line.ends_with('\n') {
                        let trimmed = line.trim_end();
                        if !trimmed.is_empty() {
                            info!(target: "bugpot::app", app = %app, stream, "{trimmed}");
                        }
                        line.clear();
                    }
                    // Otherwise: EOF hit mid-line. Keep what we have
                    // in `line` and loop — the next iteration will
                    // either pick up more bytes (if the container
                    // wrote while we were reading) or fall through to
                    // the inotify wait below.
                }
                Err(e) => {
                    warn!(app = %app, stream, error = %e, "log file tail read failed");
                    return;
                }
            }
        }

        // Bound on-disk size. In-place truncate keeps the inode (so
        // container fd 1/2 keep working); container `O_APPEND` causes
        // subsequent writes to start at offset 0.
        match tokio::fs::metadata(&path).await {
            Ok(meta) if meta.len() > MAX_LOG_BYTES => {
                if let Err(e) = truncate_in_place(&path).await {
                    warn!(app = %app, stream, error = %e, "truncate log file failed");
                } else {
                    info!(target: "bugpot::app", app = %app, stream, "log file truncated at {MAX_LOG_BYTES} bytes");
                    if let Err(e) = reader.seek(SeekFrom::Start(0)).await {
                        warn!(app = %app, stream, error = %e, "seek after truncate failed");
                        return;
                    }
                    // The bytes we accumulated belong to the pre-
                    // truncate file; concatenating them onto the
                    // first post-truncate line would corrupt it.
                    line.clear();
                }
            }
            Ok(_) => {}
            Err(e) => {
                warn!(app = %app, stream, error = %e, "metadata failed");
            }
        }

        // Block until the container writes again, or the watch goes
        // away. We don't care about the event details; one wake-up
        // per batch of writes is enough.
        if events.next().await.is_none() {
            return;
        }
    }
}

/// Spawn the two tail tasks for an app whose log dir is `log_dir` and
/// return their `JoinHandle`s. The caller is responsible for parking
/// the handles somewhere they can be `.abort()`-ed when the app is
/// removed (see `Runtime::ensure_log_tails` /
/// `Runtime::cleanup_orphan_container`). Without that pairing the
/// tasks leak — inotify watches survive container removal because
/// the log files themselves are kept around for post-mortem
/// (CLAUDE.md L333).
pub(crate) fn spawn_log_tails(log_dir: &Path, app: &str) -> [tokio::task::JoinHandle<()>; 2] {
    let stdout_path = log_dir.join("stdout.log");
    let stderr_path = log_dir.join("stderr.log");
    [
        tokio::spawn(forward_log_file(stdout_path, app.to_owned(), "stdout")),
        tokio::spawn(forward_log_file(stderr_path, app.to_owned(), "stderr")),
    ]
}
