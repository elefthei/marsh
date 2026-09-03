//! Infrastructure failures.
//!
//! `MuxError` is reserved for the mux *breaking*: a missing btrfs filesystem, a snapshot ioctl that
//! failed, an executor that could not be spawned, an unparsable trace, a corrupt write-ahead log.
//! Domain outcomes — a command whose capabilities were denied, a stale snapshot, an untranslatable
//! command line — are **not** errors; they are [`crate::CmdOutcome`] variants, because they are
//! answers the mux computed successfully.

use std::path::PathBuf;

/// Infrastructure failure raised by the mux.
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    /// The mux root is not on a btrfs filesystem, so snapshots are impossible.
    #[error("{0} is not on a btrfs filesystem (copy-on-write snapshots are required)")]
    NotBtrfs(PathBuf),
    /// A subvolume create/snapshot/delete operation failed.
    #[error("btrfs snapshot operation failed: {0}")]
    Snapshot(String),
    /// The traced executor could not be spawned or reaped.
    #[error("traced execution failed: {0}")]
    Exec(String),
    /// The strace log could not be parsed.
    #[error("cannot parse strace output: {0}")]
    TraceParse(String),
    /// The write-ahead log is unusable or its recovery failed.
    #[error("write-ahead log failure: {0}")]
    Wal(String),
    /// Filesystem I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The embedded brush shell failed to build or run.
    #[error("brush shell failure: {0}")]
    Brush(String),
    /// The seed repository could not be initialized.
    #[error("git setup failed: {0}")]
    GitSetup(String),
}
