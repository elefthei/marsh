//! Execution failures.
//!
//! `ExecError` is reserved for the executor *breaking*: a tracer that could not be probed or
//! spawned, a worker binary that is not where it was said to be, an unparsable instrumentation
//! stream, a log that could not be read, a storage layout that cannot hold a session. A command
//! that merely exited non-zero is not an error — it is an [`crate::ExecutionResult`] with that
//! exit code, because running it succeeded.

use std::path::PathBuf;

/// Failure raised while launching, supervising, or decoding one instrumented execution, or while
/// establishing the persistent storage one runs against.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// No btrfs subvolume contains the directory marsh was started in.
    #[error(
        "no btrfs subvolume contains {0}; marsh snapshots the subvolume it runs in \
         (see README.md, \"Setting up marsh\")"
    )]
    NoSubvolume(PathBuf),
    /// The seed is its mount's root, so there is nowhere beside it to keep state.
    #[error(
        "{0} is the root of its mount, so marsh has nowhere beside it for its state; \
         run marsh inside a nested subvolume (see README.md, \"Setting up marsh\")"
    )]
    SeedIsMountRoot(PathBuf),
    /// A directory marsh was pointed at cannot be used.
    #[error("{path} cannot be used: {reason}")]
    SeedDir {
        /// The path as it was given.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// Another marsh process currently owns this seed's session state.
    #[error("{0} already has an active marsh session")]
    SessionBusy(PathBuf),
    /// The state directory is not on a btrfs filesystem, so snapshots are impossible.
    #[error(
        "{0} is not on a btrfs filesystem; marsh needs copy-on-write snapshots \
         (see README.md, \"Setting up marsh\")"
    )]
    NotBtrfs(PathBuf),
    /// The state directory's mount lacks `user_subvol_rm_allowed`, so snapshots cannot be
    /// reclaimed.
    #[error(
        "{0} is on a btrfs mount without `user_subvol_rm_allowed`; marsh creates and deletes \
         subvolumes as your user (see README.md, \"Setting up marsh\")"
    )]
    NotUserSubvolRmAllowed(PathBuf),
    /// Something that is not a directory occupies a path marsh needs.
    #[error("{0} exists and is not a directory; marsh keeps its state there")]
    StateNotDirectory(PathBuf),
    /// A subvolume create/snapshot/delete operation failed.
    #[error("btrfs snapshot operation failed: {0}")]
    Snapshot(String),
    /// The traced worker could not be spawned or reaped.
    #[error("traced execution failed: {0}")]
    Exec(String),
    /// An instrumentation stream could not be parsed.
    #[error("cannot parse strace output: {0}")]
    TraceParse(String),
    /// Filesystem I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<brush_btrfs::Error> for ExecError {
    /// Maps a storage failure onto the executor failure that already meant the same thing.
    ///
    /// Variant by variant rather than through one catch-all string: a caller matching on
    /// [`ExecError::Io`] to inspect an `ErrorKind`, or on [`ExecError::SessionBusy`] to report a
    /// competing marsh, must keep working now that the storage lives in its own crate.
    ///
    /// The two storage variants with no executor counterpart — an invalid run id and a
    /// write-ahead-log failure — become [`ExecError::Exec`], which is the executor's own
    /// "this execution could not be set up or completed".
    fn from(error: brush_btrfs::Error) -> Self {
        match error {
            brush_btrfs::Error::NoSubvolume(path) => Self::NoSubvolume(path),
            brush_btrfs::Error::SeedIsMountRoot(path) => Self::SeedIsMountRoot(path),
            brush_btrfs::Error::SeedDir { path, reason } => Self::SeedDir { path, reason },
            brush_btrfs::Error::SessionBusy(path) => Self::SessionBusy(path),
            brush_btrfs::Error::NotBtrfs(path) => Self::NotBtrfs(path),
            brush_btrfs::Error::NotUserSubvolRmAllowed(path) => Self::NotUserSubvolRmAllowed(path),
            brush_btrfs::Error::StateNotDirectory(path) => Self::StateNotDirectory(path),
            brush_btrfs::Error::Snapshot(message) => Self::Snapshot(message),
            brush_btrfs::Error::InvalidRunId(run_id) => {
                Self::Exec(format!("invalid execution run id: {run_id:?}"))
            }
            brush_btrfs::Error::Wal(message) => Self::Exec(message),
            brush_btrfs::Error::Io(error) => Self::Io(error),
        }
    }
}
