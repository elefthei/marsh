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
    /// A job directory escapes the seed or names nothing in it.
    #[error("{path} cannot be used as a job directory: {reason}")]
    SandboxDir {
        /// The directory as the user typed it.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// A job name a live job already holds.
    #[error("{} already exists", .0.reference())]
    JobExists(crate::ShellId),
    /// A job name nothing in the table answers to.
    #[error("no such job: {}", .0.reference())]
    NoSuchJob(crate::ShellId),
    /// A command was submitted to a job that is already running one.
    #[error("{} is already running a command", .0.reference())]
    JobBusy(crate::ShellId),
    /// A command was submitted to a job an accepted stop has already closed.
    #[error("{} is closing", .0.reference())]
    JobClosing(crate::ShellId),
    /// A terminal geometry with a zero dimension, which no job could be given.
    #[error("invalid terminal size: {rows}x{cols}")]
    InvalidTerminalSize {
        /// Requested height in character cells.
        rows: u16,
        /// Requested width in character cells.
        cols: u16,
    },
    /// A forcibly stopped job could not be proven quiescent, so its snapshot was kept.
    ///
    /// Chained rather than flattened: the inner failure is what a reader has to act on, and the
    /// outer sentence is what says the storage is still there to act on it with.
    #[error("could not terminate job {}; snapshot retained: {source}", .job.reference())]
    JobTermination {
        /// The job whose processes outlived the kill.
        job: crate::ShellId,
        /// Why quiescence could not be established.
        #[source]
        source: Box<Self>,
    },
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
}

impl From<marsh_exec::ExecError> for MuxError {
    /// Maps an executor failure onto the mux failure that already meant the same thing.
    ///
    /// Variant by variant rather than through one catch-all string: a caller matching on
    /// [`MuxError::Io`] to inspect an `ErrorKind`, or on [`MuxError::SessionBusy`] to report a
    /// competing marsh, must keep working now that the failure comes from the executor crate,
    /// which is what owns the storage.
    fn from(error: marsh_exec::ExecError) -> Self {
        match error {
            marsh_exec::ExecError::NoSubvolume(path) => Self::NoSubvolume(path),
            marsh_exec::ExecError::SeedIsMountRoot(path) => Self::SeedIsMountRoot(path),
            marsh_exec::ExecError::SeedDir { path, reason } => Self::SeedDir { path, reason },
            marsh_exec::ExecError::SessionBusy(path) => Self::SessionBusy(path),
            marsh_exec::ExecError::NotBtrfs(path) => Self::NotBtrfs(path),
            marsh_exec::ExecError::NotUserSubvolRmAllowed(path) => {
                Self::NotUserSubvolRmAllowed(path)
            }
            marsh_exec::ExecError::StateNotDirectory(path) => Self::StateNotDirectory(path),
            marsh_exec::ExecError::Snapshot(message) => Self::Snapshot(message),
            marsh_exec::ExecError::Exec(message) => Self::Exec(message),
            marsh_exec::ExecError::TraceParse(message) => Self::TraceParse(message),
            marsh_exec::ExecError::Io(error) => Self::Io(error),
        }
    }
}
