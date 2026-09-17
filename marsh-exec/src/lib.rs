//! The instrumented executor: run a shell program, get back one ordered record of what it did.
//!
//! A command's effects are visible from two places and neither one alone is enough. External
//! programs are processes, so `strace` sees their syscalls; builtins run *inside* the shell — git
//! included, which this executor performs in-process through libgit2 — and are invisible as
//! commands to any tracer, so the shell reports them through a hook. This crate owns both streams,
//! the separate worker process that produces them, and the decoding that turns them into one
//! chronological [`ExecutionEvidence`].
//!
//! The API is a lifecycle, and each transition is a boundary a caller needs:
//!
//! 1. [`MarshExecutor::builder`] takes the [`PersistenceLayer`]'s exclusive lease, probes the
//!    tracer and starts the launcher thread, once per process.
//! 2. [`MarshExecutor::prepare`] resolves the worker binary — before the caller commits to any
//!    storage.
//! 3. [`PreparedExecutor::run`] captures output and owns the wait; [`PreparedExecutor::start`] and
//!    [`PreparedExecutor::start_pty`] attach the command to a terminal and hand the wait back.
//! 4. [`RunningExecution::complete`] consumes a reaped execution;
//!    [`RunningExecution::complete_forced`] consumes a killed one.
//! 5. [`CompletedExecution::collect`] reads and decodes the logs — after the caller has released
//!    whatever it was holding over the tree the command ran in.
//!
//! What comes back is [`ExecutionResult`]: an exit code, captured output, the retained logs, and
//! the evidence. The evidence is execution facts only — syscalls and builtin invocations in one
//! order. It names no principal, no policy, no capability and no grant; deciding what the facts
//! *mean* is the caller's job.
//!
//! The executor observes rather than confines. There is no chroot and no namespace: a command that
//! writes outside its working directory really writes there.

mod error;
mod executor;
mod strace;

pub mod evidence;
pub mod gitshell;

pub use brush_btrfs::PersistenceLayer;
pub use error::ExecError;
pub use evidence::{Call, ExecutionEvent, ExecutionEvidence, TraceLine};
pub use executor::{
    CompletedExecution, ExecutionLogs, ExecutionRequest, ExecutionResult, MarshExecutor,
    MarshExecutorBuilder, PreparedExecutor, RunningExecution,
};

/// Environment variable naming the owner a traced process belongs to.
///
/// A scope root is not an owner identity: several jobs may start from one shared tree, so a sweep
/// keyed on that path alone would kill another owner's processes.
pub use strace::JOB_UID_VAR;

/// Exit code reported when a command was killed for exceeding its timeout.
pub use strace::TIMEOUT_EXIT_CODE;
