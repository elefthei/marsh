//! `ShellMux`: a btrfs-snapshotted, strace-audited, capability-gated shell multiplexer.
//!
//! One [`ShellMux`] owns a *seed* — the btrfs subvolume containing the directory marsh was started
//! in — and one brush shell per [`Principal`]. Every command submitted through
//! [`ShellMux::run_cmd`] is an atomic transaction against that seed:
//!
//! 1. **Snapshot** — the job's snapshot `<uid>` is retaken from the seed under a read lock: one
//!    copy-on-write snapshot of the whole seed, and where the command runs. The seed itself is the
//!    reference its diff is later taken against.
//! 2. **Execute** — the command runs in `work` through the [`marsh_exec`] executor API: a
//!    dedicated `marsh-exec` worker process (a brush shell) under `strace`. Execution is
//!    out-of-process because brush performs redirections and builtins *in* the calling process,
//!    which `ptrace` cannot audit from the inside. Git is not a process at all: each supported git
//!    command is a builtin running in-process over libgit2, which the shell reports through a
//!    hook.
//! 3. **Translate** — the executor's ordered [`marsh_exec::ExecutionEvidence`], syscalls and
//!    builtin invocations already interleaved, becomes capability [`Event`]s.
//! 4. **Authorize** — the events are submitted to the central authority, backed by the forked
//!    validator's `GitPolicy`. A denial reports every refused capability, the precondition it
//!    failed, and the fixes that would unblock it.
//! 5. **Commit** — on full grant the diff between the seed and the snapshot is applied to the seed
//!    through the write-ahead log, so a crash mid-transaction is repaired by replaying it. A
//!    command whose read or write set was already committed by someone else loses the race and must
//!    be rerun. There is no second stage: the seed *is* the user's own directory.
//!
//! The mux *observes*; it does not confine. There is no chroot: a command that writes outside the
//! snapshot really writes there. What the mux guarantees is that nothing enters the seed without a
//! granted capability, and that concurrent principals see a serializable seed.
//!
//! [`ShellMux::run_cmd`] performs all five phases against a sandbox and captures the command's
//! output. A front-end instead opens *jobs*: [`ShellMux::spawn`] gives one a pseudoterminal and a
//! shell, [`ShellMux::start_in`] runs a command on it, [`ShellMux::write_input`] carries its input,
//! and [`ShellMux::wait_for_job`] observes it finishing. Its bytes travel the other way on their
//! own: the mux pumps every job's terminal and instrumentation streams into the
//! [`MarshFrontend`] it was built with, so no caller has to drain a job to keep it running.
//! The mux owns the wait and the conclusion in between, because one child has exactly one reaper,
//! and only one conclusion may merge.
//!
//! Every traced command also gets a third standard stream: fd 3 is instrumentation ("stdinstr"),
//! alongside stdout and stderr, so a command can report about itself without polluting its output.
//! [`ShellMux::run_cmd`] wires it to `/dev/null`; a job's commands write into a pipe the mux
//! delivers as [`FrontendEvent::Instrumentation`].

mod authority;
mod commit;
mod diff;
mod error;
mod frontend;
mod history;
mod ids;
mod jobs;
mod mux;
mod purity;
mod reconcile;
mod translate;
mod wal;

pub use error::MuxError;
pub use frontend::{FrontendEvent, MarshFrontend};
pub use jobs::{JobCloseMode, JobView, Reaped, RunningView, ShellId, Spawned};
pub use mux::{CapDenial, CmdOutcome, Plan, Sandbox, ShellMux, StalePath};
pub use purity::{CommandKey, PurityChecker, PurityCheckerBuilder, Verdict};

/// The execution and storage facilities a mux is built from, re-exported so a caller composes one
/// without depending on the executor crate directly.
pub use marsh_exec::{MarshExecutor, MarshExecutorBuilder, PersistenceLayer};

/// Capability model shared with the policy oracle, re-exported so callers need not depend on the
/// forked validator crate directly.
pub use rust_validator::{Action, Event, Principal, Resource};
