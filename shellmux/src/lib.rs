#![deny(missing_docs)]
//! `ShellMux`: a btrfs-snapshotted, strace-audited, capability-gated shell multiplexer.
//!
//! One [`ShellMux`] owns a *seed* directory — a git repository on a btrfs subvolume — and one brush
//! shell per [`Principal`]. Every command submitted through [`ShellMux::run_cmd`] is an atomic
//! transaction against that seed:
//!
//! 1. **Snapshot** — two writable copy-on-write snapshots of the seed are taken under a read lock:
//!    `base` (the reference) and `work` (where the command runs). The seed is never the workspace.
//! 2. **Execute** — the command runs in `work` inside a dedicated `marsh-exec` process (a brush
//!    shell) under `strace`. Execution is out-of-process because brush performs redirections and
//!    builtins *in* the calling process, which `ptrace` cannot audit from the inside. Git is not a
//!    process at all: each supported git command is a builtin running in-process over libgit2, and
//!    the shell reports every builtin invocation through a hook ([`hooks`]).
//! 3. **Translate** — the two recorded streams, syscalls and builtin invocations, are merged by
//!    timestamp and become capability [`Event`]s.
//! 4. **Authorize** — the events are submitted to the central authority, backed by the forked
//!    validator's `GitPolicy`. A denial reports every refused capability, the precondition it
//!    failed, and the fixes that would unblock it.
//! 5. **Merge** — on full grant the diff between `base` and `work` is applied to the seed through a
//!    write-ahead log, so a crash mid-merge is repaired by replaying the log. A command whose read
//!    or write set was already merged by someone else loses the race and must be rerun.
//!
//! The mux *observes*; it does not confine. There is no chroot: a command that writes outside the
//! snapshot really writes there. What the mux guarantees is that nothing enters the seed without a
//! granted capability, and that concurrent principals see a serializable seed.
//!
//! [`ShellMux::run_cmd`] performs all five phases and captures the command's output. A front-end
//! that runs commands as the user's terminal jobs splits the same transaction in two —
//! [`ShellMux::start_cmd`] does snapshot and execute, [`ShellMux::conclude_cmd`] the rest — and owns
//! the wait in between, which is the only way to observe a job *stopping* rather than exiting.
//!
//! Every traced command also gets a third standard stream: fd 3 is instrumentation ("stdinstr"),
//! alongside stdout and stderr, so a command can report about itself without polluting its output.
//! [`ShellMux::run_cmd`] wires it to `/dev/null`; [`ShellMux::start_cmd`] takes the descriptor to
//! install, which is how a console turns it into a stream it can display.

mod authority;
mod diff;
mod error;
mod gitcmd;
mod gitexec;
pub mod gitshell;
pub mod hooks;
mod mux;
mod snapshot;
mod strace;
mod translate;
mod wal;

pub use error::MuxError;
pub use mux::{CapDenial, CmdOutcome, MuxOptions, ShellMux, StalePath, StartedCmd};

/// Capability model shared with the policy oracle, re-exported so callers need not depend on the
/// forked validator crate directly.
pub use rust_validator::{Action, Event, Principal, Resource};
