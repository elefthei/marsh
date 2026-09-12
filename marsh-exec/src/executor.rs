//! The execution lifecycle: prepare, launch, complete, collect.
//!
//! One [`MarshExecutor`] owns the process-wide machinery an instrumented run needs — the probed
//! tracer, the lifetime-stable launcher thread it spawns through, and the
//! [`PersistenceLayer`] whose lease it holds — and hands out short-lived handles for the phases of
//! a single execution. The split is not decoration: a caller that snapshots storage has to resolve
//! the worker binary *before* it replaces a tree, and a caller that holds a read lease on that tree
//! has to release it *before* the fallible log parsing that [`CompletedExecution::collect`]
//! performs. Both boundaries are handle transitions here.
//!
//! The executor observes; it does not confine. There is no chroot and no namespace: a command that
//! writes outside `cwd` really writes there. The `/proc` sweeps below are opt-in ownership
//! operations keyed on markers this crate exports, not a containment mechanism.

use std::borrow::Cow;
use std::ffi::OsString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

use crate::error::ExecError;
use crate::evidence::ExecutionEvidence;
use crate::persistence::PersistenceLayer;
use crate::strace::{self, TraceIo, TracerSpawner};

/// Exit code reported for a command whose process group was killed outright.
const FORCED_EXIT_CODE: i32 = 137;

/// The instrumented-execution facility: a probed tracer, its stable launcher thread, and the
/// persistent storage every run is recorded against.
///
/// Building one costs a tracer probe, a thread and this session's exclusive lease, so it is created
/// once and kept for as long as executions run. A [`RunningExecution`] outliving its executor would
/// lose the launcher that owns its tracer's parent slot, and `strace --kill-on-exit` would take the
/// traced tree with it.
pub struct MarshExecutor {
    /// Worker binary as configured, or `None` to resolve one beside the current executable.
    worker: Option<PathBuf>,
    /// Wall-clock budget for one captured command ([`PreparedExecutor::run`]). Attached launches
    /// are untimed: their wait is the caller's.
    command_timeout: Duration,
    /// Stable launcher owning the configured tracer path.
    spawner: TracerSpawner,
    /// The seed and state directory this executor owns, holding their exclusive lease.
    ///
    /// Last, so the launcher and every other field release their resources before another process
    /// can acquire the session.
    persistence: PersistenceLayer,
}

impl MarshExecutor {
    /// Default wall-clock budget for one captured command.
    pub const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(30);

    /// Starts building an executor over `persistence`, which the built executor owns.
    #[must_use]
    pub const fn builder(persistence: PersistenceLayer) -> MarshExecutorBuilder {
        MarshExecutorBuilder {
            persistence,
            worker: None,
            tracer: None,
            command_timeout: Self::DEFAULT_CMD_TIMEOUT,
        }
    }

    /// The seed every execution runs against and the state directory beside it.
    #[must_use]
    pub const fn persistence(&self) -> &PersistenceLayer {
        &self.persistence
    }

    /// Resolves the worker binary, before any execution-specific state is committed to.
    ///
    /// Callers that replace or lease storage must do this first: a worker that cannot be found
    /// leaves whatever the previous execution produced exactly as it was.
    ///
    /// # Errors
    ///
    /// Fails when the current executable cannot be read, or when no worker sits beside it and none
    /// was configured.
    pub fn prepare(&self) -> Result<PreparedExecutor<'_>, ExecError> {
        // A configured path is used verbatim, existence included: the caller named this file, and
        // a probe here would only duplicate the spawn's own diagnostic.
        if let Some(path) = &self.worker {
            return Ok(PreparedExecutor {
                executor: self,
                worker: Cow::Borrowed(path.as_path()),
            });
        }
        let current = std::env::current_exe()
            .map_err(|error| ExecError::Exec(format!("current_exe: {error}")))?;
        let sibling = current
            .parent()
            .ok_or_else(|| ExecError::Exec("current executable has no directory".to_string()))?
            .join("marsh-exec");
        if !sibling.exists() {
            return Err(ExecError::Exec(format!(
                "{} not found; set the worker path with MarshExecutor::builder(..).worker(...)",
                sibling.display()
            )));
        }
        Ok(PreparedExecutor {
            executor: self,
            worker: Cow::Owned(sibling),
        })
    }

    /// Kills every leftover process marked as running under this executor's snapshot scope.
    ///
    /// Ownership is proven, never guessed: a candidate must share this process's effective uid,
    /// mount namespace and filesystem root, and must carry a [`crate::SNAPSHOT_ROOT_VAR`] marker
    /// naming a directory strictly below the owned scope. Identity is then pinned with a pidfd and
    /// rechecked, so a recycled pid cannot be signalled in another process's place.
    ///
    /// # Errors
    ///
    /// Fails when `/proc` cannot be scanned, when this kernel has no pidfd support, when a signal
    /// fails for a reason other than the process having ended, or when a signalled process does
    /// not exit before the shared deadline.
    pub fn terminate_orphans(&self) -> Result<(), ExecError> {
        strace::terminate_orphans(&self.persistence.snap())
    }

    /// Kills every process under this executor's snapshot scope that also carries `owner`'s
    /// marker, and waits for each to be gone.
    ///
    /// The quiescence half of a forced stop: the group signal has already been sent, and this is
    /// what proves the tree is over. `owner` is matched against [`crate::JOB_UID_VAR`] exactly, so
    /// one owner's sweep never takes another's processes with it.
    ///
    /// # Errors
    ///
    /// As [`Self::terminate_orphans`].
    pub fn terminate_owner(&self, owner: &str) -> Result<(), ExecError> {
        strace::terminate_owner(&self.persistence.snap(), owner)
    }
}

/// Configuration for one [`MarshExecutor`], around the persistence it will own.
pub struct MarshExecutorBuilder {
    /// The storage the built executor takes the lease on.
    persistence: PersistenceLayer,
    /// Worker binary override.
    worker: Option<PathBuf>,
    /// Tracer binary override.
    tracer: Option<PathBuf>,
    /// Wall-clock budget for one captured command.
    command_timeout: Duration,
}

impl MarshExecutorBuilder {
    /// Uses `path` as the worker binary instead of resolving one beside the current executable.
    #[must_use]
    pub fn worker(mut self, path: impl Into<PathBuf>) -> Self {
        self.worker = Some(path.into());
        self
    }

    /// Uses `path` as the tracer instead of `strace` from `PATH`.
    #[must_use]
    pub fn tracer(mut self, path: impl Into<PathBuf>) -> Self {
        self.tracer = Some(path.into());
        self
    }

    /// Bounds one captured command, replacing [`MarshExecutor::DEFAULT_CMD_TIMEOUT`].
    #[must_use]
    pub const fn command_timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Takes the persistence lease, probes the tracer and starts the launcher thread.
    ///
    /// The lease comes first: a competing owner must fail before this process reads, truncates or
    /// recovers anything under the state directory. No btrfs materialization is required, so an
    /// executor over ordinary directories builds and runs. The worker is *not* checked here: it is
    /// resolved per execution by [`MarshExecutor::prepare`], at the point a caller can still act on
    /// its absence.
    ///
    /// # Errors
    ///
    /// Fails when the session is already owned, when the tracer cannot be run or does not support
    /// `--kill-on-exit`, or when the launcher thread cannot be started. Any failure drops the
    /// layer, and with it the lease.
    pub fn build(mut self) -> Result<MarshExecutor, ExecError> {
        self.persistence.acquire()?;
        let tracer = self.tracer.unwrap_or_else(|| PathBuf::from("strace"));
        Ok(MarshExecutor {
            worker: self.worker,
            command_timeout: self.command_timeout,
            spawner: TracerSpawner::new(tracer)?,
            persistence: self.persistence,
        })
    }
}

/// What one execution is asked to do.
///
/// Every field is borrowed: the request is consumed by the launch that reads it, and nothing here
/// outlives the call. No shell parsing, no environment clearing, no storage management — `command`
/// reaches the worker's `-c` verbatim.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionRequest<'a> {
    /// The shell program the worker runs.
    pub command: &'a str,
    /// Working directory the command starts in.
    pub cwd: &'a Path,
    /// Environment entries added to the launch, in order.
    pub envs: &'a [(OsString, OsString)],
    /// Names this run's directory under the executor's own metadata, where both instrumentation
    /// logs are written. Exactly one plain path component.
    pub run_id: &'a str,
}

/// An executor with its worker binary resolved, ready for exactly one execution.
pub struct PreparedExecutor<'a> {
    /// The executor this borrows the tracer, launcher and persistence from.
    executor: &'a MarshExecutor,
    /// Resolved worker: borrowed when configured, owned when derived from `current_exe`.
    worker: Cow<'a, Path>,
}

impl PreparedExecutor<'_> {
    /// Runs `request` to completion with output captured, killing it after the executor's
    /// configured [`MarshExecutorBuilder::command_timeout`].
    ///
    /// Both pipes are drained on their own threads, so a command that fills a pipe buffer cannot
    /// deadlock against the wait. A command killed for exceeding its budget reports
    /// [`crate::TIMEOUT_EXIT_CODE`].
    ///
    /// # Errors
    ///
    /// Fails when the run id is not one plain component, when the log directory cannot be created,
    /// when the tracer cannot be spawned, or when the child cannot be waited for.
    pub fn run(self, request: ExecutionRequest<'_>) -> Result<CompletedExecution, ExecError> {
        let trace_log = self.prepare_logs(request.run_id)?;
        let spawn = strace::run_traced(
            &self.executor.spawner,
            &self.worker,
            request.command,
            request.cwd,
            request.envs,
            &trace_log,
            self.executor.command_timeout,
        )?;
        Ok(CompletedExecution {
            exit_code: spawn.exit_code,
            stdout: spawn.stdout,
            stderr: spawn.stderr,
            logs: ExecutionLogs {
                trace_log: spawn.trace_log,
                builtin_log: spawn.builtin_log,
            },
            forced: false,
        })
    }

    /// Launches `request` attached to the caller's terminal and returns without waiting.
    ///
    /// The command inherits stdin, stdout and stderr, and receives `instrumentation` on fd 3 — its
    /// third standard stream — or `/dev/null` when there is none. It is its own process group, so
    /// the caller can hand it the terminal and signal it. There is no wall-clock budget on this
    /// path: the wait is the caller's, and only its own `waitpid` can observe a job *stopping*
    /// rather than exiting.
    ///
    /// # Errors
    ///
    /// Fails when the run id is not one plain component, when the log directory cannot be created,
    /// or when the tracer cannot be spawned.
    pub fn start(
        self,
        request: ExecutionRequest<'_>,
        instrumentation: Option<RawFd>,
    ) -> Result<RunningExecution, ExecError> {
        self.spawn_attached(request, TraceIo::Terminal { instrumentation })
    }

    /// Launches `request` on a pseudoterminal the caller owns, and returns without waiting.
    ///
    /// `terminal` is the slave side of a PTY: the child's stdin, stdout and stderr, and the
    /// controlling terminal it establishes with `setsid`/`TIOCSCTTY`, so a full-screen program
    /// behaves exactly as it would under a real tty. `instrumentation` is its fd 3. Both
    /// descriptors are the caller's to close; the child receives duplicates.
    ///
    /// As with [`Self::start`], the wait is the caller's and there is no wall-clock budget.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    pub fn start_pty(
        self,
        request: ExecutionRequest<'_>,
        terminal: RawFd,
        instrumentation: RawFd,
    ) -> Result<RunningExecution, ExecError> {
        self.spawn_attached(
            request,
            TraceIo::Pty {
                terminal,
                instrumentation,
            },
        )
    }

    /// The shared body of the two attached launches: prepare the logs, spawn, and hand back the
    /// running execution.
    fn spawn_attached(
        self,
        request: ExecutionRequest<'_>,
        io: TraceIo,
    ) -> Result<RunningExecution, ExecError> {
        let trace_log = self.prepare_logs(request.run_id)?;
        let traced = strace::spawn_traced(
            &self.executor.spawner,
            &self.worker,
            request.command,
            request.cwd,
            request.envs,
            &trace_log,
            io,
        )?;
        Ok(RunningExecution {
            child: traced.child,
            pid: traced.pid,
            logs: ExecutionLogs {
                trace_log: traced.trace_log,
                builtin_log: traced.builtin_log,
            },
        })
    }

    /// Creates this run's log directory under the executor's persistence and returns the trace log
    /// path inside it.
    fn prepare_logs(&self, run_id: &str) -> Result<PathBuf, ExecError> {
        let run_dir = self.executor.persistence.run_dir(run_id)?;
        std::fs::create_dir_all(&run_dir)?;
        Ok(run_dir.join("trace.log"))
    }
}

/// A launched execution the caller owns the wait for.
#[derive(Debug)]
pub struct RunningExecution {
    /// The tracer process. Waited on only by [`Self::abandon`]: otherwise the caller owns the
    /// reap — only its own wait can observe a job *stopping* — and dropping a `Child` neither
    /// waits nor kills, so a handle to an already-reaped pid can never block anything.
    child: Child,
    /// Pid of the tracer, which is also the process-group id of the whole traced tree.
    pid: libc::pid_t,
    /// The two instrumentation logs being filled.
    logs: ExecutionLogs,
}

impl RunningExecution {
    /// Pid of the tracer, which is also the traced tree's process-group id: the group to hand the
    /// terminal to with `tcsetpgrp`, to signal with `kill(-pgid, …)`, and to reap with `waitpid`.
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    /// A descriptor that becomes readable when this execution's tracer has terminated.
    ///
    /// `pidfd_open(2)`: a caller waits on its reactor rather than on `SIGCHLD` or a thread, and
    /// because the descriptor names the process rather than the number, the pid cannot be handed
    /// out again until the caller reaps it — which the caller still owns. Readiness is the whole
    /// use; nothing is read from it. `libc` exposes the syscall number rather than a wrapper.
    ///
    /// # Errors
    ///
    /// Fails when the kernel refuses the descriptor: `ENOSYS` before Linux 5.3, or `EMFILE`.
    pub fn exit_fd(&self) -> std::io::Result<OwnedFd> {
        // SAFETY: `pidfd_open` takes two scalars and returns a new descriptor or -1.
        let opened = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0) };
        if opened < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let raw = libc::c_int::try_from(opened)
            .map_err(|_| std::io::Error::other("pidfd_open returned an out-of-range descriptor"))?;
        // SAFETY: the descriptor is fresh and nothing else refers to it.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    /// Kills and reaps an execution the caller cannot go on to observe.
    ///
    /// The one path that waits on the tracer here: a launch whose exit the caller could not
    /// arrange to be told about must not stay alive, and must not stay a zombie either. Blocks for
    /// the length of a `SIGKILL` landing.
    ///
    /// # Errors
    ///
    /// Fails when the group could not be signalled, or the tracer could not be waited for.
    pub fn abandon(mut self) -> Result<(), ExecError> {
        self.force_stop()?;
        self.child.wait()?;
        Ok(())
    }

    /// Kills this execution's whole process group.
    ///
    /// `SIGKILL` and nothing else: there is no term-then-kill delay to wait out and no `SIGCONT`
    /// step, because a stopped group is killed by `SIGKILL` as it stands. The tracer dies with the
    /// group, and `--kill-on-exit` takes its traced descendants with it; anything that escaped the
    /// group is [`MarshExecutor::terminate_owner`]'s to collect. A group that is already over
    /// (`ESRCH`) is success, and nothing here waits.
    ///
    /// # Errors
    ///
    /// Fails with [`ExecError::Io`] when the group could not be signalled.
    pub fn force_stop(&mut self) -> Result<(), ExecError> {
        // SAFETY: `kill` with a negated pid signals that process group; it has no memory-safety
        // requirements.
        if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(ExecError::Io(error));
            }
        }
        Ok(())
    }

    /// Consumes a reaped execution, given the raw `waitpid(2)` status of its *final* exit.
    ///
    /// A stop is not an exit: a job that stopped must be continued and waited for again before its
    /// status can conclude anything. Nothing is waited for here — the caller's own `waitpid`
    /// already reaped the pid — so this can never block on a process that is already gone.
    pub fn complete(self, wait_status: i32) -> CompletedExecution {
        CompletedExecution {
            exit_code: exit_code_of(wait_status),
            stdout: Vec::new(),
            stderr: Vec::new(),
            logs: self.logs,
            forced: false,
        }
    }

    /// Consumes an execution whose group was killed by [`Self::force_stop`].
    ///
    /// Its collection reports 137 and no evidence, and reads neither log: a partial trace may hold
    /// an earlier successful root exit record, and treating that as the command's status would
    /// report an aborted execution as a successful one.
    pub fn complete_forced(self) -> CompletedExecution {
        CompletedExecution {
            exit_code: FORCED_EXIT_CODE,
            stdout: Vec::new(),
            stderr: Vec::new(),
            logs: self.logs,
            forced: true,
        }
    }
}

/// An execution that is over, whose instrumentation has not been read yet.
///
/// Collection is a separate step because it is fallible and touches the filesystem: a caller
/// holding a lease on the tree the command ran in releases it here, between the wait and the read.
#[derive(Debug)]
pub struct CompletedExecution {
    /// Fallback status: the tracer's own exit code, or 137 for a forced stop.
    exit_code: i32,
    /// Captured stdout, empty on the attached path.
    stdout: Vec<u8>,
    /// Captured stderr, empty for the same reason.
    stderr: Vec<u8>,
    /// The two instrumentation logs.
    logs: ExecutionLogs,
    /// Whether the group was killed, in which case neither log is read.
    forced: bool,
}

impl CompletedExecution {
    /// Reads and decodes both instrumentation streams.
    ///
    /// A run that died before the tracer opened its output file — Ctrl-C right after Enter — has
    /// nothing to decode, so a missing trace alongside a non-zero fallback status yields no
    /// evidence. A run that *succeeded* without leaving a record is a different matter: an
    /// uninstrumented success must not be reported as instrumented, so that stays an error. A
    /// missing builtin dump is an empty builtin stream; a malformed present one is an error.
    ///
    /// # Errors
    ///
    /// Fails with [`ExecError::Io`] when a log cannot be read, and with [`ExecError::TraceParse`]
    /// when a present stream is malformed.
    pub fn collect(self) -> Result<ExecutionResult, ExecError> {
        if self.forced {
            return Ok(ExecutionResult {
                exit_code: self.exit_code,
                stdout: self.stdout,
                stderr: self.stderr,
                logs: self.logs,
                evidence: None,
            });
        }
        let trace_text = match std::fs::read_to_string(&self.logs.trace_log) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && self.exit_code != 0 => {
                return Ok(ExecutionResult {
                    exit_code: self.exit_code,
                    stdout: self.stdout,
                    stderr: self.stderr,
                    logs: self.logs,
                    evidence: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let builtin_text = match std::fs::read_to_string(&self.logs.builtin_log) {
            Ok(text) => text,
            // Only an abnormal exit leaves no dump, and such a run has already failed.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "[]".to_string(),
            Err(error) => return Err(error.into()),
        };
        let evidence = ExecutionEvidence::parse(&trace_text, &builtin_text)?;
        Ok(ExecutionResult {
            // The traced root's own exit record beats the tracer's exit code wherever it exists.
            exit_code: evidence.root_exit_code().unwrap_or(self.exit_code),
            stdout: self.stdout,
            stderr: self.stderr,
            logs: self.logs,
            evidence: Some(evidence),
        })
    }
}

/// Where one execution's instrumentation was written. Both files outlive the run: they are the
/// audit trail.
#[derive(Clone, Debug)]
pub struct ExecutionLogs {
    /// The syscall record.
    pub trace_log: PathBuf,
    /// The builtin record dump, absent when the run died before it could be written.
    pub builtin_log: PathBuf,
}

/// Everything one execution produced.
#[derive(Debug)]
pub struct ExecutionResult {
    /// The command's exit status.
    pub exit_code: i32,
    /// Captured stdout, empty on the attached path.
    pub stdout: Vec<u8>,
    /// Captured stderr, empty for the same reason.
    pub stderr: Vec<u8>,
    /// Where the instrumentation was retained.
    pub logs: ExecutionLogs,
    /// What the command was observed to do, absent when a failed run left no trace.
    pub evidence: Option<ExecutionEvidence>,
}

/// The exit code a raw `waitpid(2)` status reports, in the shell's convention.
///
/// A signalled command reports `128 + signal`, which is what lands a Ctrl-C'd job on 130. A status
/// that is neither an exit nor a death (a stop, which the caller is not supposed to conclude on)
/// reports `-1`, the same "not a success" every consumer reads.
const fn exit_code_of(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;

    /// A completed execution pointing at `directory`, with no logs written yet.
    fn completed(directory: &Path, exit_code: i32) -> CompletedExecution {
        CompletedExecution {
            exit_code,
            stdout: Vec::new(),
            stderr: Vec::new(),
            logs: ExecutionLogs {
                trace_log: directory.join("trace.log"),
                builtin_log: directory.join("builtins.json"),
            },
            forced: false,
        }
    }

    /// A running execution over `command`, launched as its own process group so `kill(-pid, …)`
    /// reaches exactly it — which is what the tracer's spawn arranges for a real launch.
    fn running(command: &mut Command) -> RunningExecution {
        command.process_group(0);
        let child = command.spawn().expect("spawn the child");
        let pid = libc::pid_t::try_from(child.id()).expect("a pid fits");
        RunningExecution {
            child,
            pid,
            logs: ExecutionLogs {
                trace_log: PathBuf::new(),
                builtin_log: PathBuf::new(),
            },
        }
    }

    #[test]
    fn a_missing_trace_is_an_error_only_when_the_run_succeeded() {
        let directory = tempfile::tempdir().expect("scratch directory");
        let error = completed(directory.path(), 0)
            .collect()
            .expect_err("an uninstrumented success must not be reported as instrumented");
        assert!(
            matches!(&error, ExecError::Io(io) if io.kind() == std::io::ErrorKind::NotFound),
            "got {error:?}"
        );

        let result = completed(directory.path(), 1)
            .collect()
            .expect("a failed run may leave no trace at all");
        assert_eq!(result.exit_code, 1);
        assert!(result.evidence.is_none(), "and reports no evidence");
    }

    #[test]
    fn a_malformed_builtin_dump_is_a_parse_error() {
        let directory = tempfile::tempdir().expect("scratch directory");
        std::fs::write(
            directory.path().join("trace.log"),
            "10  1788295173.846003 execve(\"/exec/marsh-exec\", [\"marsh-exec\"], 0x7ffd) = 0\n",
        )
        .expect("trace log");
        std::fs::write(directory.path().join("builtins.json"), "{\"k\":\"b\"}")
            .expect("builtin dump");
        let error = completed(directory.path(), 0)
            .collect()
            .expect_err("a present dump must parse");
        assert!(
            matches!(&error, ExecError::TraceParse(message) if message.contains("builtin record dump")),
            "got {error:?}"
        );
    }

    #[test]
    fn the_traced_roots_exit_record_beats_the_fallback_status() {
        let directory = tempfile::tempdir().expect("scratch directory");
        std::fs::write(
            directory.path().join("trace.log"),
            "10  1788295173.846003 execve(\"/exec/marsh-exec\", [\"marsh-exec\"], 0x7ffd) = 0\n\
             10  1788295173.846009 +++ exited with 3 +++\n",
        )
        .expect("trace log");
        let result = completed(directory.path(), 0).collect().expect("collect");
        assert_eq!(result.exit_code, 3);
        assert_eq!(
            result
                .evidence
                .as_ref()
                .and_then(ExecutionEvidence::root_exit_code),
            Some(3)
        );
        assert_eq!(
            result.evidence.expect("evidence").events().len(),
            2,
            "a missing builtin dump is an empty builtin stream, not a failure"
        );
    }

    #[test]
    fn a_forced_completion_reads_neither_log() {
        let directory = tempfile::tempdir().expect("scratch directory");
        std::fs::write(
            directory.path().join("trace.log"),
            "10  1788295173.846003 execve(\"/exec/marsh-exec\", [\"marsh-exec\"], 0x7ffd) = 0\n\
             10  1788295173.846009 +++ exited with 0 +++\n",
        )
        .expect("trace log");
        let mut forced = completed(directory.path(), 0);
        forced.exit_code = FORCED_EXIT_CODE;
        forced.forced = true;
        let result = forced.collect().expect("collect");
        assert_eq!(result.exit_code, FORCED_EXIT_CODE);
        assert!(
            result.evidence.is_none(),
            "an earlier successful root record is not permission to conclude a killed command"
        );
    }

    /// The exit descriptor reports the tracer ending without reaping it, so the caller's own wait
    /// still observes the status — the ownership the mux's per-command watcher is built on.
    #[test]
    fn the_exit_descriptor_reports_the_end_and_leaves_the_reap_to_the_caller() {
        let mut running = running(&mut Command::new("true"));
        let exit = running.exit_fd().expect("pidfd_open");
        let mut entry = libc::pollfd {
            fd: exit.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` reads one valid entry for the length of the call.
        let ready = unsafe { libc::poll(&raw mut entry, 1, 10_000) };
        assert_eq!(
            ready,
            1,
            "the descriptor became readable: {}",
            std::io::Error::last_os_error()
        );
        let status = running
            .child
            .wait()
            .expect("the caller still owns the reap")
            .into_raw();
        assert_eq!(running.complete(status).exit_code, 0);
    }

    /// Abandoning kills the group and reaps the tracer promptly: a command nobody could watch is
    /// neither left running nor left a zombie.
    #[test]
    fn abandon_kills_and_reaps_promptly() {
        let started = std::time::Instant::now();
        let mut command = Command::new("sleep");
        command.arg("30");
        running(&mut command).abandon().expect("kill and reap");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the group was killed rather than waited out"
        );
    }

    /// A group that is already over is not an error to stop: `ESRCH` is success.
    #[test]
    fn force_stop_of_a_finished_group_is_success() {
        let mut running = running(&mut Command::new("true"));
        running.child.wait().expect("reap the child");
        running
            .force_stop()
            .expect("a finished group is already stopped");
    }
}
