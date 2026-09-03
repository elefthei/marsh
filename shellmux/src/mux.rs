//! The multiplexer: one seed, many principals, one atomic transaction per command.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use rust_validator::{Bump, Event, GitPolicy, Principal};

use crate::authority::{AuthorityState, check_events};
use crate::diff::{MergeOp, diff_trees};
use crate::error::MuxError;
use crate::hooks;
use crate::snapshot;
use crate::strace::{self, parse_trace};
use crate::translate::translate;
use crate::wal::{self, WalEvent, WalOp, WalRecord, WalWriter};

/// Default wall-clock budget for one traced command.
const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(30);

/// Fixed timestamp used for every commit the mux produces.
///
/// Commit hashes are a function of tree, parents, message, author and committer — including their
/// timestamps. Pinning the timestamp makes a merged history reproducible: replaying the same merged
/// commands serially yields byte-identical commit objects, which is what lets the tests compare a
/// concurrent run against its serial ground truth by `rev-parse HEAD`.
///
/// The value is git's raw `<epoch> <±HHMM>` date form (the same instant as
/// `2005-04-07T22:13:13 +0000`), which is what [`crate::gitexec`] parses out of the environment.
const FIXED_GIT_DATE: &str = "1112911993 +0000";

/// Tunable paths and limits.
pub struct MuxOptions {
    /// Executor binary; defaults to `marsh-exec` beside the current executable.
    pub executor: Option<PathBuf>,
    /// Tracer binary; defaults to `strace` from `PATH`.
    pub strace: Option<PathBuf>,
    /// Wall-clock budget for one command. Applies to [`ShellMux::run_cmd`] only: a console job
    /// started with [`ShellMux::start_cmd`] is waited for by the front-end, which ends it on the
    /// user's Ctrl-C or in its exit sweep instead of on a clock.
    pub cmd_timeout: Duration,
}

impl Default for MuxOptions {
    fn default() -> Self {
        Self {
            executor: None,
            strace: None,
            cmd_timeout: DEFAULT_CMD_TIMEOUT,
        }
    }
}

/// One capability the policy refused, with the reason and the way out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapDenial {
    /// The capability that was requested.
    pub event: Event,
    /// The precondition it failed, naming the conflicting history.
    pub failed_precondition: String,
    /// State-changing actions that would make the request legal.
    pub allowed_fixes: Vec<String>,
}

/// A path whose contents moved on after this command took its snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StalePath {
    /// Seed-relative, `/`-joined path.
    pub path: String,
    /// Sequence number of the merge that won the race for it.
    pub merged_seq: u64,
}

/// What became of one submitted command.
#[derive(Debug)]
pub enum CmdOutcome {
    /// The command's capabilities were granted and its changes are in the seed.
    Merged {
        /// Sequence number the merge occupies.
        seq: u64,
        /// Exit status of the command.
        exit_code: i32,
        /// Captured stdout.
        stdout: Vec<u8>,
        /// Captured stderr.
        stderr: Vec<u8>,
        /// Capabilities the policy granted, in request order.
        granted: Vec<Event>,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
    /// At least one capability was refused; nothing was merged.
    DeniedCaps {
        /// Exit status of the command (it *ran*; only the merge was refused).
        exit_code: i32,
        /// Captured stdout.
        stdout: Vec<u8>,
        /// Captured stderr.
        stderr: Vec<u8>,
        /// Every capability the command requested.
        requested: Vec<Event>,
        /// Every capability that was refused, with its reason and fixes.
        denials: Vec<CapDenial>,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
    /// Another principal merged one of this command's paths first; rerun it.
    StaleSnapshot {
        /// Capabilities the command would have requested.
        requested: Vec<Event>,
        /// The paths that moved on, and who won them.
        stale: Vec<StalePath>,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
    /// The command itself failed; it is rolled back wholesale.
    ExecFailed {
        /// Non-zero exit status.
        exit_code: i32,
        /// Captured stdout.
        stdout: Vec<u8>,
        /// Captured stderr.
        stderr: Vec<u8>,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
    /// The command cannot be expressed as capabilities, so it cannot be authorized.
    Unsupported {
        /// What could not be translated.
        reason: String,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
}

/// One spawned, not-yet-concluded transaction.
///
/// The snapshot and spawn phases are done and the command is running, attached to the caller's
/// terminal. The caller owns the wait — it must, because only its own `waitpid` can tell a job that
/// *stopped* from one that exited — and hands the raw `waitpid(2)` status back to
/// [`ShellMux::conclude_cmd`], which performs the remaining phases.
pub struct StartedCmd {
    /// The tracer process and the two instrumentation logs it is filling.
    traced: strace::TracedChild,
    /// Reference snapshot the command's diff is taken against.
    base: PathBuf,
    /// Snapshot the command is running in.
    work: PathBuf,
    /// Seed version both snapshots copied; staleness is measured against it.
    base_seq: u64,
    /// Principal the capabilities will be requested as.
    principal: Principal,
    /// The submitted command line, recorded in the log's intent record.
    cmd: String,
}

impl StartedCmd {
    /// Pid of the traced child, which is also its process-group id: the group to hand the terminal
    /// to with `tcsetpgrp`, to signal with `kill(-pgid, …)`, and to reap with `waitpid`.
    pub fn pid(&self) -> i32 {
        self.traced.pid
    }
}

/// A principal's shell: the source of the environment its commands run with.
///
/// The shell is not the thing that executes: execution happens in a spawned `marsh-exec` so it can
/// be traced. What the retained shell provides is the principal's exported environment, which is why
/// a per-principal shell is meaningful at all.
struct PrincipalShell {
    /// The principal's brush shell.
    _shell: brush_core::Shell,
    /// Environment handed to every command this principal runs.
    envs: Vec<(OsString, OsString)>,
}

/// A btrfs-snapshotted, strace-audited, capability-gated shell multiplexer over one seed repository.
pub struct ShellMux {
    /// Mux root; holds the seed subvolume and `.marsh/`.
    root: PathBuf,
    /// The seed subvolume: the merge target, and the tree every snapshot copies.
    seed: PathBuf,
    /// Tunables.
    options: MuxOptions,
    /// The authority. A read lock quiesces the seed for snapshotting; the write lock serializes
    /// merges.
    state: RwLock<AuthorityState>,
    /// Per-principal shells, created on first use.
    shells: Mutex<HashMap<Principal, PrincipalShell>>,
    /// Runtime used only to build shells; brush's builder is async.
    runtime: tokio::runtime::Runtime,
    /// Monotonic run identifier, unique per mux root across restarts.
    run_counter: AtomicU64,
}

impl ShellMux {
    /// Creates a fresh mux at `root`, initializing the seed with `seed_init` and committing it.
    ///
    /// `root` must be on btrfs. The seed is committed even when `seed_init` writes nothing
    /// (`--allow-empty`), so every mux starts from a real `HEAD` that `git checkout HEAD -- p` and
    /// `git stash push` can restore from.
    pub fn create(
        root: &Path,
        options: MuxOptions,
        seed_init: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<Self, MuxError> {
        std::fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        snapshot::assert_btrfs(&root)?;
        let seed = root.join("seed");
        if seed.exists() {
            return Err(MuxError::Snapshot(format!(
                "{} already exists; use ShellMux::open",
                seed.display()
            )));
        }
        std::fs::create_dir_all(root.join(".marsh/snaps"))?;
        std::fs::create_dir_all(root.join(".marsh/runs"))?;
        snapshot::create_subvolume(&seed)?;
        seed_init(&seed)?;
        init_seed_repository(&seed)?;

        let wal = WalWriter::open(&root)?;
        Self::assemble(
            root,
            seed,
            options,
            AuthorityState {
                history: Vec::new(),
                generations: HashMap::new(),
                seq: 0,
                wal,
            },
            0,
        )
    }

    /// Opens an existing mux, replaying the write-ahead log and sweeping dead runs.
    ///
    /// Replaying the log is how a crash mid-merge is repaired; sweeping is how the snapshots of
    /// commands that were in flight when the process died are reclaimed — none of them can still
    /// merge, because a merge only survives a crash by being in the log.
    pub fn open(root: &Path, options: MuxOptions) -> Result<Self, MuxError> {
        let root = root.canonicalize()?;
        snapshot::assert_btrfs(&root)?;
        let seed = root.join("seed");
        if !snapshot::is_subvolume(&seed) {
            return Err(MuxError::Snapshot(format!(
                "{} is not a subvolume; not a mux root",
                seed.display()
            )));
        }

        let recovered = wal::recover(&root, &seed)?;
        sweep_snapshots(&root)?;
        sweep_temporaries(&seed)?;

        let next_run = next_run_id(&root)?;
        let wal = WalWriter::open(&root)?;
        Self::assemble(
            root,
            seed,
            options,
            AuthorityState {
                history: recovered.history,
                generations: recovered.generations,
                seq: recovered.seq,
                wal,
            },
            next_run,
        )
    }

    /// Builds the mux value around already-prepared state.
    fn assemble(
        root: PathBuf,
        seed: PathBuf,
        options: MuxOptions,
        state: AuthorityState,
        next_run: u64,
    ) -> Result<Self, MuxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|error| MuxError::Brush(format!("tokio runtime: {error}")))?;
        Ok(Self {
            root,
            seed,
            options,
            state: RwLock::new(state),
            shells: Mutex::new(HashMap::new()),
            runtime,
            run_counter: AtomicU64::new(next_run),
        })
    }

    /// The seed directory: the merge target and the tree principals share.
    pub fn seed_dir(&self) -> &Path {
        &self.seed
    }

    /// The committed capability history, in merge order.
    pub fn history(&self) -> Vec<Event> {
        self.state
            .read()
            .expect("authority lock is never poisoned by design")
            .history
            .clone()
    }

    /// Runs one command as `principal`, as a single atomic transaction against the seed.
    ///
    /// The phases are snapshot, execute, translate, authorize, merge. Only the first and last take a
    /// lock: snapshotting holds the *read* lock so both snapshots see one quiescent seed while other
    /// principals snapshot and execute in parallel, and merging holds the *write* lock so staleness,
    /// policy and log append are one serialization point.
    pub fn run_cmd(&self, principal: &Principal, cmd: &str) -> Result<CmdOutcome, MuxError> {
        let run_id = self.run_counter.fetch_add(1, Ordering::Relaxed);
        let executor = self.executor_path()?;
        let tracer = self
            .options
            .strace
            .clone()
            .unwrap_or_else(|| PathBuf::from("strace"));
        let envs = self.principal_envs(principal)?;

        let base = self
            .root
            .join(".marsh/snaps")
            .join(format!("base-{run_id}"));
        let work = self
            .root
            .join(".marsh/snaps")
            .join(format!("work-{run_id}"));
        let trace_log = self
            .root
            .join(".marsh/runs")
            .join(run_id.to_string())
            .join("trace.log");

        // Snapshot phase. The read lock excludes merges, so `base` and `work` are copies of the same
        // quiescent seed, and `base_seq` names exactly the version they copied.
        let base_seq = {
            let guard = self
                .state
                .read()
                .expect("authority lock is never poisoned by design");
            snapshot::snapshot(&self.seed, &base).and_then(|()| {
                snapshot::snapshot(&self.seed, &work).inspect_err(|_| {
                    let _ = snapshot::delete_subvolume(&base);
                })
            })?;
            guard.seq
        };

        let outcome = self.run_in_snapshot(
            principal, cmd, &executor, &tracer, &envs, &base, &work, &trace_log, base_seq,
        );

        let _ = snapshot::delete_subvolume(&work);
        let _ = snapshot::delete_subvolume(&base);
        outcome
    }

    /// Takes the snapshots and spawns one command as `principal` attached to the caller's terminal,
    /// without waiting for it.
    ///
    /// The first half of [`Self::run_cmd`]'s transaction, for a front-end that needs the command to
    /// *be* the user's foreground job: it inherits the real terminal and the real environment —
    /// which is what makes a full-screen program work — and it is its own process group, so the
    /// front-end can hand it the terminal and signal it. `instrumentation` is the descriptor the
    /// child receives on fd 3, its third standard stream; `None` gets `/dev/null`. There is no
    /// wall-clock budget on this path: the wait, and with it every timeout policy, is the caller's.
    pub fn start_cmd(
        &self,
        principal: &Principal,
        cmd: &str,
        instrumentation: Option<RawFd>,
    ) -> Result<StartedCmd, MuxError> {
        let run_id = self.run_counter.fetch_add(1, Ordering::Relaxed);
        let executor = self.executor_path()?;
        let tracer = self
            .options
            .strace
            .clone()
            .unwrap_or_else(|| PathBuf::from("strace"));
        let envs = self.principal_envs(principal)?;

        let base = self
            .root
            .join(".marsh/snaps")
            .join(format!("base-{run_id}"));
        let work = self
            .root
            .join(".marsh/snaps")
            .join(format!("work-{run_id}"));
        let trace_log = self
            .root
            .join(".marsh/runs")
            .join(run_id.to_string())
            .join("trace.log");

        // Snapshot phase, exactly as in `run_cmd`: the read lock excludes merges, so `base` and
        // `work` are copies of one quiescent seed and `base_seq` names the version they copied.
        let base_seq = {
            let guard = self
                .state
                .read()
                .expect("authority lock is never poisoned by design");
            snapshot::snapshot(&self.seed, &base).and_then(|()| {
                snapshot::snapshot(&self.seed, &work).inspect_err(|_| {
                    let _ = snapshot::delete_subvolume(&base);
                })
            })?;
            guard.seq
        };

        match strace::spawn_traced(
            &tracer,
            &executor,
            cmd,
            &work,
            &envs,
            &trace_log,
            strace::TraceIo::Terminal { instrumentation },
        ) {
            Ok(traced) => Ok(StartedCmd {
                traced,
                base,
                work,
                base_seq,
                principal: principal.clone(),
                cmd: cmd.to_string(),
            }),
            // Nothing ran, so nothing will ever conclude and free the pair; without this the
            // snapshots would linger until the next `ShellMux::open` swept them.
            Err(error) => {
                let _ = snapshot::delete_subvolume(&work);
                let _ = snapshot::delete_subvolume(&base);
                Err(error)
            }
        }
    }

    /// Concludes a command the caller has already reaped: translate, authorize, merge, and destroy
    /// both snapshots.
    ///
    /// `status` is the raw `waitpid(2)` status of the command's *final* exit. A stop is not an exit:
    /// a job that stopped must be continued and waited for again before its status can conclude
    /// anything. Nothing was captured on this path — the job's output went straight to the
    /// terminal, live — so the outcome's `stdout`/`stderr` are empty and the retained trace log is
    /// the record of what happened.
    pub fn conclude_cmd(&self, started: StartedCmd, status: i32) -> Result<CmdOutcome, MuxError> {
        let StartedCmd {
            traced,
            base,
            work,
            base_seq,
            principal,
            cmd,
        } = started;
        // The process handle is dropped right here: the caller's `waitpid` already reaped the pid,
        // and dropping a `Child` neither waits nor kills, so nothing can block on a pid that is
        // already gone.
        let strace::TracedChild {
            trace_log,
            builtin_log,
            ..
        } = traced;
        let spawn = strace::TraceSpawn {
            exit_code: exit_code_of(status),
            stdout: Vec::new(),
            stderr: Vec::new(),
            trace_log,
            builtin_log,
        };

        let outcome = self.conclude(&principal, &cmd, spawn, &base, &work, base_seq);

        let _ = snapshot::delete_subvolume(&work);
        let _ = snapshot::delete_subvolume(&base);
        outcome
    }

    /// Executes, translates, authorizes and merges. Snapshots are created and destroyed by the
    /// caller, so every early return here is safe.
    #[expect(
        clippy::too_many_arguments,
        reason = "one linear pipeline; grouping its inputs into a struct would only rename them"
    )]
    fn run_in_snapshot(
        &self,
        principal: &Principal,
        cmd: &str,
        executor: &Path,
        tracer: &Path,
        envs: &[(OsString, OsString)],
        base: &Path,
        work: &Path,
        trace_log: &Path,
        base_seq: u64,
    ) -> Result<CmdOutcome, MuxError> {
        let spawn = strace::run_traced(
            tracer,
            executor,
            cmd,
            work,
            envs,
            trace_log,
            self.options.cmd_timeout,
        )?;
        self.conclude(principal, cmd, spawn, base, work, base_seq)
    }

    /// Translates the recorded streams, authorizes the capabilities, and merges — the half of a
    /// transaction that happens once the command has exited.
    ///
    /// Split from the execution half because the two front-ends reach it by different routes: the
    /// batch path captures a [`strace::TraceSpawn`] from a completed `run_traced`, while the console
    /// path waits itself and synthesizes one from a raw wait status.
    fn conclude(
        &self,
        principal: &Principal,
        cmd: &str,
        spawn: strace::TraceSpawn,
        base: &Path,
        work: &Path,
        base_seq: u64,
    ) -> Result<CmdOutcome, MuxError> {
        let work_root = work.canonicalize()?;
        let text = match std::fs::read_to_string(&spawn.trace_log) {
            Ok(text) => text,
            // A job signalled at the moment it started — Ctrl-C right after Enter — can die before
            // the tracer opens its output file. There is nothing to translate and nothing may
            // merge, so it is reported as the failed execution it is. A command that *succeeded*
            // without leaving a record is a different matter entirely: an un-instrumented run must
            // never merge, so the missing log stays an error.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && spawn.exit_code != 0 => {
                return Ok(CmdOutcome::ExecFailed {
                    exit_code: spawn.exit_code,
                    stdout: spawn.stdout,
                    stderr: spawn.stderr,
                    trace_log: spawn.trace_log,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let lines = parse_trace(&text)?;
        let records = match std::fs::read_to_string(&spawn.builtin_log) {
            Ok(text) => hooks::parse_records(&text)?,
            // Only an abnormal exit (the timeout SIGKILL) leaves no dump, and such a run takes the
            // `ExecFailed` path below before any event or merge could matter.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let translation = translate(&lines, &records, principal, &work_root);
        let exit_code = translation.exit_code.unwrap_or(spawn.exit_code);

        if let Some(reason) = translation.unsupported {
            return Ok(CmdOutcome::Unsupported {
                reason,
                trace_log: spawn.trace_log,
            });
        }
        // A failed command is rolled back wholesale: its partial writes stay in the discarded
        // snapshot and it requests no capabilities. Half of a failed command is not a transaction.
        if exit_code != 0 {
            return Ok(CmdOutcome::ExecFailed {
                exit_code,
                stdout: spawn.stdout,
                stderr: spawn.stderr,
                trace_log: spawn.trace_log,
            });
        }

        let ops = diff_trees(base, &work_root)?;
        if translation.events.is_empty() && ops.is_empty() {
            // Nothing observed and nothing changed: recording it would only grow the log.
            return Ok(CmdOutcome::Merged {
                seq: base_seq,
                exit_code,
                stdout: spawn.stdout,
                stderr: spawn.stderr,
                granted: Vec::new(),
                trace_log: spawn.trace_log,
            });
        }

        let wal_ops: Vec<WalOp> = ops.iter().map(WalOp::from).collect();
        let mut guard = self
            .state
            .write()
            .expect("authority lock is never poisoned by design");

        // Optimistic concurrency over the union of the read set and the write set: any path this
        // command depended on or intends to write that has moved on since `base_seq` invalidates it.
        // The read set includes what git *observed* — `.git/index`, `HEAD`, refs — which is how a
        // command that wrote nothing still declares what it decided from.
        let stale = stale_paths(
            &guard.generations,
            base_seq,
            &ops,
            &translation.events,
            &translation.git_reads,
        );
        if !stale.is_empty() {
            return Ok(CmdOutcome::StaleSnapshot {
                requested: translation.events,
                stale,
                trace_log: spawn.trace_log,
            });
        }

        // A fresh arena and policy per merge: `GitPolicy` borrows its arena and is `!Send`, and
        // compiling the rule set costs microseconds against a traced command's tens of milliseconds.
        let arena = Bump::new();
        let mut policy = GitPolicy::new(&arena);
        let committed = guard.history.len();
        let denials = check_events(&mut policy, &mut guard.history, &translation.events);
        if !denials.is_empty() {
            guard.history.truncate(committed);
            return Ok(CmdOutcome::DeniedCaps {
                exit_code,
                stdout: spawn.stdout,
                stderr: spawn.stderr,
                requested: translation.events,
                denials,
                trace_log: spawn.trace_log,
            });
        }

        let seq = guard.seq + 1;
        let work_snapshot = work
            .strip_prefix(&self.root)
            .unwrap_or(work)
            .to_string_lossy()
            .into_owned();
        let intent = WalRecord::Intent {
            seq,
            principal: principal.to_string(),
            cmd: cmd.to_string(),
            work_snapshot,
            events: translation.events.iter().map(WalEvent::from).collect(),
            ops: wal_ops.clone(),
        };
        // Intent first, then the seed, then Commit. Every crash window in that order is repairable;
        // any other order can lose or double-apply a merge.
        guard.wal.append(&intent)?;
        wal::apply_ops(&self.seed, &work_root, &wal_ops)?;
        guard.wal.append(&WalRecord::Commit { seq })?;
        guard.seq = seq;
        for op in &wal_ops {
            guard.generations.insert(op.path().to_string(), seq);
        }

        Ok(CmdOutcome::Merged {
            seq,
            exit_code,
            stdout: spawn.stdout,
            stderr: spawn.stderr,
            granted: translation.events,
            trace_log: spawn.trace_log,
        })
    }

    /// Resolves the executor binary, defaulting to `marsh-exec` beside the running executable.
    fn executor_path(&self) -> Result<PathBuf, MuxError> {
        if let Some(path) = &self.options.executor {
            return Ok(path.clone());
        }
        let current = std::env::current_exe()
            .map_err(|error| MuxError::Exec(format!("current_exe: {error}")))?;
        let sibling = current
            .parent()
            .ok_or_else(|| MuxError::Exec("current executable has no directory".to_string()))?
            .join("marsh-exec");
        if sibling.exists() {
            Ok(sibling)
        } else {
            Err(MuxError::Exec(format!(
                "{} not found; set MuxOptions::executor",
                sibling.display()
            )))
        }
    }

    /// Returns the environment for `principal`, creating its shell on first use.
    fn principal_envs(&self, principal: &Principal) -> Result<Vec<OsString2>, MuxError> {
        let mut shells = self
            .shells
            .lock()
            .expect("shell map lock is never poisoned by design");
        if let Some(existing) = shells.get(principal) {
            return Ok(existing.envs.clone());
        }
        let shell = self
            .runtime
            .block_on(
                brush_core::Shell::builder()
                    .interactive(false)
                    .no_editing(true)
                    .profile(brush_core::ProfileLoadBehavior::Skip)
                    .rc(brush_core::RcLoadBehavior::Skip)
                    .build(),
            )
            .map_err(|error| MuxError::Brush(error.to_string()))?;

        let mut envs: Vec<(OsString, OsString)> = shell
            .env()
            .iter_exported()
            .filter(|(_, variable)| variable.value().is_set())
            .map(|(name, variable)| {
                (
                    OsString::from(name),
                    OsString::from(variable.value().to_cow_str(&shell).into_owned()),
                )
            })
            .collect();
        envs.extend(git_env(principal));

        shells.insert(
            principal.clone(),
            PrincipalShell {
                _shell: shell,
                envs: envs.clone(),
            },
        );
        Ok(envs)
    }
}

/// Alias keeping the environment pair type readable in signatures.
type OsString2 = (OsString, OsString);

/// The exit code a raw `waitpid(2)` status reports, in the shell's convention.
///
/// A signalled command reports `128 + signal`, which is what lands a Ctrl-C'd job on 130: non-zero,
/// so the transaction rolls back wholesale like any other failure. A status that is neither an exit
/// nor a death (a stop, which the caller is not supposed to conclude on) reports `-1`, the same
/// "not a success" the rest of the pipeline reads.
fn exit_code_of(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

/// Paths whose last writer merged after `base_seq`.
///
/// The check covers the write set (the diff's operations) *and* the read set: every event's resource
/// plus every path a git builtin was observed reading. A command that read a path someone else has
/// since rewritten computed its result from stale input, even if it wrote nothing there — and for a
/// git command the decisive input is often `.git/index` or `HEAD`, which no event names.
fn stale_paths(
    generations: &HashMap<String, u64>,
    base_seq: u64,
    ops: &[MergeOp],
    events: &[Event],
    git_reads: &[String],
) -> Vec<StalePath> {
    let mut checked: Vec<String> = ops
        .iter()
        .map(|op| match op {
            MergeOp::Write(path) | MergeOp::Remove(path) => path.clone(),
        })
        .collect();
    checked.extend(
        events
            .iter()
            .map(|event| event.resource.segments().join("/")),
    );
    checked.extend(git_reads.iter().cloned());
    checked.sort();
    checked.dedup();

    checked
        .into_iter()
        .filter_map(|path| {
            generations
                .get(&path)
                .filter(|merged| **merged > base_seq)
                .map(|merged| StalePath {
                    path,
                    merged_seq: *merged,
                })
        })
        .collect()
}

/// The deterministic git environment every command runs with.
///
/// Identity comes from the principal, so `git log` attributes a merge to whoever earned the
/// capability. Dates are pinned and configuration files are cut off (`GIT_CONFIG_NOSYSTEM`,
/// `GIT_CONFIG_GLOBAL=/dev/null`) so that a command's effect depends on the seed and the command
/// alone — never on the host user's git configuration.
fn git_env(principal: &Principal) -> Vec<(OsString, OsString)> {
    let name = principal.to_string();
    let email = format!("{name}@marsh.local");
    [
        ("GIT_AUTHOR_NAME", name.clone()),
        ("GIT_AUTHOR_EMAIL", email.clone()),
        ("GIT_AUTHOR_DATE", FIXED_GIT_DATE.to_string()),
        ("GIT_COMMITTER_NAME", name),
        ("GIT_COMMITTER_EMAIL", email),
        ("GIT_COMMITTER_DATE", FIXED_GIT_DATE.to_string()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_string()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_string()),
        ("GIT_PAGER", "cat".to_string()),
        ("GIT_TERMINAL_PROMPT", "0".to_string()),
        ("LC_ALL", "C".to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
    .collect()
}

/// Initializes the seed as a git repository with one commit.
pub(crate) fn init_seed_repository(seed: &Path) -> Result<(), MuxError> {
    let seed_principal = Principal::from("seed");
    let env = git_env(&seed_principal);
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["add", "-A"],
        vec!["commit", "-q", "--allow-empty", "-m", "seed"],
    ] {
        let output = std::process::Command::new("git")
            .args(&args)
            .current_dir(seed)
            .envs(env.iter().cloned())
            .output()
            .map_err(|error| MuxError::GitSetup(format!("git {}: {error}", args[0])))?;
        if !output.status.success() {
            return Err(MuxError::GitSetup(format!(
                "git {} failed ({}): {}",
                args[0],
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }
    Ok(())
}

/// Deletes every snapshot under `.marsh/snaps/`. Called only from [`ShellMux::open`], after
/// recovery has already consumed any snapshot a pending merge needed.
fn sweep_snapshots(root: &Path) -> Result<(), MuxError> {
    let snaps = root.join(".marsh/snaps");
    if !snaps.exists() {
        std::fs::create_dir_all(&snaps)?;
        return Ok(());
    }
    for entry in std::fs::read_dir(&snaps)? {
        let path = entry?.path();
        if path.is_dir() {
            snapshot::delete_subvolume(&path)?;
        }
    }
    Ok(())
}

/// Removes `*.tmp-wal` files a crash may have left mid-merge. They are unreferenced by definition:
/// a merge either renamed its temporary into place or never completed.
fn sweep_temporaries(seed: &Path) -> Result<(), MuxError> {
    let mut stack = vec![seed.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".tmp-wal"))
            {
                std::fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// Next unused run identifier, so reopening a mux never overwrites a retained trace log.
fn next_run_id(root: &Path) -> Result<u64, MuxError> {
    let runs = root.join(".marsh/runs");
    if !runs.exists() {
        std::fs::create_dir_all(&runs)?;
        return Ok(0);
    }
    let mut next = 0;
    for entry in std::fs::read_dir(&runs)? {
        if let Some(id) = entry?
            .file_name()
            .to_string_lossy()
            .parse::<u64>()
            .ok()
            .map(|id| id + 1)
        {
            next = next.max(id);
        }
    }
    Ok(next)
}
