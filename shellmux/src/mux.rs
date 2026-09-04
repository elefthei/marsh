//! The multiplexer: one seed, many sandboxes, one atomic transaction per command.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_validator::{Bump, Event, GitPolicy, Principal};

use crate::authority::{AuthorityState, check_events};
use crate::commit;
use crate::diff::{CommitOp, diff_trees};
use crate::error::MuxError;
use crate::gitshell;
use crate::history;
use crate::hooks;
use crate::ids;
use crate::session::Session;
use crate::snapshot;
use crate::strace::{self, parse_trace};
use crate::translate::translate;
use crate::wal;

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
    /// Sequence number of the transaction that won the race for it.
    pub merged_seq: u64,
}

/// One sandbox: a job's snapshot, the directory it works in and the identity its commands run
/// under.
///
/// A sandbox outlives the commands that run in it. Its snapshot is retaken from the seed at the
/// start of every command, so each command starts from the seed as it stands, and it survives
/// afterwards so the job keeps a tree to look at.
#[derive(Clone, Debug)]
pub struct Sandbox {
    /// The job's name, which is also its principal.
    pub name: String,
    /// Seed-relative directory its commands start in, `""` for the seed root.
    pub dir: String,
    /// Short id naming its snapshot under `snap/`.
    pub uid: String,
}

impl Sandbox {
    /// The principal this sandbox's commands request capabilities as, which is its name.
    pub fn principal(&self) -> Principal {
        Principal::from(self.name.as_str())
    }
}

/// What became of one submitted command.
#[derive(Debug)]
pub enum CmdOutcome {
    /// The command's capabilities were granted and its changes are in the seed.
    Committed {
        /// Sequence number the transaction occupies.
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
    /// At least one capability was refused; nothing was committed.
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
    /// Snapshot the command is running in.
    work: PathBuf,
    /// Seed version the snapshot copied; staleness is measured against it.
    base_seq: u64,
    /// The sandbox this command runs in, and whose name is its principal.
    sandbox: Sandbox,
    /// The submitted command line, recorded in the log's intent record.
    cmd: String,
}

impl StartedCmd {
    /// Pid of the traced child, which is also its process-group id: the group to hand the terminal
    /// to with `tcsetpgrp`, to signal with `kill(-pgid, …)`, and to reap with `waitpid`.
    pub const fn pid(&self) -> i32 {
        self.traced.pid
    }
}

/// Everything one run of a sandbox needs before its command can be spawned.
struct Launch {
    /// Executor binary the tracer runs.
    executor: PathBuf,
    /// Tracer binary.
    tracer: PathBuf,
    /// Environment the command runs with, snapshot root included.
    envs: Vec<OsString2>,
    /// The job's work tree, and the translator's root.
    work: PathBuf,
    /// Retained strace log.
    trace_log: PathBuf,
    /// Seed version the snapshot copied; staleness is measured against it.
    base_seq: u64,
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

/// A btrfs-snapshotted, strace-audited, capability-gated shell multiplexer over one btrfs seed.
pub struct ShellMux {
    /// The seed every transaction commits into, and the state directory beside it.
    session: Session,
    /// Tunables.
    options: MuxOptions,
    /// The authority. A read lock quiesces the seed for snapshotting; the write lock serializes
    /// merges.
    state: RwLock<AuthorityState>,
    /// Per-principal shells, created on first use.
    shells: Mutex<HashMap<Principal, PrincipalShell>>,
    /// Runtime used only to build shells; brush's builder is async.
    runtime: tokio::runtime::Runtime,
    /// Draws the serial half of a sandbox's id, so two sandboxes opened in the same nanosecond
    /// still differ.
    counter: AtomicU64,
}

impl ShellMux {
    /// Opens `session`, creating its state directory on first use.
    ///
    /// Recovery runs before the snapshot sweep, and that order is load-bearing: an unfinished
    /// transaction's content lives in `snap/<uid>`, which the sweep reclaims.
    ///
    /// # Errors
    ///
    /// Fails when the state directory cannot be created on a usable btrfs mount, or when recovery
    /// cannot complete a logged transaction.
    pub fn open(session: Session, options: MuxOptions) -> Result<Self, MuxError> {
        session.materialize()?;
        // Before the sweep: an unfinished transaction's content is in the snapshot it reclaims.
        commit::recover(&session)?;
        sweep_snapshots(&session)?;
        sweep_temporaries(&session.seed)?;

        let recovered = history::load(&session)?;
        Self::assemble(
            session,
            options,
            AuthorityState {
                history: recovered.history,
                generations: recovered.generations,
                seq: recovered.seq,
                log: recovered.log,
            },
        )
    }

    /// Builds the mux value around already-prepared state.
    fn assemble(
        session: Session,
        options: MuxOptions,
        state: AuthorityState,
    ) -> Result<Self, MuxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|error| MuxError::Brush(format!("tokio runtime: {error}")))?;
        Ok(Self {
            session,
            options,
            state: RwLock::new(state),
            shells: Mutex::new(HashMap::new()),
            runtime,
            counter: AtomicU64::new(0),
        })
    }

    /// Read access to the authority state.
    ///
    /// Poisoning is recovered rather than propagated: every critical section under this lock is a
    /// short, panic-free read or append, so a poisoned guard would mean some *other* thread died
    /// mid-transaction — and refusing to serve reads afterwards would take the whole mux down with
    /// it instead of letting the write-ahead log decide what is committed.
    fn read_state(&self) -> RwLockReadGuard<'_, AuthorityState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Write access to the authority state, with the same poisoning recovery as [`Self::read_state`].
    fn write_state(&self) -> RwLockWriteGuard<'_, AuthorityState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The per-principal shell cache, with the same poisoning recovery as [`Self::read_state`].
    fn shell_map(&self) -> MutexGuard<'_, HashMap<Principal, PrincipalShell>> {
        self.shells.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session: the seed every transaction commits into and the state beside it.
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// The committed capability history, in merge order.
    pub fn history(&self) -> Vec<Event> {
        self.read_state().history.clone()
    }

    /// Creates a sandbox named `name`, rooted at the seed-relative `dir`.
    ///
    /// `dir` must resolve inside the seed, component-wise; `..` that escapes it, and a path that
    /// does not exist in the seed, are both refused.
    ///
    /// # Errors
    ///
    /// Fails when `dir` escapes the seed or names nothing, or when the snapshot cannot be taken.
    pub fn open_sandbox(&self, name: &str, dir: &str) -> Result<Sandbox, MuxError> {
        let relative = seed_relative(dir).ok_or_else(|| MuxError::SandboxDir {
            path: PathBuf::from(dir),
            reason: "escapes the seed".to_string(),
        })?;
        if !self.session.seed.join(&relative).is_dir() {
            return Err(MuxError::SandboxDir {
                path: PathBuf::from(dir),
                reason: "no such directory in the seed".to_string(),
            });
        }

        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let sandbox = Sandbox {
            name: name.to_string(),
            dir: relative,
            uid: ids::short_id(&format!(
                "{}:{name}:{counter}:{nanos}",
                self.session.seed.display()
            )),
        };
        let guard = self.read_state();
        self.refresh(&sandbox)?;
        drop(guard);
        Ok(sandbox)
    }

    /// Discards a sandbox and its snapshot.
    ///
    /// Infallible by design: a snapshot that resists every deletion mechanism is leaked with a
    /// warning, because losing disk space must not fail a transaction that already committed.
    pub fn close_sandbox(&self, sandbox: &Sandbox) {
        snapshot::delete_subvolume(&self.session.work(&sandbox.uid));
    }

    /// Retakes `sandbox`'s snapshot from the seed, discarding whatever the previous command left.
    /// Called with the authority read lock held, so the snapshot copies one quiescent seed.
    fn refresh(&self, sandbox: &Sandbox) -> Result<(), MuxError> {
        let work = self.session.work(&sandbox.uid);
        snapshot::delete_subvolume(&work);
        snapshot::snapshot(&self.session.seed, &work)
    }

    /// Retakes `sandbox`'s snapshot and assembles everything the spawn needs.
    ///
    /// The order is the contract: the binaries are resolved *before* the snapshot is retaken, so a
    /// missing executor leaves the previous command's tree alone; the snapshot is retaken under the
    /// authority read lock, so it copies one quiescent seed and `base_seq` names exactly the
    /// version it copied; and the snapshot root is appended to the environment afterwards, because
    /// `principal_envs` caches per principal while the snapshot root differs per sandbox.
    fn launch(&self, sandbox: &Sandbox) -> Result<Launch, MuxError> {
        let executor = self.executor_path()?;
        let tracer = self
            .options
            .strace
            .clone()
            .unwrap_or_else(|| PathBuf::from("strace"));
        let work = self.session.work(&sandbox.uid);
        let trace_log = self
            .session
            .meta()
            .join("runs")
            .join(&sandbox.uid)
            .join("trace.log");

        let base_seq = {
            let guard = self.read_state();
            self.refresh(sandbox)?;
            guard.seq
        };

        let mut envs = self.principal_envs(&sandbox.principal())?;
        envs.push((
            OsString::from(gitshell::SNAPSHOT_ROOT_VAR),
            work.canonicalize()?.into_os_string(),
        ));

        Ok(Launch {
            executor,
            tracer,
            envs,
            work,
            trace_log,
            base_seq,
        })
    }

    /// Runs one command in `sandbox`, as a single atomic transaction against the seed.
    ///
    /// The phases are snapshot, execute, translate, authorize, commit. Only the first and last take
    /// a lock: snapshotting holds the *read* lock so the snapshot sees one quiescent seed while
    /// other sandboxes snapshot and execute in parallel, and committing holds the *write* lock so
    /// the write set, staleness, policy and log append are one serialization point.
    ///
    /// # Errors
    ///
    /// Fails when the snapshot cannot be retaken, the executor cannot run, or a log cannot be
    /// written. A denial, a lost race and a failed command are outcomes, not errors.
    pub fn run_cmd(&self, sandbox: &Sandbox, cmd: &str) -> Result<CmdOutcome, MuxError> {
        let Launch {
            executor,
            tracer,
            envs,
            work,
            trace_log,
            base_seq,
        } = self.launch(sandbox)?;

        let spawn = strace::run_traced(
            &tracer,
            &executor,
            cmd,
            &work.join(&sandbox.dir),
            &envs,
            &trace_log,
            self.options.cmd_timeout,
        )?;
        self.conclude(sandbox, cmd, spawn, &work, base_seq)
    }

    /// Takes the snapshots and spawns one command in `sandbox` attached to the caller's terminal,
    /// without waiting for it.
    ///
    /// The first half of [`Self::run_cmd`]'s transaction, for a front-end that needs the command to
    /// *be* the user's foreground job: it inherits the real terminal and the real environment —
    /// which is what makes a full-screen program work — and it is its own process group, so the
    /// front-end can hand it the terminal and signal it. `instrumentation` is the descriptor the
    /// child receives on fd 3, its third standard stream; `None` gets `/dev/null`. There is no
    /// wall-clock budget on this path: the wait, and with it every timeout policy, is the caller's.
    ///
    /// # Errors
    ///
    /// Fails when the snapshot cannot be retaken or the tracer cannot be spawned.
    pub fn start_cmd(
        &self,
        sandbox: &Sandbox,
        cmd: &str,
        instrumentation: Option<RawFd>,
    ) -> Result<StartedCmd, MuxError> {
        let Launch {
            executor,
            tracer,
            envs,
            work,
            trace_log,
            base_seq,
        } = self.launch(sandbox)?;

        let traced = strace::spawn_traced(
            &tracer,
            &executor,
            cmd,
            &work.join(&sandbox.dir),
            &envs,
            &trace_log,
            strace::TraceIo::Terminal { instrumentation },
        )?;
        Ok(StartedCmd {
            traced,
            work,
            base_seq,
            sandbox: sandbox.clone(),
            cmd: cmd.to_string(),
        })
    }

    /// Concludes a command the caller has already reaped: translate, authorize, merge.
    ///
    /// `status` is the raw `waitpid(2)` status of the command's *final* exit. A stop is not an exit:
    /// a job that stopped must be continued and waited for again before its status can conclude
    /// anything. Nothing was captured on this path — the job's output went straight to the
    /// terminal, live — so the outcome's `stdout`/`stderr` are empty and the retained trace log is
    /// the record of what happened.
    ///
    /// The snapshot is left alone: it belongs to the sandbox, not to the command, and the next
    /// command in that sandbox retakes it.
    ///
    /// # Errors
    ///
    /// Fails when the recorded streams cannot be read or a log cannot be written.
    pub fn conclude_cmd(&self, started: StartedCmd, status: i32) -> Result<CmdOutcome, MuxError> {
        let StartedCmd {
            traced,
            work,
            base_seq,
            sandbox,
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
        self.conclude(&sandbox, &cmd, spawn, &work, base_seq)
    }

    /// Translates the recorded streams, authorizes the capabilities, and merges — the half of a
    /// transaction that happens once the command has exited.
    ///
    /// Split from the execution half because the two front-ends reach it by different routes: the
    /// batch path captures a [`strace::TraceSpawn`] from a completed `run_traced`, while the console
    /// path waits itself and synthesizes one from a raw wait status.
    fn conclude(
        &self,
        sandbox: &Sandbox,
        cmd: &str,
        spawn: strace::TraceSpawn,
        work: &Path,
        base_seq: u64,
    ) -> Result<CmdOutcome, MuxError> {
        let principal = sandbox.principal();
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
        let translation = translate(
            &lines,
            &records,
            &principal,
            &work_root,
            &work_root.join(&sandbox.dir),
        );
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

        // The reference is the live seed now, so the walk must happen under the commit lock: a
        // transaction renaming into the seed mid-walk surfaces as `ENOENT` out of `diff::collect`.
        let mut guard = self.write_state();
        // Every path in the diff is inside the seed by construction, so nothing is dropped.
        let ops: Vec<CommitOp> = diff_trees(&self.session.seed, &work_root)?;
        if translation.events.is_empty() && ops.is_empty() {
            // Nothing observed and nothing changed: recording it would only grow the log.
            return Ok(CmdOutcome::Committed {
                seq: base_seq,
                exit_code,
                stdout: spawn.stdout,
                stderr: spawn.stderr,
                granted: Vec::new(),
                trace_log: spawn.trace_log,
            });
        }

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

        let seq = self.record_commit(&mut guard, sandbox, cmd, &translation.events, &ops)?;
        drop(guard);

        Ok(CmdOutcome::Committed {
            seq,
            exit_code,
            stdout: spawn.stdout,
            stderr: spawn.stderr,
            granted: translation.events,
            trace_log: spawn.trace_log,
        })
    }

    /// Records one transaction: the seed, then the history, then the generations.
    ///
    /// The order is the recovery contract: a crash between the first two leaves a written seed
    /// whose history entry is re-derived from the log. Returns the sequence number taken.
    fn record_commit(
        &self,
        state: &mut AuthorityState,
        sandbox: &Sandbox,
        cmd: &str,
        events: &[Event],
        ops: &[CommitOp],
    ) -> Result<u64, MuxError> {
        let seq = state.seq + 1;
        let name = sandbox.principal().to_string();
        commit::apply(&self.session, &sandbox.uid, seq, &name, cmd, events, ops)?;
        state.log.append(seq, &name, cmd, events, ops)?;
        state.seq = seq;
        for op in ops {
            state.generations.insert(op.path().to_string(), seq);
        }
        Ok(seq)
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
        let mut shells = self.shell_map();
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
        drop(shells);
        Ok(envs)
    }
}

/// Alias keeping the environment pair type readable in signatures.
type OsString2 = (OsString, OsString);

/// Normalizes a seed-relative directory, or `None` when it escapes the seed.
///
/// Purely lexical, and deliberately so: the seed's own layout decides what exists, and a `..` that
/// climbs past the root must be refused before any path is built from it. A leading `/` names the
/// seed root rather than the filesystem's, because everything here is seed-relative.
fn seed_relative(dir: &str) -> Option<String> {
    let mut segments: Vec<&str> = Vec::new();
    for component in dir.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(segments.join("/"))
}

/// The exit code a raw `waitpid(2)` status reports, in the shell's convention.
///
/// A signalled command reports `128 + signal`, which is what lands a Ctrl-C'd job on 130: non-zero,
/// so the transaction rolls back wholesale like any other failure. A status that is neither an exit
/// nor a death (a stop, which the caller is not supposed to conclude on) reports `-1`, the same
/// "not a success" the rest of the pipeline reads.
const fn exit_code_of(status: i32) -> i32 {
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
    ops: &[CommitOp],
    events: &[Event],
    git_reads: &[String],
) -> Vec<StalePath> {
    let mut checked: Vec<String> = ops.iter().map(|op| op.path().to_string()).collect();
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

/// Deletes every leftover snapshot.
///
/// A sandbox's snapshot is durable *within* a session and belongs to nobody after it: sandboxes
/// live in the console, so a crash leaves trees under `snap/` that no one will ever refresh or
/// delete. Called only from [`ShellMux::open`], after recovery has already consumed the content
/// those trees carried.
fn sweep_snapshots(session: &Session) -> Result<(), MuxError> {
    let snap = session.snap();
    if !snap.exists() {
        std::fs::create_dir_all(&snap)?;
        return Ok(());
    }
    // Everything under the snapshot directory is a snapshot by construction, so no name filtering.
    for entry in std::fs::read_dir(&snap)? {
        let path = entry?.path();
        if path.is_dir() {
            snapshot::delete_subvolume(&path);
        }
    }
    Ok(())
}

/// Removes the temporaries a crash may have left mid-transaction. They are unreferenced by
/// definition: a transaction either renamed its temporary into place or never completed.
fn sweep_temporaries(root: &Path) -> Result<(), MuxError> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(wal::TEMPORARY_SUFFIX))
            {
                std::fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A sandbox's directory is user input that becomes a path under the seed, so the one thing it
    /// must never do is name something outside it.
    #[test]
    fn a_sandbox_directory_cannot_climb_out_of_the_seed() {
        assert_eq!(seed_relative(""), Some(String::new()));
        assert_eq!(seed_relative("."), Some(String::new()));
        assert_eq!(seed_relative("./src"), Some("src".to_string()));
        assert_eq!(seed_relative("/src/"), Some("src".to_string()));
        assert_eq!(seed_relative("deep/../src"), Some("src".to_string()));
        assert_eq!(seed_relative(".."), None);
        assert_eq!(seed_relative("src/../.."), None);
    }
}
