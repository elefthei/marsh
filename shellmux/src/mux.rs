//! The multiplexer: one seed, many sandboxes, one atomic transaction per command.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{
    Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
};
use std::time::{SystemTime, UNIX_EPOCH};

use marsh_exec::persistence::{delete_subvolume, snapshot};
use marsh_exec::{
    CompletedExecution, ExecutionRequest, ExecutionResult, MarshExecutor, PersistenceLayer,
    PreparedExecutor, RunningExecution,
};
use rust_validator::{Action, Bump, Event, GitPolicy, Principal};
use tokio::sync::{Notify, watch};

use crate::authority::{AuthorityState, check_events};
use crate::commit;
use crate::diff::{CommitOp, diff_trees};
use crate::error::MuxError;
use crate::frontend::{FrontendEvent, MarshFrontend, lock_frontend, notify};
use crate::history;
use crate::ids;
use crate::jobs::{Background, JobTable, Merges, ShellId, validate_size};
use crate::purity::{CommandKey, PurityChecker, Verdict};
use crate::reconcile;
use crate::translate::{Translation, translate};
use crate::wal;

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
    /// The job's identity, which is also its principal.
    pub id: ShellId,
    /// Seed-relative directory its commands start in, `""` for the seed root.
    pub dir: String,
    /// Short id naming its snapshot under `snap/`.
    pub uid: String,
}

impl Sandbox {
    /// The principal this sandbox's commands request capabilities as, which is its identity.
    #[must_use]
    pub fn principal(&self) -> Principal {
        Principal::from(self.id.as_str())
    }
}

/// How one command is being run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// The full transaction: snapshot, trace, translate, authorize, merge.
    Transaction,
    /// No snapshot of its own and no merge: the command reads a snapshot shared by every bypassed
    /// command at the same seed version. Still traced, so an effect it was not supposed to have is
    /// observed — after the fact, which is the trade the bypass makes.
    Bypass,
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
    /// The command skipped the sandbox: a prior traced run showed it only reads, so it ran in a
    /// shared reader snapshot with no snapshot of its own, and its own trace said the same again.
    Bypassed {
        /// Exit status of the command.
        exit_code: i32,
        /// Captured stdout; empty on the console path, which writes straight to the terminal.
        stdout: Vec<u8>,
        /// Captured stderr; empty for the same reason.
        stderr: Vec<u8>,
        /// Reads the policy granted and the history recorded — a read is what takes a resource's
        /// read claim, so a bypass still declares them.
        granted: Vec<Event>,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
    /// A command vouched for as read-only did more than read. Its effects are contained in the
    /// reader tree it ran in and never reach the seed — a bypass diffs and merges nothing — but
    /// they were not authorized either, so this is a report: the tree is discarded and the verdict
    /// that let it out is withdrawn.
    Escaped {
        /// Exit status of the command.
        exit_code: i32,
        /// The capabilities it requested, which the authority never saw.
        requested: Vec<Event>,
        /// Whether the trace showed a write inside the tree it read, `.git/` included.
        wrote: bool,
        /// Retained syscall record.
        trace_log: PathBuf,
    },
}

/// One spawned, not-yet-concluded transaction.
///
/// The snapshot and spawn phases are done and the command is running on its job's pseudoterminal.
/// The mux owns the wait — it must, because a child has exactly one reaper and its row update
/// takes the same lock a forced stop does — and its own conclusion performs the remaining phases.
/// This never leaves the mux: handing an open transaction to a caller is what would let one be
/// concluded twice.
#[derive(Debug)]
pub(crate) struct StartedCmd {
    /// The running execution: its process group, and the instrumentation it is producing.
    running: RunningExecution,
    /// Snapshot the command is running in.
    work: PathBuf,
    /// Seed version the snapshot copied; staleness is measured against it.
    base_seq: u64,
    /// The sandbox this command runs in, and whose name is its principal.
    sandbox: Sandbox,
    /// The submitted command line, recorded in the log's intent record.
    cmd: String,
    /// How it was run: a bypass has no snapshot to diff and nothing to merge.
    plan: Plan,
    /// A forced stop has killed this command's process group, so its conclusion may not merge.
    ///
    /// Owned by the transaction rather than read back off the job table, because the row is gone
    /// from public view the moment force is accepted and a partial trace may still carry an earlier
    /// successful exit record.
    force_stopped: bool,
}

impl StartedCmd {
    /// Pid of the traced child, which is also its process-group id: the group to signal with
    /// `kill(-pgid, …)` and to reap with `waitpid`.
    pub(crate) const fn pid(&self) -> i32 {
        self.running.pid()
    }

    /// Kills this command's whole process group and marks the transaction forcibly aborted.
    ///
    /// The kill itself is the executor's ([`RunningExecution::force_stop`]); what belongs here is
    /// the transaction consequence. The flag is set only once the kill is known to have landed —
    /// or to be moot, the group already being over — so a caller that sees an error may retry
    /// against a job that is still exactly as it was.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::Io`] when the group could not be signalled.
    pub(crate) fn force_stop(&mut self) -> Result<(), MuxError> {
        self.running.force_stop()?;
        self.force_stopped = true;
        Ok(())
    }
}

/// Everything one run of a sandbox needs before its command can be spawned.
struct Launch<'a> {
    /// The executor with its worker binary already resolved.
    prepared: PreparedExecutor<'a>,
    /// Environment the command runs with, snapshot root included.
    envs: Vec<OsString2>,
    /// The job's work tree, and the translator's root.
    work: PathBuf,
    /// Seed version the snapshot copied; staleness is measured against it.
    base_seq: u64,
}

/// A principal's shell: the source of the environment its commands run with.
///
/// The shell is not the thing that executes: execution happens in a spawned `marsh-exec` so it can
/// be traced. What the retained shell provides is the principal's exported environment, which is why
/// a per-principal shell is meaningful at all.
struct PrincipalShell {
    /// The principal's brush shell: the context its commands' purity is proved against.
    shell: brush_core::Shell,
    /// Environment handed to every command this principal runs.
    envs: Vec<(OsString, OsString)>,
}

/// A btrfs-snapshotted, strace-audited, capability-gated shell multiplexer over one btrfs seed.
///
/// Built from three collaborators and one user interface: a [`MarshExecutor`] that owns the
/// storage and performs every instrumented run, a [`PurityChecker`] that decides which commands may
/// skip the sandbox, a [`brush_core::env::ShellEnvironment`] seeded into every shell it builds, and
/// the [`MarshFrontend`] whose geometry every job opens at and whose callbacks every job's bytes,
/// results and table changes reach.
pub struct ShellMux {
    /// Consulted before a command runs, and told what every traced run turned out to be.
    purity_checker: PurityChecker,
    /// Variables seeded into every shell this mux builds, on top of the inherited environment.
    environment: brush_core::env::ShellEnvironment,
    /// The authority. A read lock quiesces the seed for snapshotting; the write lock serializes
    /// merges.
    state: RwLock<AuthorityState>,
    /// Per-principal shells, created on first use.
    shells: Mutex<HashMap<Principal, PrincipalShell>>,
    /// Reader trees in use, keyed by the seed version each copied, valued by the number of
    /// bypassed commands still running in it.
    ///
    /// Locked before [`Self::state`] wherever both are taken, which is the only ordering that
    /// exists between them.
    readers: Mutex<HashMap<u64, usize>>,
    /// The open jobs, the name series they draw from, the selected job and the shared terminal
    /// size.
    ///
    /// Locked before [`Self::state`] wherever both are taken, and never held across a snapshot, a
    /// tracer spawn or a conclusion: `jobs` and the child monitor would otherwise wait for the
    /// command being started.
    pub(crate) jobs: Mutex<JobTable>,
    /// Conclusions handed to the conclusion task, and the jobs that still owe one.
    ///
    /// Locked before [`Self::jobs`] wherever both are taken.
    pub(crate) merges: Merges,
    /// Announces that a launch finished publishing, so a waiting `switch` stops polling.
    pub(crate) launched: Notify,
    /// Set once by [`Self::shutdown`], so the child monitor leaves its wait.
    pub(crate) stopping: watch::Sender<bool>,
    /// The long-lived tasks this mux owns, joined by [`Self::shutdown`].
    pub(crate) tasks: Mutex<Background>,
    /// Draws the serial half of a sandbox's id, so two sandboxes opened in the same nanosecond
    /// still differ.
    counter: AtomicU64,
    /// The user interface every job's bytes, results and table changes are delivered to.
    ///
    /// The original allocation, stored behind the trait object it was coerced to: the mux itself
    /// is not generic, because a job pump that carried the frontend's concrete type would make
    /// every internal signature depend on it.
    ///
    /// Before the executor, so a frontend's retained [`Spawned`](crate::Spawned) handles are
    /// released before the session lease is.
    frontend: Arc<Mutex<dyn MarshFrontend>>,
    /// The instrumented-execution facility every command is launched through, and the owner of
    /// this session's storage and its exclusive lease.
    ///
    /// Last, so every job's terminal, shell and open transaction is released before another process
    /// can acquire the session.
    executor: MarshExecutor,
}

impl ShellMux {
    /// Opens the mux over `executor`'s storage, at the geometry `frontend` reports.
    ///
    /// `executor` already holds the session's exclusive lease, which is what makes the recovery
    /// below safe to perform: a competing marsh has already failed by the time this is called.
    /// `purity_checker` is restored from that storage here, after recovery; `environment` is seeded
    /// into every shell this mux builds, on top of what the embedding process itself inherited.
    /// `frontend` is read for its geometry before anything is materialized, and is bound to the
    /// finished mux and told its first state before this returns.
    ///
    /// Recovery runs before the snapshot sweep, and that order is load-bearing: an unfinished
    /// transaction's content lives in `snap/<uid>`, which the sweep reclaims. The recovered history
    /// is then reconciled against the seed's own git state, so a claim outlives a restart only while
    /// the seed still shows the dirt that justified it.
    ///
    /// Must be called from within a Tokio runtime: the mux starts the tasks that monitor its
    /// children and conclude their transactions.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::InvalidTerminalSize`] before touching any storage when a dimension is
    /// zero, when the state directory cannot be created on a usable btrfs mount, when recovery
    /// cannot complete a logged transaction, or when the learned purity cache cannot be read.
    pub fn new<V: MarshFrontend>(
        executor: MarshExecutor,
        mut purity_checker: PurityChecker,
        environment: brush_core::env::ShellEnvironment,
        frontend: Arc<Mutex<V>>,
    ) -> Result<Arc<Self>, MuxError> {
        let frontend: Arc<Mutex<dyn MarshFrontend>> = frontend;
        let (rows, cols) = lock_frontend(&frontend).size();
        // Before anything mux-specific: a geometry no job could use must not leave metadata behind.
        // The collaborators it was handed are still dropped in order, which releases the lease.
        validate_size(rows, cols)?;

        let persistence = executor.persistence();
        persistence.materialize()?;
        executor.terminate_orphans()?;
        // Before the sweep: an unfinished transaction's content is in the snapshot it reclaims.
        commit::recover(persistence)?;
        sweep_snapshots(persistence)?;
        sweep_temporaries(&persistence.seed)?;

        let recovered = history::load(persistence)?;
        let history = reconcile::reconcile(persistence, recovered.history);
        // Last, and under the executor's lease: restoring a learned cache reads and repairs a log
        // that a competing owner must never have been able to truncate.
        purity_checker.restore(persistence)?;

        let mux = Arc::new(Self::assemble(
            executor,
            purity_checker,
            environment,
            AuthorityState {
                history,
                generations: recovered.generations,
                seq: recovered.seq,
                log: recovered.log,
            },
            rows,
            cols,
            Arc::clone(&frontend),
        ));
        // One guard for both: a frontend must never be told the table changed by a mux it has not
        // been given a reference to yet.
        let mut bound = lock_frontend(&frontend);
        bound.bind(Arc::downgrade(&mux));
        bound.update(FrontendEvent::Changed);
        drop(bound);
        Ok(mux)
    }

    /// Builds the mux value around already-prepared state.
    fn assemble(
        executor: MarshExecutor,
        purity_checker: PurityChecker,
        environment: brush_core::env::ShellEnvironment,
        state: AuthorityState,
        rows: u16,
        cols: u16,
        frontend: Arc<Mutex<dyn MarshFrontend>>,
    ) -> Self {
        Self {
            purity_checker,
            environment,
            state: RwLock::new(state),
            shells: Mutex::new(HashMap::new()),
            readers: Mutex::new(HashMap::new()),
            jobs: Mutex::new(JobTable::new(rows, cols)),
            merges: Self::new_merges(),
            launched: Notify::new(),
            stopping: watch::Sender::new(false),
            tasks: Mutex::new(Background::new()),
            counter: AtomicU64::new(0),
            frontend,
            executor,
        }
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

    /// Delivers one observation to this mux's frontend.
    ///
    /// Never called with a job-table, merge, authority or background-task lock held: a frontend
    /// callback is allowed to read the mux back, and holding one of those across it would deadlock
    /// the first frontend that does.
    pub(crate) fn announce(&self, event: FrontendEvent<'_>) {
        notify(&self.frontend, event);
    }

    /// This mux's frontend, for the pumps that outlive the row they read.
    pub(crate) fn frontend(&self) -> Arc<Mutex<dyn MarshFrontend>> {
        Arc::clone(&self.frontend)
    }

    /// Releases the frontend's reference to this mux, for [`Self::shutdown`].
    ///
    /// The same binding hook the constructor uses, with an empty weak reference: a detached
    /// frontend drops the live handles and per-session buffers it was holding, and there is no
    /// second shutdown protocol for it to implement.
    pub(crate) fn detach(&self) {
        lock_frontend(&self.frontend).bind(Weak::new());
    }

    /// The persistent storage: the seed every transaction commits into and the state beside it.
    ///
    /// Borrowed through the executor, which owns it and holds its lease.
    #[must_use]
    pub const fn persistence(&self) -> &PersistenceLayer {
        self.executor.persistence()
    }

    /// The committed capability history, in merge order.
    #[must_use]
    pub fn history(&self) -> Vec<Event> {
        self.read_state().history.clone()
    }

    /// Creates a sandbox for `id`, rooted at the seed-relative `dir`.
    ///
    /// `dir` must resolve inside the seed, component-wise; `..` that escapes it, and a path that
    /// does not exist in the seed, are both refused — the two checks that make `sd api nope` fail
    /// at the prompt rather than at the first command.
    ///
    /// No snapshot is taken here. [`Self::launch`] retakes one before every transactional command
    /// anyway, so taking one now would only be thrown away; a job whose commands all bypass never
    /// takes one at all, and deleting a snapshot that was never taken is already a no-op. That is
    /// also what makes this cheap enough to run under the job table's lock, which
    /// [`Self::spawn`] does.
    ///
    /// # Errors
    ///
    /// Fails when `dir` escapes the seed or names nothing.
    pub(crate) fn new_sandbox(&self, id: &ShellId, dir: &str) -> Result<Sandbox, MuxError> {
        let relative = seed_relative(dir).ok_or_else(|| MuxError::SandboxDir {
            path: PathBuf::from(dir),
            reason: "escapes the seed".to_string(),
        })?;
        let seed = &self.persistence().seed;
        if !seed.join(&relative).is_dir() {
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
            id: id.clone(),
            dir: relative,
            uid: ids::short_id(&format!("{}:{id}:{counter}:{nanos}", seed.display())),
        };
        Ok(sandbox)
    }

    /// The plan for `cmd` in `sandbox`, proved against `shell`.
    ///
    /// `shell` is the context the proof needs and cannot invent: a function or an alias with a
    /// familiar builtin's name is a real shadowing definition, so the same spelling means different
    /// things in different jobs.
    pub(crate) fn plan_for(&self, shell: &brush_core::Shell, sandbox: &Sandbox, cmd: &str) -> Plan {
        let key = CommandKey {
            cmd,
            dir: &sandbox.dir,
        };
        match self.purity_checker.check(shell, key) {
            Verdict::Pure => Plan::Bypass,
            Verdict::Sandboxed => Plan::Transaction,
        }
    }

    /// Tells the checker what a run turned out to be.
    fn observe(&self, sandbox: &Sandbox, cmd: &str, verdict: Verdict) {
        self.purity_checker.observe(
            CommandKey {
                cmd,
                dir: &sandbox.dir,
            },
            verdict,
        );
    }

    /// Records that a command the checker let out of the sandbox turned out to act, and says so.
    ///
    /// The run that escaped is the evidence, so nothing is re-analyzed here: a learning checker
    /// corrects itself from this observation, a static one cannot, and naming the mode is what
    /// tells a reader which of the two just happened.
    fn withdraw(&self, sandbox: &Sandbox, cmd: &str) {
        eprintln!(
            "marsh: withdrawing the {} purity verdict for {cmd:?}",
            self.purity_checker.mode()
        );
        self.observe(sandbox, cmd, Verdict::Sandboxed);
    }

    /// Discards a sandbox, its snapshot and the job that held it.
    ///
    /// Forgetting the job is what frees its name: a caller that closes a sandbox by hand has
    /// finished with that principal, and the next [`Self::spawn`] may hand the name out again.
    ///
    /// The row's producers are held across the deletion, exactly as the automatic reclamation path
    /// holds them: closing the pseudoterminal slave and the instrumentation writer is what turns a
    /// retained handle's reads into end of file, and [`FrontendEvent::Closed`] promises the storage
    /// was already reclaimed when it arrives.
    ///
    /// Infallible by design: a snapshot that resists every deletion mechanism is leaked with a
    /// warning, because losing disk space must not fail a transaction that already committed.
    pub fn close_sandbox(&self, sandbox: &Sandbox) {
        let retired = self.job_table().forget(&sandbox.uid);
        delete_subvolume(&self.persistence().work(&sandbox.uid));
        drop(retired);
        self.announce(FrontendEvent::Changed);
    }

    /// Retakes `sandbox`'s snapshot from the seed, discarding whatever the previous command left.
    /// Called with the authority read lock held, so the snapshot copies one quiescent seed.
    fn refresh(&self, sandbox: &Sandbox) -> Result<(), MuxError> {
        let work = self.persistence().work(&sandbox.uid);
        delete_subvolume(&work);
        Ok(snapshot(&self.persistence().seed, &work)?)
    }

    /// Takes a reader tree for a bypassed command, and the seed version it copied.
    ///
    /// A bypassed command must see one *quiesced* version of the seed, not the live seed a commit
    /// may be applying into file by file — the same guarantee a transaction gets from its own
    /// snapshot. It must also not pay for a snapshot per command, so the tree is shared: one per
    /// committed version, named by that version because a committed version never changes again,
    /// created under the authority read lock, and reused by every read-only command that starts
    /// while it is current.
    ///
    /// Naming by version rather than reusing one path is what makes concurrency safe: a commit
    /// landing mid-read gives the *next* command a new tree instead of deleting the one a running
    /// command is reading. Superseded trees nobody is left reading are reclaimed here.
    fn acquire_reader(&self) -> Result<(PathBuf, u64), MuxError> {
        let mut readers = self.readers.lock().unwrap_or_else(PoisonError::into_inner);
        let seq = {
            let guard = self.read_state();
            match readers.entry(guard.seq) {
                std::collections::hash_map::Entry::Occupied(mut used) => *used.get_mut() += 1,
                std::collections::hash_map::Entry::Vacant(slot) => {
                    let path = self.persistence().reader(guard.seq);
                    // A crashed session may have left this exact name behind; the sweep only runs
                    // at startup, and this one is being recreated now anyway.
                    delete_subvolume(&path);
                    snapshot(&self.persistence().seed, &path)?;
                    slot.insert(1);
                }
            }
            guard.seq
        };

        let superseded: Vec<u64> = readers
            .iter()
            .filter(|(version, users)| **version != seq && **users == 0)
            .map(|(version, _)| *version)
            .collect();
        for version in superseded {
            readers.remove(&version);
            delete_subvolume(&self.persistence().reader(version));
        }
        drop(readers);
        Ok((self.persistence().reader(seq), seq))
    }

    /// Releases the reader tree of version `seq`, reclaiming it once the seed has moved on and
    /// nothing is left reading it.
    ///
    /// A tree that is still current is kept even with no readers: it is exactly what the next
    /// bypassed command would otherwise have to take again.
    fn release_reader(&self, seq: u64) {
        let mut readers = self.readers.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(users) = readers.get_mut(&seq) else {
            return;
        };
        *users = users.saturating_sub(1);
        if *users > 0 || seq == self.read_state().seq {
            return;
        }
        readers.remove(&seq);
        drop(readers);
        delete_subvolume(&self.persistence().reader(seq));
    }

    /// Discards the reader tree of version `seq` once nothing is left reading it.
    ///
    /// Called when a bypassed command turns out to have written. Its writes are contained — a
    /// reader tree is a snapshot, so nothing it wrote reaches the seed — but they are visible to
    /// anything else reading the same version, so the tree must not be handed out again.
    ///
    /// It can only be deleted once its last reader leaves, and that is almost always at once: the
    /// escapee is normally the only command in it, and [`Self::conclude`] has already released it.
    /// A concurrent bypass at the same version keeps the tree alive and does inherit the dirtied
    /// view — a read-only command that merges nothing, until the next commit supersedes the
    /// version — which is the one case this cannot quarantine without stranding the tree.
    fn discard_reader(&self, seq: u64) {
        let mut readers = self.readers.lock().unwrap_or_else(PoisonError::into_inner);
        if readers.get(&seq).is_none_or(|users| *users > 0) {
            return;
        }
        readers.remove(&seq);
        drop(readers);
        delete_subvolume(&self.persistence().reader(seq));
    }

    /// Prepares everything the spawn needs, taking the tree the command runs in.
    ///
    /// The order is the contract: the worker binary is resolved *before* any tree is taken, so a
    /// missing worker leaves the previous command's tree alone; the tree is taken under the
    /// authority read lock, so it copies one quiescent seed and `base_seq` names exactly the
    /// version it copied; and the per-command markers — the snapshot root and the job uid — are
    /// appended to the environment afterwards, because `principal_envs` caches per principal while
    /// both of those differ per command.
    ///
    /// `work` is canonical, because it is also the translator's strip prefix and the diff's
    /// reference — and because a reader tree may be reclaimed before the conclusion that needs it.
    fn launch(&self, sandbox: &Sandbox, plan: Plan) -> Result<Launch<'_>, MuxError> {
        let prepared = self.executor.prepare()?;

        let (work, base_seq) = match plan {
            Plan::Transaction => {
                let guard = self.read_state();
                self.refresh(sandbox)?;
                let seq = guard.seq;
                drop(guard);
                (self.persistence().work(&sandbox.uid).canonicalize()?, seq)
            }
            // No snapshot of its own: it shares the reader tree of the version it starts at, and
            // merges nothing, so there is no version for it to be stale against.
            Plan::Bypass => {
                let (path, seq) = self.acquire_reader()?;
                (path.canonicalize()?, seq)
            }
        };

        let mut envs = match self.principal_envs(&sandbox.principal()) {
            Ok(envs) => envs,
            Err(error) => {
                if plan == Plan::Bypass {
                    self.release_reader(base_seq);
                }
                return Err(error);
            }
        };
        envs.push((
            OsString::from(marsh_exec::SNAPSHOT_ROOT_VAR),
            work.clone().into_os_string(),
        ));
        // After the cached principal environment, for the same reason the snapshot root is: this
        // pair differs per job, and `principal_envs` caches per principal. It is what makes one
        // job's processes identifiable among the reader tree's shared occupants.
        envs.push((
            OsString::from(marsh_exec::JOB_UID_VAR),
            OsString::from(&sandbox.uid),
        ));

        Ok(Launch {
            prepared,
            envs,
            work,
            base_seq,
        })
    }

    /// Runs one command in `sandbox`, as a single atomic transaction against the seed, capturing
    /// its output.
    ///
    /// The phases are snapshot, execute, translate, authorize, commit. Only the first and last take
    /// a lock: snapshotting holds the *read* lock so the snapshot sees one quiescent seed while
    /// other sandboxes snapshot and execute in parallel, and committing holds the *write* lock so
    /// the write set, staleness, policy and log append are one serialization point. The command's
    /// wall-clock budget is the executor's ([`MarshExecutor::DEFAULT_CMD_TIMEOUT`] unless its
    /// builder was told otherwise).
    ///
    /// # Errors
    ///
    /// Fails when the snapshot cannot be retaken, the executor cannot run, or a log cannot be
    /// written. A denial, a lost race and a failed command are outcomes, not errors.
    pub async fn run_cmd(
        self: &Arc<Self>,
        sandbox: &Sandbox,
        cmd: &str,
    ) -> Result<CmdOutcome, MuxError> {
        let plan = self.batch_plan(sandbox, cmd).await?;
        let mux = Arc::clone(self);
        let sandbox = sandbox.clone();
        let cmd = cmd.to_string();
        // The whole transaction is blocking work — a snapshot, a traced run, two tree walks — with
        // owned inputs, so it never occupies an asynchronous worker.
        tokio::task::spawn_blocking(move || mux.run_cmd_blocking(&sandbox, &cmd, plan))
            .await
            .map_err(|error| MuxError::Exec(format!("command task: {error}")))?
    }

    /// The blocking body of [`Self::run_cmd`].
    fn run_cmd_blocking(
        &self,
        sandbox: &Sandbox,
        cmd: &str,
        plan: Plan,
    ) -> Result<CmdOutcome, MuxError> {
        let Launch {
            prepared,
            envs,
            work,
            base_seq,
        } = self.launch(sandbox, plan)?;

        let completed = match prepared.run(ExecutionRequest {
            command: cmd,
            cwd: &work.join(&sandbox.dir),
            envs: &envs,
            run_id: &sandbox.uid,
        }) {
            Ok(completed) => completed,
            Err(error) => {
                if plan == Plan::Bypass {
                    self.release_reader(base_seq);
                }
                return Err(error.into());
            }
        };
        self.conclude(sandbox, cmd, completed, &work, base_seq, plan)
    }

    /// Takes the snapshots and spawns one command in `sandbox` on the job's own pseudoterminal,
    /// without waiting for it.
    ///
    /// The first half of [`Self::run_cmd`]'s transaction, for a job a user is looking at: `terminal`
    /// is the slave side the command's standard descriptors are duplicated from and the controlling
    /// terminal it claims, so a full-screen program behaves exactly as it would under any other
    /// shell, and `instrumentation` is the descriptor it receives on fd 3, its third standard
    /// stream. There is no wall-clock budget on this path: the wait is the mux's own, and only it
    /// can observe a job stopping rather than exiting.
    ///
    /// Blocking, and called from a blocking task: it retakes a snapshot and forks a tracer.
    ///
    /// # Errors
    ///
    /// Fails when the snapshot cannot be retaken or the tracer cannot be spawned.
    pub(crate) fn start_cmd(
        &self,
        sandbox: &Sandbox,
        cmd: &str,
        plan: Plan,
        terminal: RawFd,
        instrumentation: RawFd,
    ) -> Result<StartedCmd, MuxError> {
        let Launch {
            prepared,
            envs,
            work,
            base_seq,
        } = self.launch(sandbox, plan)?;

        let running = match prepared.start_pty(
            ExecutionRequest {
                command: cmd,
                cwd: &work.join(&sandbox.dir),
                envs: &envs,
                run_id: &sandbox.uid,
            },
            terminal,
            instrumentation,
        ) {
            Ok(running) => running,
            Err(error) => {
                if plan == Plan::Bypass {
                    self.release_reader(base_seq);
                }
                return Err(error.into());
            }
        };
        Ok(StartedCmd {
            running,
            work,
            base_seq,
            sandbox: sandbox.clone(),
            cmd: cmd.to_string(),
            plan,
            force_stopped: false,
        })
    }

    /// Concludes a command the mux has already reaped: translate, authorize, merge.
    ///
    /// `status` is the raw `waitpid(2)` status of the command's exit. Nothing was captured on this
    /// path — the job's output went straight to the terminal, live — so the outcome's
    /// `stdout`/`stderr` are empty and the retained trace log is the record of what happened.
    ///
    /// The snapshot is left alone: it belongs to the sandbox, not to the command, and the next
    /// command in that sandbox retakes it.
    ///
    /// A forcibly stopped command is not translated, does not teach purity, authorizes nothing and
    /// merges nothing: it reports 137, the code a `SIGKILL`ed command exits with. That branch is
    /// taken from the transaction's own flag rather than from the trace, because a partial trace
    /// may hold an earlier successful root exit that would otherwise commit an aborted command.
    ///
    /// # Errors
    ///
    /// Fails when the recorded streams cannot be read or a log cannot be written, and with
    /// [`MuxError::JobTermination`] when a forced job's remaining processes could not be proven
    /// gone — the one failure after which the caller must keep the job's tree.
    pub(crate) fn conclude_cmd(
        &self,
        started: StartedCmd,
        status: i32,
    ) -> Result<CmdOutcome, MuxError> {
        let StartedCmd {
            running,
            work,
            base_seq,
            sandbox,
            cmd,
            plan,
            force_stopped,
        } = started;
        let completed = if force_stopped {
            // Before the handle is consumed and before the reader lease is released, so a tree is
            // never handed to the next command while a killed one may still be writing into it.
            self.executor
                .terminate_owner(&sandbox.uid)
                .map_err(|source| MuxError::JobTermination {
                    job: sandbox.id.clone(),
                    source: Box::new(source.into()),
                })?;
            running.complete_forced()
        } else {
            running.complete(status)
        };
        self.conclude(&sandbox, &cmd, completed, &work, base_seq, plan)
    }

    /// Collects the execution's evidence, authorizes the capabilities, and merges — the half of a
    /// transaction that happens once the command has exited.
    ///
    /// Split from the execution half because the two front-ends reach it by different routes: the
    /// batch path hands over a completed capture, the console path waits itself and completes a
    /// running execution from a raw wait status. Both arrive as a [`CompletedExecution`], and the
    /// collection is deliberately the *first* fallible step after the lease is released: reading
    /// the logs must not happen while a tree the next command could be handed is still leased.
    ///
    /// A [`Plan::Bypass`] run takes no snapshot of its own and merges nothing, so it stops after
    /// the translation: what is left is to check that the verdict which let it out was right, and
    /// to submit the reads it did make. `work` is already canonical — [`Self::launch`] made it so,
    /// because a reader tree may be reclaimed before the conclusion that names it.
    fn conclude(
        &self,
        sandbox: &Sandbox,
        cmd: &str,
        completed: CompletedExecution,
        work: &Path,
        base_seq: u64,
        plan: Plan,
    ) -> Result<CmdOutcome, MuxError> {
        // The command has exited, so the version it read is one reader fewer. Before anything
        // fallible: a conclusion that errors must not pin a tree for the rest of the session.
        if plan == Plan::Bypass {
            self.release_reader(base_seq);
        }
        let mut result = completed.collect()?;
        let work_root = work.to_path_buf();
        let exit_code = result.exit_code;
        // Taken out rather than borrowed: a forced or trace-less run has none, and that is exactly
        // the run that must not be translated, must not teach purity, and must not merge.
        let Some(evidence) = result.evidence.take() else {
            return Ok(CmdOutcome::ExecFailed {
                exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                trace_log: result.logs.trace_log,
            });
        };
        let translation = translate(
            &evidence,
            &sandbox.principal(),
            &work_root,
            &work_root.join(&sandbox.dir),
        );
        drop(evidence);

        if plan == Plan::Bypass {
            return self.conclude_bypass(sandbox, cmd, translation, result, base_seq);
        }

        // What this traced run showed, for the sources that learn. Before every early return
        // below, so a command that requests nothing is learned whatever it exits with.
        self.observe(sandbox, cmd, verdict_of(&translation, exit_code));

        if let Some(reason) = translation.unsupported {
            return Ok(CmdOutcome::Unsupported {
                reason,
                trace_log: result.logs.trace_log,
            });
        }
        // A failed command is rolled back wholesale: its partial writes stay in the discarded
        // snapshot and it requests no capabilities. Half of a failed command is not a transaction.
        if exit_code != 0 {
            return Ok(CmdOutcome::ExecFailed {
                exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                trace_log: result.logs.trace_log,
            });
        }

        // The reference is the live seed now, so the walk must happen under the commit lock: a
        // transaction renaming into the seed mid-walk surfaces as `ENOENT` out of `diff::collect`.
        let mut guard = self.write_state();
        // A command that opened nothing for writing inside the snapshot cannot have a write set, so
        // the two full tree walks `diff_trees` costs are skipped. On a seed of any size that diff
        // is the whole cost of a transaction, and until now every `ls` and every `cat` paid it.
        // Every path in the diff is inside the seed by construction, so nothing is dropped.
        let ops: Vec<CommitOp> = if translation.wrote_in_root {
            diff_trees(&self.persistence().seed, &work_root)?
        } else {
            Vec::new()
        };
        if translation.events.is_empty() && ops.is_empty() {
            // Nothing observed and nothing changed: recording it would only grow the log.
            return Ok(CmdOutcome::Committed {
                seq: base_seq,
                exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                granted: Vec::new(),
                trace_log: result.logs.trace_log,
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
                trace_log: result.logs.trace_log,
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
                stdout: result.stdout,
                stderr: result.stderr,
                requested: translation.events,
                denials,
                trace_log: result.logs.trace_log,
            });
        }

        let seq = self.record_commit(&mut guard, sandbox, cmd, &translation.events, &ops)?;
        drop(guard);

        Ok(CmdOutcome::Committed {
            seq,
            exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            granted: translation.events,
            trace_log: result.logs.trace_log,
        })
    }

    /// Concludes a [`Plan::Bypass`] run: it read, so its reads are authorized and recorded, but
    /// there is no snapshot to diff, nothing to merge and no write-ahead log entry.
    ///
    /// The reads still go to the authority, and that is not bookkeeping. A `Read` can never be
    /// refused — the git policy has no rule for one — but a read is what *takes the read claim* on
    /// a resource, and rules 19-23 forbid another principal's `edit`, `delete`, `clean`, `checkout`
    /// or `stash` while someone else holds it, with "must read it before editing it" as the fix. A
    /// principal whose reads stopped being recorded could never take a claim back, and would be
    /// denied for a read it had actually performed.
    ///
    /// No sequence number is taken. `seq` names a *version of the seed*, and `generations` and
    /// `base_seq` read it as one; a read changes no version, so it rides on the current number and
    /// contributes no generation. Order in the log is what the policy needs, and appending gives
    /// it that.
    ///
    /// A run that turns out to have done more than read is reported, its verdict withdrawn and the
    /// tree it dirtied discarded. Nothing it wrote reaches the seed — a reader tree is a snapshot,
    /// and no diff or merge follows a bypass — so an escape costs the tree, not the seed.
    fn conclude_bypass(
        &self,
        sandbox: &Sandbox,
        cmd: &str,
        translation: Translation,
        result: ExecutionResult,
        base_seq: u64,
    ) -> Result<CmdOutcome, MuxError> {
        let exit_code = result.exit_code;
        if translation.unsupported.is_some()
            || translation.wrote_in_root
            || translation
                .events
                .iter()
                .any(|event| event.action != Action::Read)
        {
            self.withdraw(sandbox, cmd);
            self.discard_reader(base_seq);
            return Ok(CmdOutcome::Escaped {
                exit_code,
                requested: translation.events,
                wrote: translation.wrote_in_root,
                trace_log: result.logs.trace_log,
            });
        }
        if exit_code != 0 {
            // A command that failed without touching anything is still read-only; its verdict
            // stands, and a failed run declares nothing.
            return Ok(CmdOutcome::ExecFailed {
                exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                trace_log: result.logs.trace_log,
            });
        }
        if translation.events.is_empty() {
            return Ok(CmdOutcome::Bypassed {
                exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                granted: Vec::new(),
                trace_log: result.logs.trace_log,
            });
        }

        // The write lock, because the history is what is being changed — the same serialization
        // point a merge takes, held for the length of a policy decision over a handful of reads
        // rather than for two tree walks.
        let mut guard = self.write_state();
        let arena = Bump::new();
        let mut policy = GitPolicy::new(&arena);
        let committed = guard.history.len();
        let denials = check_events(&mut policy, &mut guard.history, &translation.events);
        if !denials.is_empty() {
            guard.history.truncate(committed);
            return Ok(CmdOutcome::DeniedCaps {
                exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
                requested: translation.events,
                denials,
                trace_log: result.logs.trace_log,
            });
        }
        let seq = guard.seq;
        let principal = sandbox.principal().to_string();
        guard
            .log
            .append(seq, &principal, cmd, &translation.events, &[])?;
        drop(guard);

        Ok(CmdOutcome::Bypassed {
            exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            granted: translation.events,
            trace_log: result.logs.trace_log,
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
        commit::apply(
            self.persistence(),
            &sandbox.uid,
            seq,
            &name,
            cmd,
            events,
            ops,
        )?;
        state.log.append(seq, &name, cmd, events, ops)?;
        state.seq = seq;
        for op in ops {
            state.generations.insert(op.path().to_string(), seq);
        }
        Ok(seq)
    }

    /// Applies this mux's seeded environment to `builder`.
    ///
    /// Every shell the mux builds goes through here, so a job's interactive shell and the exported
    /// environment its commands run with agree on what was seeded. The variables are assigned after
    /// the inherited and well-known ones, so a seeded name overrides the embedding process's value
    /// for that name; unique names make the iteration order immaterial.
    fn seed_environment<S: brush_core::ShellBuilderState>(
        &self,
        mut builder: brush_core::ShellBuilder<brush_core::extensions::DefaultShellExtensions, S>,
    ) -> brush_core::ShellBuilder<brush_core::extensions::DefaultShellExtensions, S> {
        for (name, variable) in self.environment.iter() {
            builder = builder.var(name.clone(), variable.clone());
        }
        builder
    }

    /// Builds one shell for this mux: seeded, with no profile or rc, over `fds`.
    ///
    /// The one asynchronous initialization path. A job's terminal shell and a principal's
    /// environment shell differ only in the descriptors and working directory they are given.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::Brush`] when the shell could not be built.
    pub(crate) async fn build_shell(
        &self,
        working_dir: Option<std::path::PathBuf>,
        fds: HashMap<brush_core::ShellFd, brush_core::openfiles::OpenFile>,
    ) -> Result<brush_core::Shell, MuxError> {
        let builder = brush_core::Shell::builder()
            .interactive(false)
            .no_editing(true)
            .maybe_working_dir(working_dir)
            .fds(fds)
            .profile(brush_core::ProfileLoadBehavior::Skip)
            .rc(brush_core::RcLoadBehavior::Skip);
        self.seed_environment(builder)
            .build()
            .await
            .map_err(|error| MuxError::Brush(error.to_string()))
    }

    /// Creates `principal`'s shell if it does not have one yet.
    ///
    /// Separated from [`Self::principal_envs`] because building a shell is asynchronous and every
    /// caller of the environment is inside a blocking transaction by the time it needs one.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::Brush`] when the shell could not be built.
    pub(crate) async fn ensure_principal(&self, principal: &Principal) -> Result<(), MuxError> {
        if self.shell_map().contains_key(principal) {
            return Ok(());
        }
        let shell = self.build_shell(None, HashMap::new()).await?;

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

        let mut shells = self.shell_map();
        shells
            .entry(principal.clone())
            .or_insert(PrincipalShell { shell, envs });
        drop(shells);
        Ok(())
    }

    /// The plan for a captured command, proved against its principal's own shell.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::Brush`] when the principal's shell could not be built.
    async fn batch_plan(&self, sandbox: &Sandbox, cmd: &str) -> Result<Plan, MuxError> {
        self.ensure_principal(&sandbox.principal()).await?;
        let shells = self.shell_map();
        let plan = shells
            .get(&sandbox.principal())
            .map_or(Plan::Transaction, |entry| {
                self.plan_for(&entry.shell, sandbox, cmd)
            });
        drop(shells);
        Ok(plan)
    }

    /// The environment for `principal`, whose shell [`Self::ensure_principal`] has already built.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::Brush`] when no shell was built for that principal, which means a
    /// caller reached a launch without initializing it.
    fn principal_envs(&self, principal: &Principal) -> Result<Vec<OsString2>, MuxError> {
        let shells = self.shell_map();
        let envs = shells.get(principal).map(|entry| entry.envs.clone());
        drop(shells);
        envs.ok_or_else(|| {
            MuxError::Brush(format!(
                "no shell was initialized for principal {principal}"
            ))
        })
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

/// The purity verdict one traced run earns: read-only, and nothing else.
///
/// [`Read`](rust_validator::Action::Read) is the one action a bypass can honour, because it is the
/// one the policy never refuses and the one a bypassed run still submits
/// ([`ShellMux::conclude_bypass`]). Every other action either changes the seed or is refusable, and
/// neither survives having no snapshot to hold it back. `wrote_in_root` is checked separately from
/// the event list because a write under `.git/` produces no event at all, and a write is a write.
fn verdict_of(translation: &Translation, exit_code: i32) -> Verdict {
    if translation.unsupported.is_none()
        && !translation.wrote_in_root
        && translation
            .events
            .iter()
            .all(|event| event.action == Action::Read)
        && exit_code == 0
    {
        Verdict::Pure
    } else {
        Verdict::Sandboxed
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
    // The address, unlike the name, has to be one word: a job name may hold spaces, and every
    // character outside an address's alphabet becomes a hyphen so the identity stays well formed
    // whatever the job was called.
    let slug: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '.' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect();
    let email = format!("{slug}@marsh.local");
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
/// live in a front-end, so a crash leaves trees under `snap/` that no one will ever refresh or
/// delete. Called only from [`ShellMux::new`], after recovery has already consumed the content
/// those trees carried.
fn sweep_snapshots(persistence: &PersistenceLayer) -> Result<(), MuxError> {
    let snap = persistence.snap();
    if !snap.exists() {
        std::fs::create_dir_all(&snap)?;
        return Ok(());
    }
    // Everything under the snapshot directory is a snapshot by construction, so no name filtering.
    for entry in std::fs::read_dir(&snap)? {
        let path = entry?.path();
        if path.is_dir() {
            delete_subvolume(&path);
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

    /// A job name becomes the commit author, and a job name may hold spaces — but an address may
    /// not, and libgit2 refuses the identity rather than the commit.
    #[test]
    fn a_principals_address_is_one_word_whatever_the_principal_is() {
        let env: HashMap<String, String> = git_env(&Principal::from("a long name"))
            .into_iter()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert_eq!(env["GIT_AUTHOR_NAME"], "a long name");
        assert_eq!(env["GIT_AUTHOR_EMAIL"], "a-long-name@marsh.local");
        assert_eq!(
            git_env(&Principal::from("main"))
                .into_iter()
                .find(|(key, _)| key == "GIT_COMMITTER_EMAIL")
                .map(|(_, value)| value.to_string_lossy().into_owned()),
            Some("main@marsh.local".to_string()),
            "a name that was already one word is untouched, so no commit hash moves"
        );
    }
}
