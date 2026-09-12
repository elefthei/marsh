//! The job table: the shells a front-end has open, the commands running in them, the terminals
//! they own, and the names they answer to.
//!
//! A job is a *sandbox*, not a command: it outlives the commands that run in it, and its
//! [`ShellId`] is the [`crate::Principal`] those commands request capabilities as. That is why the
//! table lives here rather than in a front-end: a job's name and a principal's name are one
//! identity, and two registries of it would drift.
//!
//! Every job owns a pseudoterminal and an instrumentation pipe from the moment it is created, so a
//! front-end reads bytes rather than sharing the process's real terminal, and a full-screen program
//! behaves as it would under any other shell. The whole terminal geometry is the mux's, not the
//! job's: one size, applied to every job, changed by [`ShellMux::resize`].
//!
//! One command at a time per job. The table is never held across a launch, a wait or a conclusion,
//! so [`ShellMux::jobs`] answers while a command is starting and while another is running.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use newtype::NewType;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

use crate::error::MuxError;
use crate::frontend::{FrontendEvent, MarshFrontend, notify};
use crate::mux::{CmdOutcome, Sandbox, ShellMux, StartedCmd};

/// A job's identity: the name a front-end prints, the handle `fg` resolves, and the principal its
/// commands request capabilities as.
///
/// A typed handle rather than an enforced invariant. The conversion from `String` is infallible and
/// the inner string is reachable through [`Deref`](std::ops::Deref), because job-name *grammar* is
/// a front-end's rule — a CLI refuses `main` and free-form names, a programmatic caller need not —
/// while the mux's own rules are the ones it can enforce: a live duplicate is refused, and an
/// unknown name is an error.
#[derive(NewType, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShellId(String);

impl ShellId {
    /// Whether this name needs no quoting when written as `%name`.
    ///
    /// The set is the one that survives being printed in a job table and typed back without
    /// quoting.
    #[must_use]
    pub fn is_bare(&self) -> bool {
        !self.0.is_empty()
            && self.0.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '-'
            })
    }

    /// How this job is written for a reader: `%name` when the name is one word, `%"a name"` when
    /// it is not.
    ///
    /// Every `%…` a front-end prints goes through this, because a job reference is also *input*: it
    /// is what a reader types at `fg` and `stop`, so a row of a job table has to be
    /// re-typeable. `{name:?}` is exact rather than merely close: a bare name holds neither a quote
    /// nor a control character, so there is nothing for `Debug` to escape.
    #[must_use]
    pub fn reference(&self) -> String {
        if self.is_bare() {
            format!("%{}", self.0)
        } else {
            format!("%{:?}", self.0)
        }
    }
}

impl std::fmt::Display for ShellId {
    /// The bare name, unquoted: [`ShellId::reference`] is the form that carries the `%`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&str> for ShellId {
    fn from(name: &str) -> Self {
        Self::from(name.to_string())
    }
}

/// Why a job is to close once its execution and conclusion finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobCloseMode {
    /// An unnamed background command; a reader may keep this job.
    Automatic,
    /// Explicitly close after normal command completion.
    Graceful,
    /// Explicitly abort and retire the job immediately.
    Force,
}

impl JobCloseMode {
    /// Whether a reader asked for this closure, rather than the `1`, `2`, … series implying it.
    const fn explicit(self) -> bool {
        !matches!(self, Self::Automatic)
    }
}

/// The terminal, instrumentation and shell one job owns for as long as it exists.
///
/// Published only once construction has fully succeeded, so a caller never observes a job whose
/// terminal is half-built. Dropping it closes the producer descriptors — the pseudoterminal slave
/// and the instrumentation writer — which is what turns a retained [`Spawned`] handle's reads into
/// end of file rather than a wait nothing will end.
pub(crate) struct JobResources {
    /// Master side of the job's pseudoterminal, shared with every [`Spawned`] handle so output can
    /// still be drained after the public row is gone.
    terminal: Arc<AsyncFd<OwnedFd>>,
    /// Slave side: what a launched command's standard descriptors are duplicated from, and the
    /// controlling terminal it claims. Mux-owned, never handed out.
    slave: OwnedFd,
    /// Write end of the instrumentation pipe, placed on each command's fd 3. Mux-owned.
    writer: OwnedFd,
    /// The job's own brush shell: the context a command's purity is proved against, and the owner
    /// of this job's copies of the descriptors above.
    shell: brush_core::Shell,
    /// Dropped when this job's resources are released, which is what tells its pump the job is
    /// over. Never read and nothing is ever sent through it: the drop *is* the signal, and it
    /// happens only after the storage the job named is gone.
    _release: tokio::sync::oneshot::Sender<()>,
}

/// One job: a named sandbox, its terminal, and whatever command is running in it.
struct Job {
    /// The handle a job table prints and `fg NAME` resolves.
    id: ShellId,
    /// The sandbox every command of this job runs in.
    sandbox: Sandbox,
    /// The terminal and shell, once they are built. `None` only between the name reservation and
    /// the end of construction.
    resources: Option<JobResources>,
    /// The command currently running in it, if any.
    running: Option<Running>,
    /// A command is being launched into it: its snapshot is being retaken and its tracer spawned.
    ///
    /// Separate from `running`, which cannot exist until the tracer has a pid. Without it the busy
    /// check would pass twice for one job and the second launch would strand the first's tracer.
    starting: bool,
    /// Why this job is to close, or `None` while it is to stay.
    ///
    /// [`JobCloseMode::Automatic`] is the job nobody named: a number drawn from the `1`, `2`, …
    /// series for a command a bare `&` submitted, so there is no handle a reader would come back to
    /// and [`ShellMux::keep`] is what cancels it. The explicit modes are a reader's `stop`, which
    /// no later `keep` may cancel.
    close: Option<JobCloseMode>,
    /// Called when the command this job is running ends, when someone asked to be told.
    ///
    /// One slot, because one command runs at a time, and set only while a command exists:
    /// whichever path publishes that command's conclusion takes it, so a callback is never
    /// delivered for a command it was not registered against.
    done: Option<OnFinish>,
}

impl Job {
    /// Whether this row has left public view: a forced job is gone the moment force is accepted,
    /// while its tracer, its conclusion and its name remain this row's until teardown.
    const fn retired(&self) -> bool {
        matches!(self.close, Some(JobCloseMode::Force))
    }
}

/// The half of a job that exists only while a command is in flight.
struct Running {
    /// The command line, for a job table and the job's start line.
    cmd: String,
    /// Process id of the traced child — also its process-group id, so `kill(-pid, …)` reaches the
    /// tracer, the shell it traces and every descendant together.
    pid: libc::pid_t,
    /// The open transaction.
    started: StartedCmd,
}

/// The job table, the name series it draws from, the selected job, and the one terminal size every
/// job's pseudoterminal is set to.
pub(crate) struct JobTable {
    /// The open jobs, in creation order.
    open: Vec<Job>,
    /// Next automatic job name.
    counter: u64,
    /// The job a front-end is looking at, cleared when that job closes.
    current: Option<ShellId>,
    /// Rows and columns, in that order: the geometry every job's terminal is given.
    terminal_size: (u16, u16),
}

impl JobTable {
    /// An empty table whose first automatic name is `1` and whose jobs open at `rows` × `cols`.
    pub(crate) const fn new(rows: u16, cols: u16) -> Self {
        Self {
            open: Vec::new(),
            counter: 1,
            current: None,
            terminal_size: (rows, cols),
        }
    }

    /// The next automatic job name, skipping any a job already occupies.
    ///
    /// Monotonic within a session — a name is never reused while the mux lives — because a job name
    /// is a principal, and reusing one would make two sandboxes indistinguishable in the history.
    fn next_id(&mut self) -> ShellId {
        loop {
            let id = ShellId::from(self.counter.to_string());
            self.counter += 1;
            if !self.open.iter().any(|job| job.id == id) {
                return id;
            }
        }
    }

    /// Removes the job whose sandbox is `uid`, freeing its name, and hands back what it owned.
    ///
    /// The reclamation primitive's half of the bookkeeping: a caller that closes a sandbox by hand
    /// has finished with that principal, and the next spawn may hand the name out again. Its
    /// producers are returned rather than closed here, because that caller reclaims the storage
    /// next and a retained handle's end of file must not arrive while the tree is still on disk.
    ///
    /// `None` is an unknown uid or a row removed before its construction finished: neither leaves
    /// a producer for the caller to hold.
    pub(crate) fn forget(&mut self, uid: &str) -> Option<JobResources> {
        let index = self.open.iter().position(|job| job.sandbox.uid == uid)?;
        let job = self.open.remove(index);
        if self.current.as_ref() == Some(&job.id) {
            self.current = None;
        }
        job.resources
    }

    /// The row for `id`, retired ones included.
    fn find(&self, id: &ShellId) -> Option<&Job> {
        self.open.iter().find(|job| &job.id == id)
    }

    /// The mutable row for `id`, retired ones included.
    fn find_mut(&mut self, id: &ShellId) -> Option<&mut Job> {
        self.open.iter_mut().find(|job| &job.id == id)
    }

    /// Removes a job that is to close and has nothing left in flight, returning it and why.
    ///
    /// A job with a command running or starting is kept whatever its mode: the tree is what that
    /// command is running in, and its transaction is not concluded yet. Idleness of the *table* is
    /// all this can see — a queued or in-flight conclusion is [`Merges`]'s to know about.
    fn take_closable(
        &mut self,
        id: &ShellId,
    ) -> Option<(Sandbox, JobCloseMode, Option<JobResources>)> {
        let index = self.open.iter().position(|job| {
            &job.id == id && job.close.is_some() && job.running.is_none() && !job.starting
        })?;
        let job = self.open.remove(index);
        if self.current.as_ref() == Some(id) {
            self.current = None;
        }
        job.close.map(|mode| (job.sandbox, mode, job.resources))
    }
}

/// The command in flight in a job.
#[derive(Clone, Debug)]
pub struct RunningView {
    /// The command line as submitted.
    pub cmd: String,
    /// Process-group id of the traced command, for signals.
    pub pid: libc::pid_t,
}

/// One job as a caller sees it.
///
/// A view rather than the row itself, because the open transaction a running job holds, and the
/// terminal it owns, are the mux's and must not leave the table.
#[derive(Clone, Debug)]
pub struct JobView {
    /// The job's identity, which is also its principal.
    pub id: ShellId,
    /// The sandbox its commands run in.
    pub sandbox: Sandbox,
    /// The command in flight, or `None` when the job is idle.
    pub running: Option<RunningView>,
    /// A command is being launched into it, so it is neither idle nor yet running.
    pub starting: bool,
    /// A reader's `stop` has been accepted, so it will close and takes no new command.
    pub closing: bool,
}

/// A handle on one open job: its identity, its sandbox and its terminal.
///
/// Cloning shares the terminal; it does not duplicate the job's output, because a job's bytes are
/// the mux's to pump and they reach exactly one frontend. Dropping a handle stops nothing: the job
/// is the mux's, and [`ShellMux::stop`] is how one ends.
#[derive(Clone, Debug)]
pub struct Spawned {
    /// The new job's identity: the one asked for, or the next number when none was.
    pub id: ShellId,
    /// Its sandbox.
    pub sandbox: Sandbox,
    /// Master side of the job's terminal, retained so input still reaches it after the row is
    /// gone. Reading it is the mux's own pump's work, not a holder's.
    terminal: Arc<AsyncFd<OwnedFd>>,
}

/// What a caller that must block is told when the command it asked about ends: the exit status, in
/// the shell's convention, and `-1` for a launch that never produced a command.
///
/// Called once, from the task that concluded the transaction, with no lock held. The transaction
/// itself is not passed: it reaches every frontend as [`FrontendEvent::Finished`], and a caller
/// that only has to stop waiting needs the status. Dropped uncalled instead when its launch fails
/// or the session shuts down first.
pub type OnFinish = Box<dyn FnOnce(i32) + Send>;

/// One command's conclusion, waiting for the conclusion task.
struct Conclusion {
    /// The job it ran in; its verdict is published under this identity.
    id: ShellId,
    /// The open transaction whose wait has already ended.
    started: StartedCmd,
    /// Raw `waitpid(2)` status the command exited with.
    status: i32,
}

/// The conclusions handed off, and what each job still owes.
struct ConclusionQueue {
    /// Conclusions the task has not taken yet.
    pending: VecDeque<Conclusion>,
    /// Per-job count of conclusions submitted and not yet reported.
    active: HashMap<ShellId, usize>,
    /// Set when the session ends: the task returns once the queue drains.
    closed: bool,
}

/// The conclusion task's half of the job machinery.
///
/// Concluding a transaction walks the seed and the snapshot to compute the write set, which on a
/// large seed takes seconds. Doing that on the caller's future is what would make `jobs` wait for
/// the previous command, so callers only ever *submit* here.
pub(crate) struct Merges {
    /// The queue and its bookkeeping.
    queue: Mutex<ConclusionQueue>,
    /// Signals a submission to the task, and a completion to [`Merges::wait_for`].
    signal: Notify,
}

impl Merges {
    /// An empty queue.
    fn new() -> Self {
        Self {
            queue: Mutex::new(ConclusionQueue {
                pending: VecDeque::new(),
                active: HashMap::new(),
                closed: false,
            }),
            signal: Notify::new(),
        }
    }

    /// The queue, recovering a poisoned lock like the rest of this crate: a task that died holding
    /// it left the queue itself intact, and refusing to serve it would strand every open merge.
    fn lock(&self) -> MutexGuard<'_, ConclusionQueue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands `conclusion` to the task and counts it against its job.
    fn submit(&self, conclusion: Conclusion) {
        let mut queue = self.lock();
        if queue.closed {
            return;
        }
        *queue.active.entry(conclusion.id.clone()).or_insert(0) += 1;
        queue.pending.push_back(conclusion);
        drop(queue);
        self.signal.notify_waiters();
    }

    /// The next conclusion, or `None` once the queue is closed and empty.
    async fn take(&self) -> Option<Conclusion> {
        loop {
            // Registered before the check, so a submission that lands between them is not a lost
            // wakeup.
            let notified = self.signal.notified();
            {
                let mut queue = self.lock();
                if let Some(conclusion) = queue.pending.pop_front() {
                    return Some(conclusion);
                }
                if queue.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Marks one conclusion reported and wakes whoever waits on that job.
    fn finish(&self, id: &ShellId) {
        let mut queue = self.lock();
        if let Some(count) = queue.active.get_mut(id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                queue.active.remove(id);
            }
        }
        drop(queue);
        self.signal.notify_waiters();
    }

    /// Waits until job `id` owes no conclusion.
    async fn wait_for(&self, id: &ShellId) {
        loop {
            let notified = self.signal.notified();
            {
                let queue = self.lock();
                if queue.closed || !queue.active.contains_key(id) {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Whether `id` has a conclusion in flight — what a job table prints as `merging`.
    pub(crate) fn is_merging(&self, id: &ShellId) -> bool {
        self.lock().active.contains_key(id)
    }

    /// Whether `id` owes nothing, so its row may be taken.
    fn idle(&self, id: &ShellId) -> bool {
        !self.lock().active.contains_key(id)
    }

    /// Closes the queue immediately; no further conclusion may start.
    fn cancel(&self) {
        let mut queue = self.lock();
        queue.closed = true;
        drop(queue);
        self.signal.notify_waiters();
    }
}

/// The background work one mux owns: the conclusion task, every launch, one byte pump per job and
/// one exit watcher per command.
pub(crate) struct Background {
    /// Whether the long-lived tasks have been started against an `Arc<ShellMux>`.
    started: bool,
    /// Handles joined by [`ShellMux::shutdown`].
    handles: Vec<tokio::task::JoinHandle<()>>,
    /// One byte pump per job, carrying its terminal and instrumentation bytes to the frontend, and
    /// one exit watcher per command.
    ///
    /// A set rather than a list of handles: each ends by itself when its job's streams or its
    /// command do, and [`Self::spawn_detached`] joins the ones that already have, so nobody has to
    /// notice which job it was. [`ShellMux::shutdown`] aborts and joins whatever is left in one
    /// call.
    detached: tokio::task::JoinSet<()>,
}

impl Background {
    /// A set with nothing started yet.
    pub(crate) fn new() -> Self {
        Self {
            started: false,
            handles: Vec::new(),
            detached: tokio::task::JoinSet::new(),
        }
    }

    /// Registers a task that ends by itself — a job's byte pump, a command's exit watcher — so
    /// [`ShellMux::shutdown`] cancels whatever is left of them.
    ///
    /// Neither kind keeps the mux alive: a pump holds only the frontend, the job's readers and its
    /// identity, and a watcher holds a weak reference it upgrades for the length of one reap. So a
    /// session whose last handle is dropped is not kept alive by the jobs it was still reading.
    ///
    /// The tasks that have already finished are taken first: a set holds a finished task's record
    /// until someone joins it, so a long session that opened and closed many jobs would otherwise
    /// accumulate one record per job for its whole life. Only the ready ones are taken — a task
    /// still running is neither awaited nor aborted here — and one that ended in a panic is
    /// dropped exactly as [`ShellMux::shutdown`] drops one.
    fn spawn_detached(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        while self.detached.try_join_next().is_some() {}
        self.detached.spawn(task);
    }
}

impl ShellMux {
    /// The job table, recovering a poisoned lock like the rest of this crate.
    pub(crate) fn job_table(&self) -> MutexGuard<'_, JobTable> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The background task set, with the same poisoning recovery.
    fn background(&self) -> MutexGuard<'_, Background> {
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the conclusion task, once per mux.
    ///
    /// Deferred to the first operation rather than done in [`Self::new`] because the task needs a
    /// `Weak<Self>`, which does not exist until the caller has put the mux in an `Arc`. It holds a
    /// weak reference and takes a strong one only while doing work, so it never keeps the mux
    /// alive.
    fn ensure_background(self: &Arc<Self>) {
        let mut background = self.background();
        if background.started {
            return;
        }
        background.started = true;
        let concluder = Arc::downgrade(self);
        background
            .handles
            .push(tokio::spawn(async move { conclude_queue(concluder).await }));
        drop(background);
    }

    /// Registers a task this mux owns, so [`Self::shutdown`] joins it.
    fn own_task(&self, handle: tokio::task::JoinHandle<()>) {
        self.background().handles.push(handle);
    }

    /// Opens a job over `dir`, gives it a terminal, and reserves it for `cmd` when one is given.
    ///
    /// `id` is `None` for the next number in the `1`, `2`, … series. A name a live job already
    /// holds is refused, because a job name is a capability principal and two sandboxes sharing one
    /// would be indistinguishable in the history. `dir` is seed-relative.
    ///
    /// The job's pseudoterminal is created at the mux's own size, and its shell is built with that
    /// terminal on fds 0, 1 and 2 and its instrumentation pipe on fd 3. No snapshot is taken: a
    /// command retakes one anyway, and a job whose commands all bypass never needs one.
    ///
    /// `cmd` is the command the job is being opened *for*. It is launched by a task this mux owns,
    /// so a front-end's own prompt is never held for a snapshot and a tracer spawn.
    ///
    /// # Errors
    ///
    /// Fails when `id` is taken, when `dir` escapes the seed or names nothing in it, or when the
    /// terminal, the pipe or the shell could not be created. A failed construction closes every
    /// descriptor it opened and releases the name.
    pub async fn spawn(
        self: &Arc<Self>,
        dir: &str,
        id: Option<ShellId>,
        cmd: Option<&str>,
    ) -> Result<Spawned, MuxError> {
        self.ensure_background();
        let anonymous = id.is_none();
        let (id, sandbox, size) = {
            let mut table = self.job_table();
            let id = match id {
                Some(id) => {
                    if table.find(&id).is_some() {
                        return Err(MuxError::JobExists(id));
                    }
                    id
                }
                None => table.next_id(),
            };
            let sandbox = self.new_sandbox(&id, dir)?;
            let size = table.terminal_size;
            table.open.push(Job {
                id: id.clone(),
                sandbox: sandbox.clone(),
                resources: None,
                running: None,
                starting: cmd.is_some(),
                close: (anonymous && cmd.is_some()).then_some(JobCloseMode::Automatic),
                done: None,
            });
            drop(table);
            (id, sandbox, size)
        };
        self.announce(FrontendEvent::Changed);

        let spawned = match self.build_resources(&id, &sandbox, size).await {
            Ok(spawned) => spawned,
            Err(error) => {
                let mut table = self.job_table();
                if let Some(index) = table.open.iter().position(|job| job.id == id) {
                    table.open.remove(index);
                }
                drop(table);
                self.launched.notify_waiters();
                self.announce(FrontendEvent::Changed);
                return Err(error);
            }
        };

        if let Some(cmd) = cmd {
            let mux = Arc::clone(self);
            let launch_id = id.clone();
            let cmd = cmd.to_string();
            self.own_task(tokio::spawn(async move {
                if let Err(error) = mux.launch_into(&launch_id, &cmd, None).await {
                    mux.report_launch_failure(&launch_id, error).await;
                }
            }));
        }
        Ok(spawned)
    }

    /// Builds one job's terminal, instrumentation pipe and shell, publishes them, and starts the
    /// pump that carries the job's bytes to the frontend.
    ///
    /// The shell is awaited with no lock held; the size is rechecked and reapplied under the table
    /// lock immediately before publication, so a [`Self::resize`] that ran during construction is
    /// not lost on the terminal it could not see yet. The frontend is told the job is open only
    /// once that is settled, and before any command it was opened for can start.
    async fn build_resources(
        self: &Arc<Self>,
        id: &ShellId,
        sandbox: &Sandbox,
        size: (u16, u16),
    ) -> Result<Spawned, MuxError> {
        let (rows, cols) = size;
        let (master, slave) = brush_core::sys::terminal::open_pty(rows, cols)?;
        let (receiver, writer) = instrumentation_pipe()?;

        let shell_slave = slave.try_clone()?;
        let shell_writer = writer.try_clone()?;
        let terminal: brush_core::openfiles::OpenFile = std::fs::File::from(shell_slave).into();
        let mut fds = HashMap::new();
        fds.insert(brush_core::openfiles::OpenFiles::STDIN_FD, terminal.clone());
        fds.insert(
            brush_core::openfiles::OpenFiles::STDOUT_FD,
            terminal.clone(),
        );
        fds.insert(brush_core::openfiles::OpenFiles::STDERR_FD, terminal);
        fds.insert(
            brush_core::openfiles::OpenFiles::STDINSTR_FD,
            std::fs::File::from(shell_writer).into(),
        );
        let working_dir = self.persistence().seed.join(&sandbox.dir);
        let shell = self.build_shell(Some(working_dir), fds).await?;

        let terminal = Arc::new(AsyncFd::new(master)?);
        let (release, released) = tokio::sync::oneshot::channel::<()>();

        let latest = {
            let mut table = self.job_table();
            let latest = table.terminal_size;
            let Some(job) = table.find_mut(id) else {
                return Err(MuxError::NoSuchJob(id.clone()));
            };
            job.resources = Some(JobResources {
                terminal: Arc::clone(&terminal),
                slave,
                writer,
                shell,
                _release: release,
            });
            drop(table);
            latest
        };
        // After publication and outside the lock: the ioctl is a syscall on a descriptor nothing
        // else may take away while the row holds it.
        if latest != size {
            brush_core::sys::terminal::resize_pty(terminal.get_ref().as_fd(), latest.0, latest.1)?;
        }
        self.launched.notify_waiters();

        let spawned = Spawned {
            id: id.clone(),
            sandbox: sandbox.clone(),
            terminal: Arc::clone(&terminal),
        };
        self.announce(FrontendEvent::Opened(&spawned));
        // Publication is a state change, not only a new handle: the reservation announced `Changed`
        // while this row still had no resources, so a display refreshed on that alone goes on
        // drawing a job that is now idle and ready as one that is still opening.
        self.announce(FrontendEvent::Changed);
        // Constructed outside the guard, so nothing but the registration itself is held under it.
        let pump = pump_job(
            self.frontend(),
            sandbox.clone(),
            terminal,
            receiver,
            released,
        );
        self.background().spawn_detached(pump);
        Ok(spawned)
    }

    /// Starts `cmd` in the job named `id`.
    ///
    /// Returns once the command is running: its snapshot has been retaken and its tracer spawned.
    /// Its output reaches the frontend on its own, and its conclusion reaches every frontend as
    /// [`FrontendEvent::Finished`]. `done`, when given, is called exactly once when the command it
    /// started ends. It is dropped uncalled when this returns an error, or when the session shuts
    /// down before the command ends; a caller blocked on it is released either way.
    ///
    /// # Errors
    ///
    /// Fails when no job answers to `id`, when an accepted stop has already closed that job, when
    /// it is already running or starting a command, or when the snapshot could not be retaken or
    /// the tracer spawned.
    pub async fn start_in(
        self: &Arc<Self>,
        id: &ShellId,
        cmd: &str,
        done: Option<OnFinish>,
    ) -> Result<(), MuxError> {
        self.ensure_background();
        {
            let mut table = self.job_table();
            let Some(job) = table.find_mut(id) else {
                return Err(MuxError::NoSuchJob(id.clone()));
            };
            // Before the busy check, because an accepted stop is not something a new command may
            // postpone: a closing job answers with what it is, not with what it is doing.
            if job.close.is_some_and(JobCloseMode::explicit) {
                return Err(MuxError::JobClosing(id.clone()));
            }
            if job.running.is_some() || job.starting {
                return Err(MuxError::JobBusy(id.clone()));
            }
            job.starting = true;
            drop(table);
        }
        self.announce(FrontendEvent::Changed);
        // A command may not start before its predecessor's conclusion has landed: the launch
        // retakes the snapshot from the seed, so starting early would copy a seed the merge has not
        // reached yet — and would delete the very tree that merge is diffing.
        self.merges.wait_for(id).await;
        self.launch_into(id, cmd, done).await
    }

    /// Starts `cmd` in the job named `id`, which is in the table and marked `starting`.
    ///
    /// The second half of [`Self::spawn`] given a command, and the tail of [`Self::start_in`]: the
    /// only difference between the two is who took the reservation. A force requested while the job
    /// was still `starting` is carried out here, under the same table lock that publishes the new
    /// command: the group cannot be signalled before it exists, and signalling it after the lock is
    /// released would race a reader who is told the job is gone.
    ///
    /// # Errors
    ///
    /// Fails when no job answers to `id`, or when the snapshot cannot be retaken or the tracer
    /// spawned. A failed launch only clears the reservation.
    /// [`MuxError::JobTermination`] is the one error that reports a *live* command: the launch
    /// succeeded and the deferred kill did not, so the row is visibly closing again and its
    /// sandbox must be left alone.
    async fn launch_into(
        self: &Arc<Self>,
        id: &ShellId,
        cmd: &str,
        done: Option<OnFinish>,
    ) -> Result<(), MuxError> {
        let launched = self.launch_command(id, cmd, done).await;
        self.launched.notify_waiters();
        launched
    }

    /// The body of a launch, without the completion notification its callers owe.
    async fn launch_command(
        self: &Arc<Self>,
        id: &ShellId,
        cmd: &str,
        done: Option<OnFinish>,
    ) -> Result<(), MuxError> {
        // The private row, not `job()`: a force request has already taken the public view away, and
        // the reserved launch it accepted still has to complete.
        let prepared = {
            let table = self.job_table();
            let Some(job) = table.find(id) else {
                return Err(MuxError::NoSuchJob(id.clone()));
            };
            let Some(resources) = &job.resources else {
                return Err(MuxError::NoSuchJob(id.clone()));
            };
            let plan = self.plan_for(&resources.shell, &job.sandbox, cmd);
            let prepared = (
                job.sandbox.clone(),
                plan,
                resources.slave.as_raw_fd(),
                resources.writer.as_raw_fd(),
            );
            drop(table);
            prepared
        };
        let (sandbox, plan, terminal, instrumentation) = prepared;

        // Before the blocking section, because building a shell is asynchronous: the launch reads
        // this principal's exported environment out of a cache, and a cache miss inside a blocking
        // task would have nowhere to await.
        if let Err(error) = self.ensure_principal(&sandbox.principal()).await {
            let mut table = self.job_table();
            if let Some(job) = table.find_mut(id) {
                job.starting = false;
            }
            drop(table);
            self.announce(FrontendEvent::Changed);
            return Err(error);
        }

        // The command's start is a snapshot and a fork: blocking work with owned inputs, off every
        // asynchronous worker.
        let mux = Arc::clone(self);
        let launch = {
            let cmd = cmd.to_string();
            let sandbox = sandbox.clone();
            tokio::task::spawn_blocking(move || {
                mux.start_cmd(&sandbox, &cmd, plan, terminal, instrumentation)
            })
            .await
            .map_err(|error| MuxError::Exec(format!("launch task: {error}")))?
        };

        let (mut started, exit) = match launch {
            Ok(launched) => launched,
            Err(error) => {
                let mut table = self.job_table();
                if let Some(job) = table.find_mut(id) {
                    job.starting = false;
                }
                drop(table);
                self.announce(FrontendEvent::Changed);
                return Err(error);
            }
        };
        let pid = started.pid();
        let mut table = self.job_table();
        let mut deferred = Ok(());
        if let Some(job) = table.find_mut(id) {
            job.starting = false;
            if job.retired()
                && let Err(error) = started.force_stop()
            {
                // The command is alive and unkillable, so it must not stay invisible: a job a
                // reader cannot see is a job a reader cannot stop again.
                job.close = Some(JobCloseMode::Graceful);
                deferred = Err(MuxError::JobTermination {
                    job: id.clone(),
                    source: Box::new(error),
                });
            }
            // Installed only for a launch this call reports as started: a caller told its start
            // failed must not be called back for it later.
            if deferred.is_ok() {
                job.done = done;
            }
            job.running = Some(Running {
                cmd: cmd.to_string(),
                pid,
                started,
            });
        }
        drop(table);
        self.announce(FrontendEvent::Changed);
        // After publication, so the watcher always finds the row it is to update; the pidfd is
        // already open, so a command that ended between the fork and the publication is observed
        // as soon as this task first polls.
        let watch = watch_command(Arc::downgrade(self), id.clone(), pid, exit);
        self.background().spawn_detached(watch);
        deferred
    }

    /// Reports a failed launch, and closes the job it opened.
    ///
    /// A launch that never produced a command has no exit status and no transaction, so the
    /// failure itself is the observation: a front-end renders it exactly as it renders any other
    /// job event. The row is then reclaimed, because nothing ever ran in it and its tree is one
    /// nobody would look at. [`MuxError::JobTermination`] is the exception: its command *is* alive,
    /// so the job stays and keeps its storage.
    ///
    /// Delivered by the one path every completion goes through, outside the table lock. Nothing
    /// waits on this path: [`Self::spawn`] registers no callback.
    async fn report_launch_failure(self: &Arc<Self>, id: &ShellId, error: MuxError) {
        let retained = matches!(error, MuxError::JobTermination { .. });
        self.deliver(id, -1, &Arc::new(Err(error)));

        let closed = {
            let mut table = self.job_table();
            let closed = if retained {
                None
            } else {
                table
                    .find_mut(id)
                    .map(|job| job.close = Some(JobCloseMode::Graceful))
                    .and_then(|()| table.take_closable(id))
            };
            drop(table);
            closed
        };
        if let Some(closed) = closed {
            self.reclaim(closed).await;
        }
    }

    /// Announces one completion to the frontend, and then to the caller that asked to be told.
    ///
    /// The sandbox and the callback are taken out of the protected row and the lock is released
    /// before either delivery, because a frontend callback may read the mux back. The row, not its
    /// resources: a completion names a sandbox and a status, neither of which needs a terminal.
    fn deliver(&self, id: &ShellId, exit_code: i32, outcome: &Arc<Result<CmdOutcome, MuxError>>) {
        let published = {
            let mut table = self.job_table();
            let published = table
                .find_mut(id)
                .map(|job| (job.sandbox.clone(), job.done.take()));
            drop(table);
            published
        };
        let Some((sandbox, done)) = published else {
            return;
        };
        self.announce(FrontendEvent::Finished {
            shell: &sandbox,
            exit_code,
            outcome,
        });
        if let Some(done) = done {
            done(exit_code);
        }
    }

    /// Whether `id` has a conclusion in flight — what a job table prints as `merging`.
    ///
    /// A cheap synchronous snapshot, like [`Self::jobs`]: the row is out of the table from the
    /// moment its command ends, and this is what says the transaction is not over.
    #[must_use]
    pub fn is_merging(&self, id: &ShellId) -> bool {
        self.merges.is_merging(id)
    }

    /// Every open job, in creation order. A forced job is not one: it left public view when its
    /// stop was accepted.
    ///
    /// A cheap synchronous snapshot: the lock it takes is held for the copy alone, never across a
    /// snapshot, an execution or a conclusion.
    #[must_use]
    pub fn jobs(&self) -> Vec<JobView> {
        self.job_table()
            .open
            .iter()
            .filter(|job| !job.retired())
            .map(job_view)
            .collect()
    }

    /// One job, by identity, excluding a forced one for the reason [`Self::jobs`] does.
    #[must_use]
    pub fn job(&self, id: &ShellId) -> Option<JobView> {
        self.job_table()
            .open
            .iter()
            .find(|job| &job.id == id && !job.retired())
            .map(job_view)
    }

    /// The job a front-end has selected, if it is still open.
    #[must_use]
    pub fn current_job(&self) -> Option<JobView> {
        let table = self.job_table();
        let current = table.current.clone()?;
        let view = table
            .open
            .iter()
            .find(|job| job.id == current && !job.retired())
            .map(job_view);
        drop(table);
        view
    }

    /// Keeps a job a reader has taken an interest in: it will not close itself any more.
    ///
    /// Only the automatic closure of a job nobody named is cancelled. A reader's own `stop` is a
    /// decision, not a default, and selecting the job afterwards does not revoke it.
    pub fn keep(&self, id: &ShellId) {
        let mut table = self.job_table();
        if let Some(job) = table.find_mut(id)
            && job.close == Some(JobCloseMode::Automatic)
        {
            job.close = None;
        }
        drop(table);
        self.announce(FrontendEvent::Changed);
    }

    /// Selects `id` as the job a front-end is looking at, waiting for a launch already in flight.
    ///
    /// Selecting stops nothing: a job a reader has already stopped is refused, because an explicit
    /// stop is a decision this may not quietly cancel.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::NoSuchJob`] when nothing visible answers to `id`, and with
    /// [`MuxError::JobClosing`] when an accepted stop has already closed it.
    pub async fn switch(self: &Arc<Self>, id: &ShellId) -> Result<JobView, MuxError> {
        {
            let table = self.job_table();
            let Some(job) = table.find(id).filter(|job| !job.retired()) else {
                return Err(MuxError::NoSuchJob(id.clone()));
            };
            if job.close.is_some_and(JobCloseMode::explicit) {
                return Err(MuxError::JobClosing(id.clone()));
            }
            drop(table);
        }
        // A reader who brought this job up means to look at it, so it is no longer one the series
        // can reclaim on its own.
        self.keep(id);
        self.await_launch(id).await;
        let mut table = self.job_table();
        let Some(view) = table.find(id).filter(|job| !job.retired()).map(job_view) else {
            return Err(MuxError::NoSuchJob(id.clone()));
        };
        table.current = Some(id.clone());
        drop(table);
        self.announce(FrontendEvent::Changed);
        Ok(view)
    }

    /// Waits until nothing is being launched into job `id`.
    ///
    /// `starting` is the mux's own answer to "a command is being launched into this job" — the flag
    /// `take_closable` and [`Self::start_in`] refuse on — so a front-end keeps no second record of
    /// it. [`Self::spawn`] sets it before it returns, so there is no window in which a launch is
    /// pending and this says otherwise.
    async fn await_launch(&self, id: &ShellId) {
        loop {
            // Registered before the check: a publication that lands between them is not a lost
            // wakeup.
            let notified = self.launched.notified();
            {
                let table = self.job_table();
                let pending = table
                    .find(id)
                    .is_some_and(|job| job.starting || job.resources.is_none());
                drop(table);
                if !pending {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Accepts a reader's `stop` for the job named `id`, gracefully or by force.
    ///
    /// Graceful sends no signal: it records that the job closes once its command and that command's
    /// conclusion are over, and a repeated request is harmless. It returns on acceptance rather
    /// than blocking for the running command.
    ///
    /// Force kills the running command's process group — the tracer, the shell it traces and every
    /// descendant, because a running command *is* one group — and retires the row at once; its
    /// storage is reclaimed when the killed transaction's lifecycle is over, never before. A job
    /// that is merely `starting` records the request, and the launch carries it out when the group
    /// exists.
    ///
    /// Force upgrades a graceful request. The reverse cannot happen: a forced job is already gone
    /// from public view, so a later plain `stop` finds nothing to downgrade.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::NoSuchJob`] when nothing visible answers to `id`, and with the kill
    /// failure when a forced job's process group could not be signalled.
    pub async fn stop(self: &Arc<Self>, id: &ShellId, force: bool) -> Result<(), MuxError> {
        // Queue first, then the job table — the one order these two locks are ever taken in, so a
        // request arriving between a conclusion's close check and its bookkeeping is not lost.
        let closed = {
            let queue = self.merges.lock();
            let mut table = self.job_table();
            let Some(job) = table.find_mut(id).filter(|job| !job.retired()) else {
                return Err(MuxError::NoSuchJob(id.clone()));
            };
            if force {
                if let Some(running) = job.running.as_mut() {
                    running.started.force_stop()?;
                }
                job.close = Some(JobCloseMode::Force);
            } else {
                job.close = Some(JobCloseMode::Graceful);
            }
            let closed = if queue.active.contains_key(id) {
                None
            } else {
                table.take_closable(id)
            };
            drop(table);
            drop(queue);
            closed
        };
        self.announce(FrontendEvent::Changed);
        if let Some(closed) = closed {
            self.reclaim(closed).await;
        }
        Ok(())
    }

    /// Applies `rows` × `cols` to every job this mux owns, and to every job opened afterwards.
    ///
    /// One size for the whole mux: a front-end that resizes resizes everything it is showing,
    /// including the jobs it is not looking at, because a job whose terminal disagrees with the
    /// window redraws wrongly the moment it is selected. A repeated resize reapplies the size,
    /// because a command may have changed the terminal underneath.
    ///
    /// The frontend is told the new geometry whatever the pass reported: an accepted resize is the
    /// mux's own size from the moment the table takes it, and a terminal that refused the ioctl is
    /// one dead descriptor rather than a rejected size.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::InvalidTerminalSize`] when a dimension is zero, changing nothing at
    /// all — including telling the frontend. Every existing terminal is attempted; the first I/O
    /// failure is reported once the pass is over, so one dead terminal does not silently skip the
    /// rest.
    pub async fn resize(self: &Arc<Self>, rows: u16, cols: u16) -> Result<(), MuxError> {
        validate_size(rows, cols)?;
        let terminals = {
            let mut table = self.job_table();
            table.terminal_size = (rows, cols);
            let terminals: Vec<Arc<AsyncFd<OwnedFd>>> = table
                .open
                .iter()
                .filter_map(|job| job.resources.as_ref())
                .map(|resources| Arc::clone(&resources.terminal))
                .collect();
            drop(table);
            terminals
        };
        let applied = tokio::task::spawn_blocking(move || {
            let mut failure = Ok(());
            for terminal in terminals {
                let applied =
                    brush_core::sys::terminal::resize_pty(terminal.get_ref().as_fd(), rows, cols);
                if let Err(error) = applied
                    && failure.is_ok()
                {
                    failure = Err(MuxError::Io(error));
                }
            }
            failure
        })
        .await
        .map_err(|error| MuxError::Exec(format!("resize task: {error}")))?;
        self.announce(FrontendEvent::Resized { rows, cols });
        applied
    }

    /// Asks to be told when the command now running in `id` ends.
    ///
    /// `false` when nothing is running in that job, or when a caller is already waiting on its
    /// command: there is no completion left for `done` to be called with, and the caller must not
    /// block on one. A job that is still *starting* is also `false` — its callback, if any, is the
    /// launch's to install — and [`Self::switch`] waits a launch out, which is how `fg` never sees
    /// one. Registered under the job table's lock, the lock the reap takes, so a command that ends
    /// between a caller's look at the table and this call is still reported.
    pub fn on_finish(&self, id: &ShellId, done: OnFinish) -> bool {
        let mut table = self.job_table();
        let registered = match table.find_mut(id) {
            Some(job) if job.running.is_some() && job.done.is_none() => {
                job.done = Some(done);
                true
            }
            _ => false,
        };
        drop(table);
        registered
    }

    /// Writes `bytes` to the job's terminal, as if they had been typed at it.
    ///
    /// Partial writes are retried, so the whole slice reaches the terminal or an error is reported.
    ///
    /// # Errors
    ///
    /// Fails with [`MuxError::JobClosing`] when the job has been closed, and with
    /// [`MuxError::Io`] when the terminal could not take the bytes.
    pub async fn write_input(&self, job: &Spawned, bytes: &[u8]) -> Result<(), MuxError> {
        if self.job(&job.id).is_none_or(|view| view.closing) {
            return Err(MuxError::JobClosing(job.id.clone()));
        }
        let mut written = 0;
        while written < bytes.len() {
            let mut guard = job.terminal.writable().await.map_err(MuxError::Io)?;
            let attempt = guard.try_io(|inner| {
                let slice = &bytes[written..];
                // SAFETY: `write` receives an open descriptor, a valid pointer and the length of
                // the slice behind it.
                let count = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        slice.as_ptr().cast(),
                        slice.len(),
                    )
                };
                if count < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(usize::try_from(count).unwrap_or(0))
            });
            match attempt {
                Ok(Ok(count)) => written += count,
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Ok(Err(error)) => return Err(MuxError::Io(error)),
                // Not ready after all; the guard is cleared and the next await waits again.
                Err(_would_block) => {}
            }
        }
        Ok(())
    }

    /// Reaps `pid` and submits its conclusion, if it is still the command job `id` is running.
    ///
    /// Called once per command, by that command's own watcher, after its pidfd reported the child
    /// waitable. The reap and the row update happen under one short job-table lock, which is the
    /// same lock a forced stop takes, and nothing reaps the child before that lock is held: a stop
    /// can therefore never signal a pid that has already been reaped and whose number the kernel
    /// may have handed out again.
    fn reap_command(self: &Arc<Self>, id: &ShellId, pid: libc::pid_t) {
        let reaped = {
            let mut table = self.job_table();
            let reaped = table
                .find_mut(id)
                .filter(|job| {
                    job.running
                        .as_ref()
                        .is_some_and(|running| running.pid == pid)
                })
                .and_then(|job| job.running.take())
                .map(|running| (running.started, reap_status(pid)));
            drop(table);
            reaped
        };
        let Some((started, status)) = reaped else {
            return;
        };
        self.merges.submit(Conclusion {
            id: id.clone(),
            started,
            status,
        });
        self.announce(FrontendEvent::Changed);
    }

    /// Concludes one command: translate, authorize, merge, publish, and reclaim if the job is done.
    ///
    /// Runs on the conclusion task, never on a caller's future, because the diff is two tree walks.
    async fn conclude_one(self: &Arc<Self>, conclusion: Conclusion) {
        let Conclusion {
            id,
            started,
            status,
        } = conclusion;
        let mux = Arc::clone(self);
        let concluded = tokio::task::spawn_blocking(move || mux.conclude_cmd(started, status))
            .await
            .unwrap_or_else(|error| Err(MuxError::Exec(format!("conclusion task: {error}"))));
        let exit_code = match &concluded {
            Ok(outcome) => outcome_exit_code(outcome),
            Err(_) => -1,
        };
        // A forced job whose processes could not be proven gone keeps its tree: something may still
        // be writing into it. Startup reclaims it.
        let retained = matches!(concluded, Err(MuxError::JobTermination { .. }));
        let outcome = Arc::new(concluded);

        self.deliver(&id, exit_code, &outcome);

        // One operation, not a close check followed by bookkeeping: a stop arriving between the two
        // would find the job busy and then find nobody left to close it.
        let closed = {
            let queue = self.merges.lock();
            drop(queue);
            self.merges.finish(&id);
            let mut table = self.job_table();
            let closed = if self.merges.idle(&id) {
                table.take_closable(&id)
            } else {
                None
            };
            drop(table);
            closed
        };
        if let Some(closed) = closed
            && !retained
        {
            self.reclaim(closed).await;
        }
        self.announce(FrontendEvent::Changed);
    }

    /// Reclaims a closed job's storage, and only then closes its terminal.
    ///
    /// The storage goes first and the resources last: closing the pseudoterminal slave and the
    /// instrumentation writer is what turns a retained handle's reads into end of file, and a
    /// caller that reads that end of file as "this job is over" must not see it while the tree the
    /// job named is still on disk.
    async fn reclaim(self: &Arc<Self>, closed: (Sandbox, JobCloseMode, Option<JobResources>)) {
        let (sandbox, _mode, resources) = closed;
        let mux = Arc::clone(self);
        let _ = tokio::task::spawn_blocking(move || mux.close_sandbox(&sandbox)).await;
        drop(resources);
    }

    /// Ends the session: no new admission, outstanding commands terminated and the callers waiting
    /// on them released, owned tasks joined, remaining byte pumps and exit watchers cancelled, and
    /// the frontend detached.
    ///
    /// Startup owns persistent recovery and reclamation, so nothing here sweeps snapshots or the
    /// write-ahead log: an interrupted session is repaired by the next one, which is the only place
    /// that can tell an unfinished transaction from a live one. The caller's runtime is neither
    /// created nor shut down here.
    ///
    /// An ordinary [`Self::stop`] drains its job through [`FrontendEvent::Closed`]; a whole-session
    /// shutdown cancels whatever delivery is left rather than promising to flush every unfinished
    /// job. The host stops issuing operations and awaits its in-flight calls before calling this.
    ///
    /// # Errors
    ///
    /// Fails with the first termination failure observed while killing outstanding commands.
    pub async fn shutdown(self: &Arc<Self>) -> Result<(), MuxError> {
        self.merges.cancel();

        let mut failure = Ok(());
        let abandoned = {
            let mut table = self.job_table();
            let mut abandoned = Vec::new();
            for job in &mut table.open {
                if let Some(running) = job.running.as_mut()
                    && let Err(error) = running.started.force_stop()
                    && failure.is_ok()
                {
                    failure = Err(error);
                }
                // Its conclusion was cancelled above, so no status will come: the caller waiting
                // on this command is released now rather than when the mux is finally dropped.
                abandoned.extend(job.done.take());
            }
            drop(table);
            abandoned
        };
        // Outside the lock, like every other callback delivery.
        drop(abandoned);

        let handles = std::mem::take(&mut self.background().handles);
        for handle in handles {
            let _ = handle.await;
        }

        // Before the detached tasks: the terminals and shells a job owns are what a still-running
        // conclusion would have been publishing into, and closing them is what ends the reads below.
        {
            let mut table = self.job_table();
            for job in &mut table.open {
                job.resources = None;
            }
            drop(table);
        }

        // Tokio aborts and joins whatever is left reading or watching. No frontend guard is held
        // across it.
        let mut detached = std::mem::take(&mut self.background().detached);
        detached.shutdown().await;
        self.detach();
        failure
    }
}

/// One row as a caller sees it.
fn job_view(job: &Job) -> JobView {
    JobView {
        id: job.id.clone(),
        sandbox: job.sandbox.clone(),
        running: job.running.as_ref().map(|running| RunningView {
            cmd: running.cmd.clone(),
            pid: running.pid,
        }),
        starting: job.starting || job.resources.is_none(),
        closing: job.close.is_some_and(JobCloseMode::explicit),
    }
}

/// The exit code an outcome reports, for the completion a waiter observes.
const fn outcome_exit_code(outcome: &CmdOutcome) -> i32 {
    match outcome {
        CmdOutcome::Committed { exit_code, .. }
        | CmdOutcome::DeniedCaps { exit_code, .. }
        | CmdOutcome::ExecFailed { exit_code, .. }
        | CmdOutcome::Bypassed { exit_code, .. }
        | CmdOutcome::Escaped { exit_code, .. } => *exit_code,
        // Neither ran to a status a caller could act on.
        CmdOutcome::StaleSnapshot { .. } | CmdOutcome::Unsupported { .. } => 1,
    }
}

/// Refuses a terminal geometry with a zero dimension.
pub(crate) const fn validate_size(rows: u16, cols: u16) -> Result<(), MuxError> {
    if rows == 0 || cols == 0 {
        return Err(MuxError::InvalidTerminalSize { rows, cols });
    }
    Ok(())
}

/// Creates one job's instrumentation pipe: a non-blocking reader for the mux, a blocking writer for
/// the commands that report through fd 3.
///
/// The writer must block: a command writing to its third standard stream may not be told to try
/// again, because it has no way to.
fn instrumentation_pipe() -> Result<(tokio::net::unix::pipe::Receiver, OwnedFd), MuxError> {
    let mut ends: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `pipe2` writes exactly two descriptors through the pointer we pass.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(MuxError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: the read descriptor is fresh and nothing else refers to it.
    let reader = unsafe { OwnedFd::from_raw_fd(ends[0]) };
    // SAFETY: as above, for the write descriptor.
    let writer = unsafe { OwnedFd::from_raw_fd(ends[1]) };
    // SAFETY: `fcntl` receives an open descriptor and scalar arguments.
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(MuxError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: as above; the flag word is the one just read, minus non-blocking.
    if unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(MuxError::Io(std::io::Error::last_os_error()));
    }
    let receiver = tokio::net::unix::pipe::Receiver::from_file(std::fs::File::from(reader))
        .map_err(MuxError::Io)?;
    Ok((receiver, writer))
}

/// Reads whatever a job's terminal has produced into `buffer`, returning how many bytes.
///
/// Bytes are preserved exactly: escape sequences, non-UTF-8 output and a final line with no
/// newline all arrive as they were written. `0` is end of file, which on Linux is how a
/// pseudoterminal reports that its last writer is gone.
async fn read_terminal(terminal: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = terminal.readable().await?;
        let attempt = guard.try_io(|inner| {
            // SAFETY: `read` receives an open descriptor, a valid writable pointer and the
            // length of the slice behind it.
            let count = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(usize::try_from(count).unwrap_or(0))
        });
        match attempt {
            Ok(Ok(count)) => return Ok(count),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {}
            // A pseudoterminal master whose slave has been closed answers `EIO`. That is a
            // hangup, not a failure: it is this stream's end of file.
            Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => return Ok(0),
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => {}
        }
    }
}

/// Carries one job's two streams to the frontend for as long as the job produces bytes.
///
/// Both are drained concurrently and unconditionally, the jobs nobody is looking at included:
/// a pseudoterminal whose master nobody reads fills its buffer and stops the command writing into
/// it, which is exactly the deadlock a front-end that only drained the selected job used to hit.
///
/// Nothing here holds a reference to the mux. The end of the job is the end of its resources: when
/// both readers are done, this waits for the release token the row owned to be dropped before
/// announcing [`FrontendEvent::Closed`], so two failed reads alone never claim a live job closed.
async fn pump_job(
    frontend: Arc<Mutex<dyn MarshFrontend>>,
    shell: Sandbox,
    terminal: Arc<AsyncFd<OwnedFd>>,
    mut instrumentation: tokio::net::unix::pipe::Receiver,
    released: tokio::sync::oneshot::Receiver<()>,
) {
    let mut terminal_buffer = [0u8; 8192];
    let mut instrumentation_buffer = [0u8; 4096];
    let mut terminal_open = true;
    let mut instrumentation_open = true;

    while terminal_open || instrumentation_open {
        tokio::select! {
            read = read_terminal(&terminal, &mut terminal_buffer), if terminal_open => {
                match read {
                    Ok(0) => terminal_open = false,
                    Ok(count) => notify(&frontend, FrontendEvent::Terminal {
                        shell: &shell,
                        bytes: &terminal_buffer[..count],
                    }),
                    Err(error) => {
                        notify(&frontend, FrontendEvent::IoError { shell: &shell, error: &error });
                        terminal_open = false;
                    }
                }
            }
            read = instrumentation.read(&mut instrumentation_buffer), if instrumentation_open => {
                match read {
                    Ok(0) => instrumentation_open = false,
                    Ok(count) => notify(&frontend, FrontendEvent::Instrumentation {
                        shell: &shell,
                        bytes: &instrumentation_buffer[..count],
                    }),
                    Err(error) => {
                        notify(&frontend, FrontendEvent::IoError { shell: &shell, error: &error });
                        instrumentation_open = false;
                    }
                }
            }
        }
    }

    // The row's own token, so this ends when the job's resources are released — which the mux does
    // only after the storage that job named is gone. A resolved `Err` is the sender dropping,
    // which is the signal.
    let _ = released.await;
    notify(&frontend, FrontendEvent::Closed(&shell));
}

/// One command's exit watcher: the only reaper of that command's child.
///
/// A weak reference, so a watcher never keeps the mux alive. Everything after the readiness edge
/// is synchronous, so a watcher aborted at shutdown is aborted either before it observed the exit
/// or after it submitted the conclusion, never between the reap and the row update.
async fn watch_command(mux: Weak<ShellMux>, id: ShellId, pid: libc::pid_t, exit: AsyncFd<OwnedFd>) {
    if exit.readable().await.is_err() {
        return;
    }
    let Some(mux) = mux.upgrade() else {
        return;
    };
    mux.reap_command(&id, pid);
    drop(mux);
}

/// The mux's conclusion task: one queue, in submission order, off every caller's future.
async fn conclude_queue(mux: Weak<ShellMux>) {
    loop {
        let conclusion = {
            let Some(strong) = mux.upgrade() else {
                return;
            };
            let taken = strong.merges.take().await;
            drop(strong);
            taken
        };
        let Some(conclusion) = conclusion else {
            return;
        };
        let Some(strong) = mux.upgrade() else {
            return;
        };
        strong.conclude_one(conclusion).await;
    }
}

/// The raw `waitpid(2)` status of `pid`, whose pidfd has reported it waitable.
///
/// Never blocks: the job-table lock is held across this call. A pid that cannot be reaped after
/// all — `ECHILD`, or a `WNOHANG` poll that still finds it running, which a readable pidfd rules
/// out — is reported as killed by `SIGKILL`, so its transaction rolls back rather than merging on
/// no evidence; the trace's own exit record still wins where it exists. Only a final status is
/// asked for: a stop is not something this mux observes, because nothing here continues one.
fn reap_status(pid: libc::pid_t) -> i32 {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid` writes the status through the pointer we pass and has no other
        // requirements.
        let result = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if result > 0 {
            return status;
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return libc::SIGKILL;
    }
}

/// The queue every mux concludes through.
impl ShellMux {
    /// An empty conclusion queue, for [`ShellMux::assemble`].
    pub(crate) fn new_merges() -> Merges {
        Merges::new()
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A row for a table test: no terminal, because none of these reach one.
    fn row(id: &str, close: Option<JobCloseMode>, starting: bool) -> Job {
        Job {
            id: ShellId::from(id),
            sandbox: Sandbox {
                id: ShellId::from(id),
                dir: String::new(),
                uid: format!("uid-{id}"),
            },
            resources: None,
            running: None,
            starting,
            close,
            done: None,
        }
    }

    /// A job name is a principal, so the automatic series must never hand out one a job already
    /// holds — `bg` after `&2` would otherwise open a second `%2`.
    #[test]
    fn the_automatic_series_skips_names_a_job_already_holds() {
        let mut table = JobTable::new(24, 80);
        assert_eq!(table.next_id(), ShellId::from("1"));
        table.open.push(row("2", None, false));
        assert_eq!(
            table.next_id(),
            ShellId::from("3"),
            "2 is taken, so the series steps over it"
        );
    }

    /// A row leaves the table only once nothing is using it, and only when something asked it to:
    /// a number drawn from the series ends with its command, a reader's `stop` ends the job it
    /// named, and a job nobody spoke for stays.
    #[test]
    fn a_closable_row_is_taken_and_a_busy_or_unmarked_one_is_not() {
        let mut table = JobTable::new(24, 80);
        table
            .open
            .push(row("1", Some(JobCloseMode::Automatic), false));
        table
            .open
            .push(row("2", Some(JobCloseMode::Automatic), true));
        table.open.push(row("api", None, false));
        table
            .open
            .push(row("build", Some(JobCloseMode::Graceful), false));

        assert_eq!(
            table
                .take_closable(&ShellId::from("1"))
                .map(|(sandbox, mode, _)| (sandbox.uid, mode)),
            Some(("uid-1".to_string(), JobCloseMode::Automatic))
        );
        assert!(
            table.take_closable(&ShellId::from("2")).is_none(),
            "a command is being launched into it, and that tree is where it will run"
        );
        assert!(
            table.take_closable(&ShellId::from("api")).is_none(),
            "a name a reader chose is a name a reader means to come back to"
        );
        assert_eq!(
            table
                .take_closable(&ShellId::from("build"))
                .map(|(_, mode, _)| mode),
            Some(JobCloseMode::Graceful),
            "an explicit stop closes a job the series would have kept"
        );
        assert_eq!(table.open.len(), 2, "only the closed jobs left the table");
    }

    /// Closing the selected job clears the selection: a prompt that keeps naming a job nobody can
    /// reach is a prompt that lies.
    #[test]
    fn closing_the_selected_job_clears_the_selection() {
        let mut table = JobTable::new(24, 80);
        table
            .open
            .push(row("build", Some(JobCloseMode::Graceful), false));
        table.current = Some(ShellId::from("build"));
        assert!(table.take_closable(&ShellId::from("build")).is_some());
        assert_eq!(table.current, None);
    }

    /// [`ShellMux::close_sandbox`] reclaims a sandbox's storage *after* taking its row out of the
    /// table, and the frontend's end of stream promises the storage went first. So the row's
    /// producers must survive the removal: `forget` hands them back for the caller to hold across
    /// the deletion instead of closing them on the way out.
    #[test]
    fn retired_job_keeps_producers_until_reclamation_finishes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a runtime");
        runtime.block_on(async {
            let (master, slave) =
                brush_core::sys::terminal::open_pty(24, 80).expect("open a pseudoterminal");
            let (_receiver, writer) = instrumentation_pipe().expect("open an instrumentation pipe");
            let shell = brush_core::Shell::builder()
                .do_not_inherit_env(true)
                .skip_well_known_vars(true)
                .build()
                .await
                .expect("build a shell");
            let (release, mut released) = tokio::sync::oneshot::channel::<()>();

            let mut table = JobTable::new(24, 80);
            let mut job = row("held", None, false);
            job.resources = Some(JobResources {
                terminal: Arc::new(AsyncFd::new(master).expect("register the terminal")),
                slave,
                writer,
                shell,
                _release: release,
            });
            table.open.push(job);
            table.current = Some(ShellId::from("held"));

            {
                let _retired = table.forget("uid-held");
                assert!(table.open.is_empty(), "the row left the table");
                assert_eq!(table.current, None, "and took the selection with it");
                assert!(
                    matches!(
                        released.try_recv(),
                        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                    ),
                    "its producers are still open while the caller reclaims the storage"
                );
            }
            assert!(
                matches!(
                    released.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                ),
                "and close only once the caller drops what it was handed"
            );
        });
    }

    /// A job table row is also input: it is what a reader types back at `fg` and `stop`.
    #[test]
    fn a_name_that_is_not_one_word_is_written_quoted() {
        assert_eq!(ShellId::from("main").reference(), "%main");
        assert_eq!(ShellId::from("1").reference(), "%1");
        assert_eq!(ShellId::from("a long name").reference(), "%\"a long name\"");
        assert_eq!(ShellId::from("has.a.dot").reference(), "%\"has.a.dot\"");
    }

    /// A terminal with no rows or no columns is not a terminal, and a job given one would render
    /// into nothing.
    #[test]
    fn a_zero_dimension_is_refused() {
        assert!(validate_size(24, 80).is_ok());
        for (rows, cols) in [(0, 80), (24, 0), (0, 0)] {
            let error = validate_size(rows, cols).expect_err("a zero dimension");
            assert_eq!(
                error.to_string(),
                format!("invalid terminal size: {rows}x{cols}")
            );
        }
    }

    /// A detached task's record outlives the task itself: a [`JoinSet`](tokio::task::JoinSet) holds
    /// a finished task until someone takes it, so a session that opens and closes jobs all day
    /// would carry one record per job until shutdown. Admitting the next one is when the finished
    /// ones are taken, and it must not disturb the ones still running.
    #[test]
    fn completed_tasks_are_pruned_without_cancelling_live_ones() {
        /// Long enough that a channel that never fires fails this test instead of hanging the run.
        const WAIT: std::time::Duration = std::time::Duration::from_secs(30);
        /// Enough registrations that an unpruned set is unmistakable beside the two live ones.
        const FINISHED: usize = 32;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a runtime");
        runtime.block_on(async {
            let mut background = Background::new();

            let (release, released) = tokio::sync::oneshot::channel::<()>();
            let (ran_out, live_finished) = tokio::sync::oneshot::channel::<()>();
            background.spawn_detached(async move {
                let _ = released.await;
                let _ = ran_out.send(());
            });

            for step in 0..FINISHED {
                let (acknowledge, acknowledged) = tokio::sync::oneshot::channel::<usize>();
                background.spawn_detached(async move {
                    let _ = acknowledge.send(step);
                });
                // On a single-threaded runtime the acknowledgment is that task's last operation,
                // so it has returned by the time this test is polled again — no sleep required.
                let observed = tokio::time::timeout(WAIT, acknowledged)
                    .await
                    .expect("a short task ran")
                    .expect("and acknowledged before returning");
                assert_eq!(
                    observed, step,
                    "the task that acknowledged is the one just registered"
                );
            }

            // One more registration, to take the last finished task: a set is pruned on admission.
            let (_never, pending) = tokio::sync::oneshot::channel::<()>();
            background.spawn_detached(async move {
                let _ = pending.await;
            });
            assert_eq!(
                background.detached.len(),
                2,
                "only the two tasks that never finished are still held"
            );

            let _ = release.send(());
            tokio::time::timeout(WAIT, live_finished)
                .await
                .expect("the task held across every pruning was not cancelled")
                .expect("and ran on to its acknowledgment");
            background.detached.shutdown().await;
        });
    }
}
