//! The job table: the sandboxes a front-end has open, the commands running in them, and the names
//! they answer to.
//!
//! A job is a *sandbox*, not a command: it outlives the commands that run in it, and its name is
//! the [`crate::Principal`] those commands request capabilities as. That is why the table lives
//! beside the mux's per-principal shells rather than in a front-end: a job's name and a
//! principal's name are one identity, and two registries of it would drift.
//!
//! One command at a time per job. The table is never held across a launch or a wait, so `jobs`
//! answers while a command is starting and while another is running.

use std::os::fd::RawFd;
use std::sync::{MutexGuard, PoisonError};

use crate::error::MuxError;
use crate::mux::{Sandbox, ShellMux, StartedCmd};
use crate::snapshot;

/// Whether `name` needs no quoting when written as `%name`.
///
/// The set is the one that survives being printed in a job table and typed back without quoting.
pub fn bare_job_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

/// How a job is written for a reader: `%name` when the name is one word, `%"a name"` when it is not.
///
/// Every `%…` a front-end prints goes through this, because a job reference is also *input*: it is
/// what a reader types at `fg`, `bg` and `stop`, so a row of a job table has to be re-typeable.
/// `{name:?}` is exact rather than merely close: a name may hold neither a quote nor a control
/// character, so there is nothing for `Debug` to escape.
pub fn job_ref(name: &str) -> String {
    if bare_job_name(name) {
        format!("%{name}")
    } else {
        format!("%{name:?}")
    }
}

/// Whether a job's command is running or parked by a stop signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    /// Running, in the foreground or the background.
    Running,
    /// Stopped by Ctrl-Z or by reading from the terminal in the background.
    Stopped,
}

impl JobState {
    /// The word a job table prints for this state.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// One job: a named sandbox, and whatever command is running in it.
struct Job {
    /// The handle a job table prints and `fg NAME` resolves.
    name: String,
    /// The sandbox every command of this job runs in.
    sandbox: Sandbox,
    /// The command currently running in it, if any.
    running: Option<Running>,
    /// A command is being launched into it: its snapshot is being retaken and its tracer spawned.
    ///
    /// Separate from `running`, which cannot exist until the tracer has a pid. Without it the busy
    /// check would pass twice for one job and the second launch would strand the first's tracer.
    starting: bool,
    /// Nobody chose this job's name: it was drawn from the `1`, `2`, … series for a command that a
    /// bare `&` submitted, so there is no handle a reader would come back to and it closes itself
    /// when that command's transaction concludes. Cleared by [`ShellMux::keep`].
    transient: bool,
}

/// The half of a job that exists only while a command is in flight.
struct Running {
    /// The command line, for a job table and the job's start line.
    cmd: String,
    /// Process id of the traced child — also its process-group id, so `kill(-pid, …)` reaches the
    /// tracer, the shell it traces and every descendant together.
    pid: libc::pid_t,
    /// Whether it is running or stopped.
    state: JobState,
    /// The open transaction.
    started: StartedCmd,
}

/// The job table and the name series it draws from.
pub(crate) struct JobTable {
    /// The open jobs, in creation order.
    open: Vec<Job>,
    /// Next automatic job name.
    counter: u64,
}

impl JobTable {
    /// An empty table whose first automatic name is `1`.
    pub(crate) const fn new() -> Self {
        Self {
            open: Vec::new(),
            counter: 1,
        }
    }

    /// The next automatic job name, skipping any a job already occupies.
    ///
    /// Monotonic within a session — a name is never reused while the mux lives — because a job name
    /// is a principal, and reusing one would make two sandboxes indistinguishable in the history.
    fn next_name(&mut self) -> String {
        loop {
            let name = self.counter.to_string();
            self.counter += 1;
            if !self.open.iter().any(|job| job.name == name) {
                return name;
            }
        }
    }

    /// Removes every job whose sandbox is `uid`.
    pub(crate) fn forget(&mut self, uid: &str) {
        self.open.retain(|job| job.sandbox.uid != uid);
    }

    /// Removes a job that nobody named and nothing is using, returning its sandbox.
    ///
    /// A job with a command in flight is kept whatever its name: the tree is what that command is
    /// running in, and its transaction is not concluded yet.
    fn close_transient(&mut self, name: &str) -> Option<Sandbox> {
        let index = self.open.iter().position(|job| {
            job.name == name && job.transient && job.running.is_none() && !job.starting
        })?;
        Some(self.open.remove(index).sandbox)
    }
}

/// The command in flight in a job.
#[derive(Clone, Debug)]
pub struct RunningView {
    /// The command line as submitted.
    pub cmd: String,
    /// Process-group id of the traced command, for signals and for `tcsetpgrp`.
    pub pid: libc::pid_t,
    /// Whether it is running or stopped.
    pub state: JobState,
}

/// One job as a caller sees it.
///
/// A view rather than the row itself, because the open transaction a running job holds is the
/// mux's to conclude and must not leave the table.
#[derive(Clone, Debug)]
pub struct JobView {
    /// The job's name, which is also its principal.
    pub name: String,
    /// The sandbox its commands run in.
    pub sandbox: Sandbox,
    /// The command in flight, or `None` when the job is idle.
    pub running: Option<RunningView>,
    /// A command is being launched into it, so it is neither idle nor yet running.
    pub starting: bool,
}

/// What [`ShellMux::spawn`] opened.
#[derive(Clone, Debug)]
pub struct Spawned {
    /// The new job's name: the one asked for, or the next number when none was.
    pub name: String,
    /// Its sandbox.
    pub sandbox: Sandbox,
    /// Process-group id of the command it was given, when it was given one.
    pub pid: Option<libc::pid_t>,
}

/// What a wait observed about a job's command.
#[derive(Debug)]
pub enum Reaped {
    /// It stopped. The transaction stays open and the job keeps it.
    Stopped {
        /// The job whose command stopped.
        name: String,
    },
    /// It ended. The transaction is out of the table and ready for
    /// [`ShellMux::conclude_cmd`].
    ///
    /// The transaction is boxed because a reap returns a vector of these and a stop is three
    /// words: paying a whole open transaction per row would make the common case — nothing to
    /// report — the expensive one.
    Ended {
        /// The job whose command ended.
        name: String,
        /// The open transaction.
        started: Box<StartedCmd>,
        /// Raw `waitpid(2)` status.
        status: i32,
    },
}

impl ShellMux {
    /// The job table, recovering a poisoned lock like the rest of this crate.
    pub(crate) fn job_table(&self) -> MutexGuard<'_, JobTable> {
        self.jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a job over `dir` and, when `cmd` is given, starts it there.
    ///
    /// `name` is `None` for the next number in the `1`, `2`, … series. A name a live job already
    /// holds is refused, because a job name is a capability principal and two sandboxes sharing one
    /// would be indistinguishable in the history. `dir` is seed-relative; `instrumentation` is the
    /// descriptor the command receives on fd 3.
    ///
    /// The table is released before the command is launched, and the job is in it throughout: a
    /// launch retakes the snapshot and spawns a tracer, which on a large seed takes seconds, and
    /// holding the table across that would make every `jobs` and every reap wait for it.
    ///
    /// # Errors
    ///
    /// Fails when `name` is taken, when `dir` escapes the seed or names nothing in it, or when the
    /// command's snapshot could not be retaken or its tracer spawned. A failed launch leaves the
    /// table as it found it and reclaims the sandbox it had opened.
    pub fn spawn(
        &self,
        dir: &str,
        name: Option<String>,
        cmd: Option<&str>,
        instrumentation: Option<RawFd>,
    ) -> Result<Spawned, MuxError> {
        let anonymous = name.is_none();
        let (name, sandbox) = {
            let mut table = self.job_table();
            let name = match name {
                Some(name) => {
                    if table.open.iter().any(|job| job.name == name) {
                        return Err(MuxError::JobExists(job_ref(&name)));
                    }
                    name
                }
                None => table.next_name(),
            };
            let sandbox = self.new_sandbox(&name, dir)?;
            table.open.push(Job {
                name: name.clone(),
                sandbox: sandbox.clone(),
                running: None,
                starting: cmd.is_some(),
                transient: anonymous && cmd.is_some(),
            });
            drop(table);
            (name, sandbox)
        };
        let Some(cmd) = cmd else {
            return Ok(Spawned {
                name,
                sandbox,
                pid: None,
            });
        };
        match self.launch_into(&name, cmd, instrumentation) {
            Ok(pid) => Ok(Spawned {
                name,
                sandbox,
                pid: Some(pid),
            }),
            Err(error) => {
                // Nothing ever ran in it, so it is not a tree anyone would want to look at, and a
                // row left behind would be one more name between a reader and the real jobs.
                self.job_table().forget(&sandbox.uid);
                self.close_sandbox(&sandbox);
                Err(error)
            }
        }
    }

    /// Starts `cmd` in the job named `name`, returning its process-group id.
    ///
    /// # Errors
    ///
    /// Fails when no job answers to `name`, when that job is already running or starting a command,
    /// or when the snapshot could not be retaken or the tracer spawned.
    pub fn start_in(
        &self,
        name: &str,
        cmd: &str,
        instrumentation: Option<RawFd>,
    ) -> Result<libc::pid_t, MuxError> {
        {
            let mut table = self.job_table();
            let Some(job) = table.open.iter_mut().find(|job| job.name == name) else {
                return Err(MuxError::NoSuchJob(job_ref(name)));
            };
            if job.running.is_some() || job.starting {
                return Err(MuxError::JobBusy(job_ref(name)));
            }
            job.starting = true;
            drop(table);
        }
        self.launch_into(name, cmd, instrumentation)
    }

    /// Starts `cmd` in the job named `name`, which is in the table and marked `starting`.
    ///
    /// Runs with no lock held: this is the second or two a snapshot and a tracer spawn cost.
    fn launch_into(
        &self,
        name: &str,
        cmd: &str,
        instrumentation: Option<RawFd>,
    ) -> Result<libc::pid_t, MuxError> {
        let Some(sandbox) = self.job(name).map(|job| job.sandbox) else {
            return Err(MuxError::NoSuchJob(job_ref(name)));
        };
        let started = match self.start_cmd(&sandbox, cmd, instrumentation) {
            Ok(started) => started,
            Err(error) => {
                if let Some(job) = self
                    .job_table()
                    .open
                    .iter_mut()
                    .find(|job| job.name == name)
                {
                    job.starting = false;
                }
                return Err(error);
            }
        };
        let pid = started.pid();
        // Also set from the child's side. Doing it here too closes the race where the parent hands
        // the terminal to a group the child has not created yet; `EACCES` (the child already
        // exec'd) and `ESRCH` (it already exited) are both benign.
        // SAFETY: `setpgid` only manipulates process group membership.
        unsafe { libc::setpgid(pid, pid) };
        let mut table = self.job_table();
        if let Some(job) = table.open.iter_mut().find(|job| job.name == name) {
            job.starting = false;
            job.running = Some(Running {
                cmd: cmd.to_string(),
                pid,
                state: JobState::Running,
                started,
            });
        }
        drop(table);
        Ok(pid)
    }

    /// Every open job, in creation order.
    pub fn jobs(&self) -> Vec<JobView> {
        self.job_table().open.iter().map(job_view).collect()
    }

    /// One job, by name.
    pub fn job(&self, name: &str) -> Option<JobView> {
        self.job_table()
            .open
            .iter()
            .find(|job| job.name == name)
            .map(job_view)
    }

    /// Polls every running command without blocking, updating the table.
    ///
    /// A `SIGCHLD` handler's thread calls this; it never blocks, so it cannot hold the terminal's
    /// waiter against the foreground command.
    pub fn reap(&self) -> Vec<Reaped> {
        let _waiter = self.waits.lock().unwrap_or_else(PoisonError::into_inner);
        let mut observed = Vec::new();
        let mut table = self.job_table();
        for job in &mut table.open {
            let Some(running) = job.running.as_ref() else {
                continue;
            };
            let (pid, state) = (running.pid, running.state);
            match wait_job(pid, libc::WNOHANG | libc::WUNTRACED) {
                Wait::Running => {}
                Wait::Stopped => {
                    if state != JobState::Stopped
                        && let Some(running) = job.running.as_mut()
                    {
                        running.state = JobState::Stopped;
                        observed.push(Reaped::Stopped {
                            name: job.name.clone(),
                        });
                    }
                }
                Wait::Finished(status) => {
                    if let Some(running) = job.running.take() {
                        observed.push(Reaped::Ended {
                            name: job.name.clone(),
                            started: Box::new(running.started),
                            status,
                        });
                    }
                }
            }
        }
        drop(table);
        observed
    }

    /// Blocks until the command in `name` exits or stops, updating the table.
    ///
    /// The table is not held across the wait — `jobs` and the prompt stay answerable while a
    /// foreground command owns the terminal — but the waiter lock is, which is what keeps the
    /// reaper from claiming the same child.
    pub fn wait_for_job(&self, name: &str) -> Option<Reaped> {
        let pid = self.job(name)?.running?.pid;
        let observed = {
            let _waiter = self.waits.lock().unwrap_or_else(PoisonError::into_inner);
            wait_job(pid, libc::WUNTRACED)
        };
        let mut table = self.job_table();
        let job = table.open.iter_mut().find(|job| job.name == name)?;
        let reaped = match observed {
            Wait::Finished(status) => job.running.take().map(|running| Reaped::Ended {
                name: name.to_string(),
                started: Box::new(running.started),
                status,
            }),
            Wait::Stopped | Wait::Running => {
                if let Some(running) = job.running.as_mut() {
                    running.state = JobState::Stopped;
                }
                Some(Reaped::Stopped {
                    name: name.to_string(),
                })
            }
        };
        drop(table);
        reaped
    }

    /// Marks a stopped command running again, returning its process group and command line.
    ///
    /// The signal is the caller's to send: what this does is agree that the job is running again,
    /// so a reap that observes it no longer reports a stop it already reported.
    pub fn resume(&self, name: &str) -> Option<(libc::pid_t, String)> {
        let mut table = self.job_table();
        let job = table.open.iter_mut().find(|job| job.name == name)?;
        let running = job.running.as_mut()?;
        running.state = JobState::Running;
        let resumed = (running.pid, running.cmd.clone());
        drop(table);
        Some(resumed)
    }

    /// Closes the job named `name`, returning the sandbox whose tree the caller must now reclaim.
    ///
    /// The tree is *not* deleted here: a conclusion may still be diffing it against the seed, and
    /// only the front-end that queued that merge knows when it has landed. The caller closes the
    /// sandbox once it has.
    ///
    /// # Errors
    ///
    /// Fails when no job answers to `name`, or when one does and a command is running or starting
    /// in it — that command's tracer is writing into the tree this would reclaim.
    pub fn close_job(&self, name: &str) -> Result<Sandbox, MuxError> {
        let mut table = self.job_table();
        let Some(index) = table.open.iter().position(|job| job.name == name) else {
            return Err(MuxError::NoSuchJob(job_ref(name)));
        };
        let job = &table.open[index];
        if job.running.is_some() || job.starting {
            return Err(MuxError::JobBusy(job_ref(name)));
        }
        let sandbox = table.open.remove(index).sandbox;
        drop(table);
        Ok(sandbox)
    }

    /// Closes `name` and reclaims its tree if it is a job nobody named and nothing is using.
    ///
    /// Called once a transaction has been concluded, so nothing is diffing the tree any more and
    /// the deletion is this method's to do.
    pub fn close_if_transient(&self, name: &str) {
        let closed = {
            let mut table = self.job_table();
            table.close_transient(name)
        };
        let Some(sandbox) = closed else {
            return;
        };
        snapshot::delete_subvolume(&self.session().work(&sandbox.uid));
    }

    /// Keeps a job a reader has taken an interest in: it will not close itself any more.
    pub fn keep(&self, name: &str) {
        let mut table = self.job_table();
        if let Some(job) = table.open.iter_mut().find(|job| job.name == name) {
            job.transient = false;
        }
        drop(table);
    }

    /// Closes every job's sandbox and empties the table.
    pub fn close_jobs(&self) {
        let mut table = self.job_table();
        for job in &table.open {
            // Inlined rather than `close_sandbox`, which takes this very lock to deregister.
            snapshot::delete_subvolume(&self.session().work(&job.sandbox.uid));
        }
        table.open.clear();
    }
}

/// One row as a caller sees it.
fn job_view(job: &Job) -> JobView {
    JobView {
        name: job.name.clone(),
        sandbox: job.sandbox.clone(),
        running: job.running.as_ref().map(|running| RunningView {
            cmd: running.cmd.clone(),
            pid: running.pid,
            state: running.state,
        }),
        starting: job.starting,
    }
}

/// What one `waitpid` observed.
enum Wait {
    /// Still alive; only a polling wait returns this.
    Running,
    /// Newly stopped. The transaction stays open.
    Stopped,
    /// Gone, with the raw wait status to conclude the transaction with.
    Finished(i32),
}

/// Waits on `pid`, retrying an interrupted call.
///
/// `flags` decides whether this blocks: `WNOHANG` polls, its absence waits. `WUNTRACED` is what
/// makes a stop observable at all — without it, Ctrl-Z would look like "still running" forever.
fn wait_job(pid: libc::pid_t, flags: libc::c_int) -> Wait {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid` writes the status through the pointer we pass and has no other
        // requirements.
        let result = unsafe { libc::waitpid(pid, &raw mut status, flags) };
        if result == 0 {
            return Wait::Running;
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // Unreapable (there is nothing else in this process that reaps children). Report it as
            // signalled rather than as a clean exit, so the transaction rolls back instead of
            // merging on no evidence; the trace's own exit record still wins where it exists.
            return Wait::Finished(libc::SIGKILL);
        }
        if libc::WIFSTOPPED(status) {
            return Wait::Stopped;
        }
        return Wait::Finished(status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job name is a principal, so the automatic series must never hand out one a job already
    /// holds — `sda` after `&2` would otherwise open a second `%2`.
    #[test]
    fn the_automatic_series_skips_names_a_job_already_holds() {
        let mut table = JobTable::new();
        assert_eq!(table.next_name(), "1");
        table.open.push(Job {
            name: "2".to_string(),
            sandbox: Sandbox {
                name: "2".to_string(),
                dir: String::new(),
                uid: "deadbeef".to_string(),
            },
            running: None,
            starting: false,
            transient: false,
        });
        assert_eq!(
            table.next_name(),
            "3",
            "2 is taken, so the series steps over it"
        );
    }

    /// A number drawn from the series is nothing to come back to, so such a job ends with its
    /// command — but only that job, and only once nothing is using it.
    #[test]
    fn a_job_nobody_named_closes_itself_and_a_busy_one_does_not() {
        let row = |name: &str, transient: bool, starting: bool| Job {
            name: name.to_string(),
            sandbox: Sandbox {
                name: name.to_string(),
                dir: String::new(),
                uid: format!("uid-{name}"),
            },
            running: None,
            starting,
            transient,
        };
        let mut table = JobTable::new();
        table.open.push(row("1", true, false));
        table.open.push(row("2", true, true));
        table.open.push(row("api", false, false));

        assert_eq!(
            table.close_transient("1").map(|sandbox| sandbox.uid),
            Some("uid-1".to_string())
        );
        assert!(
            table.close_transient("2").is_none(),
            "a command is being launched into it, and that tree is where it will run"
        );
        assert!(
            table.close_transient("api").is_none(),
            "a name a reader chose is a name a reader means to come back to"
        );
        assert_eq!(table.open.len(), 2, "only the closed job left the table");
    }

    /// A job table row is also input: it is what a reader types back at `fg` and `stop`.
    #[test]
    fn a_name_that_is_not_one_word_is_written_quoted() {
        assert_eq!(job_ref("main"), "%main");
        assert_eq!(job_ref("1"), "%1");
        assert_eq!(job_ref("a long name"), "%\"a long name\"");
        assert_eq!(job_ref("has.a.dot"), "%\"has.a.dot\"");
    }
}
