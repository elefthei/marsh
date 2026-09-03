//! The job table, the terminal it hands out, and the instrumentation stream everything reports on.
//!
//! This is the effectful half of the console: snapshots, traced children, `waitpid`, `tcsetpgrp`
//! and the mux calls that conclude a transaction. The pure half — the line grammar and the report
//! text — is [`crate::repl`].
//!
//! Jobs are bash-shaped. A foreground command owns the real terminal, so full-screen programs
//! (`less`, `vim`, an agent TUI) work exactly as they would in any shell, and Ctrl-C and Ctrl-Z
//! reach it through the terminal rather than through a key handler here. `cmd &` and
//! `spawn NAME cmd` start background jobs, `jobs` lists them, `fg`/`bg` move them between the
//! terminal and the background, `kill` signals them. A job's name *is* its principal, which is
//! what makes the job table a picture of the capability contention against the seed: `%foo` and
//! `%bar` race exactly as two agents would.

use std::io::{BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use shellmux::{MuxError, Principal, ShellMux, StartedCmd};

use crate::repl::{self, FOREGROUND};

/// The instrumentation stream: fd 3 of this process, and of every job it starts.
///
/// It is brush-core's third standard stream, not a number this crate invented, so a builtin's
/// `stdinstr()` writer and a job's `echo x >&3` are the same channel.
pub const INSTRUMENTATION_FD: RawFd = brush_core::openfiles::OpenFiles::STDINSTR_FD;

/// Signals the console must not receive, so the foreground job receives them instead.
///
/// The terminal delivers Ctrl-C and Ctrl-Z to the *foreground process group*, which is the job's,
/// not ours. Ignoring them here is also what makes the tcsetpgrp handoff work at all: a background
/// process group that writes to or reconfigures the terminal would otherwise be stopped by
/// `SIGTTOU`, and that group is us for as long as a job holds the terminal.
const IGNORED_SIGNALS: [libc::c_int; 5] = [
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

/// How long the exit sweep gives a hung-up job to die before killing it outright.
const SWEEP_GRACE: Duration = Duration::from_secs(2);

/// SGR parameter for light gray (bright black): the instrumentation color.
const GRAY: &str = "\x1b[90m";

/// The one console of this process.
///
/// A [`brush_core::builtins::Registration`]'s `execute_func` is a plain function pointer, so a
/// builtin cannot close over the console it must act on. For a single-console binary a
/// process-global is the honest shape: it is installed once by [`install`], before the interactive
/// loop starts, and every job-control builtin reads it back through [`shared`].
static CONSOLE: OnceLock<Arc<Mutex<Console>>> = OnceLock::new();

/// Publishes `console` as the one the job-control builtins act on.
///
/// Returns an error if a console was already installed, which would mean two consoles were
/// competing for the same job table.
pub fn install(console: Arc<Mutex<Console>>) -> Result<(), String> {
    CONSOLE
        .set(console)
        .map_err(|_| "a console is already installed".to_string())
}

/// The installed console, or `None` when called before [`install`].
pub fn shared() -> Option<&'static Arc<Mutex<Console>>> {
    CONSOLE.get()
}

/// Ignores the terminal signals that belong to the foreground job, and returns this process's
/// group id: what the terminal goes back to when a job releases it.
pub fn claim_terminal_signals() -> libc::pid_t {
    for signal in IGNORED_SIGNALS {
        // SAFETY: `signal` only installs a disposition for a signal number. `SIG_IGN` runs no
        // handler, so there is no async-signal-safety requirement to honor.
        let _ = unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
    // SAFETY: `getpgrp` reads the calling process's group id and cannot fail.
    unsafe { libc::getpgrp() }
}

/// Creates the instrumentation pipe and puts its write end on this process's fd 3.
///
/// Returns the read end. `dup2` clears close-on-exec, which is exactly what makes the stream
/// inheritable: every job the console starts finds the pipe at fd 3 without being told about it,
/// and so does the outer shell's own file table.
pub fn open_instrumentation() -> Result<std::fs::File, String> {
    let mut ends: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `pipe2` writes exactly two descriptors through the pointer we pass.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "cannot create the instrumentation pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    let [mut read_end, write_end] = ends;

    // The kernel hands out the lowest free descriptors, so the read end can *be* fd 3 — in which
    // case the `dup2` below would silently close it. Move it out of the way first.
    if read_end == INSTRUMENTATION_FD {
        // SAFETY: duplicating a descriptor we own to the lowest free number above fd 3.
        let moved = unsafe { libc::fcntl(read_end, libc::F_DUPFD_CLOEXEC, INSTRUMENTATION_FD + 1) };
        if moved < 0 {
            return Err(format!(
                "cannot relocate the instrumentation pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: closing the original descriptor, which nothing else refers to yet.
        unsafe { libc::close(read_end) };
        read_end = moved;
    }

    if write_end == INSTRUMENTATION_FD {
        // Already in place. Only the close-on-exec flag has to go, or no job would inherit it —
        // and `dup2(3, 3)` is defined to do nothing at all, flag included.
        // SAFETY: clearing the descriptor flags of a descriptor we own.
        if unsafe { libc::fcntl(write_end, libc::F_SETFD, 0) } < 0 {
            return Err(format!(
                "cannot share the instrumentation pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
    } else {
        // SAFETY: both arguments are open descriptors we own; `dup2` closes fd 3 first if it was
        // in use (an inherited fd 3 is exactly what a session is meant to replace).
        if unsafe { libc::dup2(write_end, INSTRUMENTATION_FD) } < 0 {
            return Err(format!(
                "cannot install the instrumentation pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: closing the now-redundant original write end.
        unsafe { libc::close(write_end) };
    }

    // SAFETY: `read_end` is an open descriptor this function owns and never touches again.
    Ok(unsafe { std::fs::File::from_raw_fd(read_end) })
}

/// Prints everything written to the instrumentation pipe, one gray line at a time.
///
/// Line-buffered on purpose: two jobs writing at once interleave by line rather than mid-word. The
/// pipe never reaches end of file while this process holds fd 3, so the thread simply lives as long
/// as the session.
pub fn spawn_instrumentation_reader(read_end: std::fs::File) {
    let _ = std::thread::spawn(move || {
        let reader = std::io::BufReader::new(read_end);
        for line in reader.lines() {
            match line {
                Ok(line) => gray(&line),
                Err(_) => break,
            }
        }
    });
}

/// Writes one instrumentation line in gray, in a single write.
///
/// One write per line is what keeps a job's output and the console's reports from tearing into each
/// other: the escape sequence, the text and the newline never arrive separately.
///
/// The line is framed for a terminal the line editor may be holding in raw mode, because a
/// background job's fd-3 write arrives while the user sits at the prompt. `\r` and `\x1b[K` put the
/// text at column 0 over the partially drawn prompt instead of appending to it, and the write ends
/// with `\r\n` because in raw mode a bare `\n` moves down a row without returning to column 0.
/// Without this framing the editor's next repaint erases the line, and the instrumentation is lost
/// exactly when it mattered. On a cooked-mode terminal the cursor is already at column 0 on a fresh
/// line, so the framing is invisible.
pub fn gray(line: &str) {
    let text = format!("\r\x1b[K{GRAY}{line}\x1b[0m\r\n");
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

/// Whether a job is running or parked by a stop signal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JobState {
    /// Running (possibly in the background).
    Running,
    /// Stopped by Ctrl-Z or by reading from the terminal in the background.
    Stopped,
}

impl JobState {
    /// The word `jobs` prints for this state.
    const fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// One job: an open transaction that owns a process group.
struct Job {
    /// The handle `jobs` prints and `fg %name` resolves.
    name: String,
    /// The principal the transaction runs as. Usually the same string as the name; a foreground
    /// command that got stopped keeps `main` and gains a name.
    principal: Principal,
    /// The command line, for `jobs` and for the job's start line.
    cmd: String,
    /// Process id of the traced child — also its process-group id, so `kill(-pid, …)` reaches the
    /// tracer, the shell it traces and every descendant together.
    pid: libc::pid_t,
    /// Whether it is running or stopped.
    state: JobState,
    /// The transaction, still open: snapshots, instrumentation logs, and the identity the mux
    /// needs to merge it.
    started: StartedCmd,
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

/// The console: the job table plus the terminal it hands out.
pub struct Console {
    /// The multiplexer every line is a transaction against.
    mux: Arc<ShellMux>,
    /// Open transactions, in start order.
    jobs: Vec<Job>,
    /// The terminal, for handing the foreground process group to a job and taking it back.
    tty: std::fs::File,
    /// This process's group id: what the terminal goes back to when a job releases it.
    own_pgid: libc::pid_t,
    /// Next automatic job name.
    counter: u64,
    /// Whether a preceding `exit` already warned about live jobs.
    exit_armed: bool,
}

impl Console {
    /// Creates the console for `mux`, handing it the terminal it will lend to jobs.
    pub const fn new(mux: Arc<ShellMux>, tty: std::fs::File, own_pgid: libc::pid_t) -> Self {
        Self {
            mux,
            jobs: Vec::new(),
            tty,
            own_pgid,
            counter: 1,
            exit_armed: false,
        }
    }

    /// The seed directory: the tree every transaction is against.
    pub fn seed_dir(&self) -> &std::path::Path {
        self.mux.seed_dir()
    }

    /// Reaps finished and newly stopped jobs, concluding the transactions of the finished ones.
    ///
    /// Called once per loop turn, between one line's execution and the next prompt, which is where
    /// bash reports job status too: a merge that lands while the user is typing would otherwise
    /// scribble over the line being edited.
    pub fn reap(&mut self) {
        let mut index = 0;
        while index < self.jobs.len() {
            match wait_job(self.jobs[index].pid, libc::WNOHANG | libc::WUNTRACED) {
                Wait::Running => index += 1,
                Wait::Stopped => {
                    if self.jobs[index].state != JobState::Stopped {
                        self.jobs[index].state = JobState::Stopped;
                        gray(&format!(
                            "%{} stopped — fg %{} to resume",
                            self.jobs[index].name, self.jobs[index].name
                        ));
                    }
                    index += 1;
                }
                Wait::Finished(status) => {
                    let job = self.jobs.remove(index);
                    self.conclude(job, status);
                }
            }
        }
    }

    /// Forgets a pending `exit` warning, because something other than `exit` was submitted.
    pub const fn disarm_exit(&mut self) {
        self.exit_armed = false;
    }

    /// Whether the session may end now, warning once while jobs are still open.
    ///
    /// The warning is not paternalism: a job is an open transaction holding two btrfs snapshots,
    /// and quitting kills it before it can merge.
    pub fn may_exit(&mut self, err: &mut dyn Write) -> bool {
        if !self.jobs.is_empty() && !self.exit_armed {
            let _ = writeln!(
                err,
                "marsh: there are running jobs (exit again to kill them)"
            );
            self.exit_armed = true;
            return false;
        }
        true
    }

    /// Hangs up, kills and concludes every remaining job.
    ///
    /// Runs after the loop has returned, whether the session ended with `exit`, with Ctrl-D or with
    /// an error. Merges can still land here — a job that finishes its work while being hung up has
    /// earned its capabilities — and the ones that die of the signal roll back as failed
    /// executions. Whatever cannot be reaped leaves its snapshots for [`ShellMux::open`]'s sweep to
    /// reclaim on the next start.
    pub fn sweep(&mut self) {
        if self.jobs.is_empty() {
            return;
        }
        for job in &self.jobs {
            // SIGCONT after SIGHUP: a stopped job would not run its hangup until it is resumed.
            signal_group(job.pid, libc::SIGHUP);
            signal_group(job.pid, libc::SIGCONT);
        }

        let deadline = Instant::now() + SWEEP_GRACE;
        while !self.jobs.is_empty() && Instant::now() < deadline {
            let mut index = 0;
            while index < self.jobs.len() {
                match wait_job(self.jobs[index].pid, libc::WNOHANG) {
                    Wait::Finished(status) => {
                        let job = self.jobs.remove(index);
                        self.conclude(job, status);
                    }
                    _ => index += 1,
                }
            }
            if !self.jobs.is_empty() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        while !self.jobs.is_empty() {
            let job = self.jobs.remove(0);
            signal_group(job.pid, libc::SIGKILL);
            let status = match wait_job(job.pid, 0) {
                Wait::Finished(status) => status,
                // A stop cannot survive SIGKILL, and a blocking wait does not return "running".
                _ => libc::SIGKILL,
            };
            self.conclude(job, status);
        }
    }

    /// Runs `cmd` as the foreground principal, attached to the terminal.
    pub fn foreground(&mut self, cmd: String, err: &mut dyn Write) -> u8 {
        let job = match self.start(FOREGROUND.to_string(), Principal::from(FOREGROUND), cmd) {
            Ok(job) => job,
            Err(error) => {
                let _ = writeln!(err, "marsh: {error}");
                return 1;
            }
        };
        self.attach(job, false)
    }

    /// Starts `cmd` as a named background job, which is also a named principal.
    pub fn spawn(&mut self, name: String, cmd: String, err: &mut dyn Write) -> u8 {
        if self.jobs.iter().any(|job| job.name == name) {
            let _ = writeln!(err, "spawn: job %{name} already exists");
            return 1;
        }
        let job = match self.start(name.clone(), Principal::from(name.as_str()), cmd) {
            Ok(job) => job,
            Err(error) => {
                let _ = writeln!(err, "marsh: {error}");
                return 1;
            }
        };
        // Background jobs inherit the real terminal, bash-style: their output interleaves live, and
        // a background read from the terminal earns `SIGTTIN`, which stops the job for `fg` to
        // service.
        gray(&format!("%{} $ {}", job.name, job.cmd));
        self.jobs.push(job);
        0
    }

    /// Attaches a job to the terminal: bare `fg` takes the most recent one.
    pub fn fg(&mut self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(index) = self.resolve(name, "fg", None, err) else {
            return 1;
        };
        let job = self.jobs.remove(index);
        // The user typed `fg`, not the command, so the command line is worth repeating.
        gray(&format!("%{} $ {}", job.name, job.cmd));
        self.attach(job, true)
    }

    /// Resumes a stopped job in the background: bare `bg` takes the most recent stopped one.
    pub fn bg(&mut self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(index) = self.resolve(name, "bg", Some(JobState::Stopped), err) else {
            return 1;
        };
        let job = &mut self.jobs[index];
        if job.state == JobState::Running {
            let _ = writeln!(err, "bg: job %{} already running", job.name);
            return 1;
        }
        job.state = JobState::Running;
        signal_group(job.pid, libc::SIGCONT);
        gray(&format!("%{} continued: {}", job.name, job.cmd));
        0
    }

    /// Signals jobs and process ids.
    ///
    /// A `%name` target signals the job's whole process group, because a job *is* a process group:
    /// the tracer, the shell it traces and every descendant have to receive the signal together, or
    /// a `kill` would leave the transaction's tracer alive around a dead child. A bare pid is
    /// signalled as itself, exactly as `kill(1)` does.
    pub fn kill(&mut self, args: &[String], err: &mut dyn Write) -> u8 {
        let (signal, targets) = match args.split_first() {
            Some((first, rest)) if first.starts_with('-') => match parse_signal(first) {
                Some(signal) => (signal, rest),
                None => {
                    let _ = writeln!(err, "kill: {first}: invalid signal specification");
                    return 1;
                }
            },
            _ => (libc::SIGTERM, args),
        };
        if targets.is_empty() {
            let _ = writeln!(err, "kill: usage: kill [-SIGNAL] %NAME|PID…");
            return 1;
        }

        let mut code = 0;
        for target in targets {
            if let Some(name) = target.strip_prefix('%') {
                match self.jobs.iter().find(|job| job.name == name) {
                    Some(job) => signal_group(job.pid, signal),
                    None => {
                        let _ = writeln!(err, "kill: no such job: %{name}");
                        code = 1;
                    }
                }
            } else if let Ok(pid) = target.parse::<libc::pid_t>() {
                // SAFETY: `kill` signals a process by id and has no memory-safety requirements.
                if unsafe { libc::kill(pid, signal) } != 0 {
                    let _ = writeln!(
                        err,
                        "kill: ({pid}) - {}",
                        std::io::Error::last_os_error()
                            .to_string()
                            .trim_end_matches('.')
                    );
                    code = 1;
                }
            } else {
                let _ = writeln!(err, "kill: {target}: arguments must be jobs or process ids");
                code = 1;
            }
        }
        code
    }

    /// Resolves a `fg`/`bg` argument to an index into the job table, reporting failure to `err`.
    ///
    /// `default_state` restricts what a bare `fg`/`bg` picks: `bg` only makes sense for a stopped
    /// job, while `fg` is meaningful for either.
    fn resolve(
        &self,
        name: Option<&str>,
        verb: &str,
        default_state: Option<JobState>,
        err: &mut dyn Write,
    ) -> Option<usize> {
        match name {
            Some(name) => {
                let index = self.jobs.iter().position(|job| job.name == name);
                if index.is_none() {
                    let _ = writeln!(err, "{verb}: no such job: %{name}");
                }
                index
            }
            None => {
                let index = match default_state {
                    Some(state) => self.jobs.iter().rposition(|job| job.state == state),
                    None => self.jobs.len().checked_sub(1),
                };
                if index.is_none() {
                    match default_state {
                        Some(JobState::Stopped) => {
                            let _ = writeln!(err, "{verb}: no stopped jobs");
                        }
                        _ => {
                            let _ = writeln!(err, "{verb}: no jobs");
                        }
                    }
                }
                index
            }
        }
    }

    /// Writes the job table to `out`, one row per open transaction.
    pub fn print_jobs(&self, out: &mut dyn Write) {
        for job in &self.jobs {
            let _ = writeln!(out, "%{:<8} {:<8} {}", job.name, job.state.label(), job.cmd);
        }
    }

    /// Snapshots the seed and spawns `cmd` as its own process group.
    fn start(&mut self, name: String, principal: Principal, cmd: String) -> Result<Job, MuxError> {
        // `block_in_place`: `start_cmd` builds the principal's shell on the mux's own runtime, and
        // blocking on a nested runtime from an async context panics unless the thread is marked as
        // blocking.
        let started = tokio::task::block_in_place(|| {
            self.mux
                .start_cmd(&principal, &cmd, Some(INSTRUMENTATION_FD))
        })?;
        let pid = started.pid();
        // Also set from the child's side. Doing it here too closes the race where the parent hands
        // the terminal to a group the child has not created yet; `EACCES` (the child already
        // exec'd) and `ESRCH` (it already exited) are both benign.
        // SAFETY: `setpgid` only manipulates process group membership.
        unsafe { libc::setpgid(pid, pid) };
        Ok(Job {
            name,
            principal,
            cmd,
            pid,
            state: JobState::Running,
            started,
        })
    }

    /// Gives `job` the terminal and waits for it to exit or stop.
    ///
    /// Returns the exit code the console reports for the line. A job that stops stays in the table
    /// as a background job — that is what Ctrl-Z means — and a foreground command that stops earns
    /// a job name on the way out, since it now needs a handle.
    fn attach(&mut self, mut job: Job, resume: bool) -> u8 {
        set_foreground(&self.tty, job.pid);
        if resume {
            signal_group(job.pid, libc::SIGCONT);
        }
        let wait = wait_job(job.pid, libc::WUNTRACED);
        set_foreground(&self.tty, self.own_pgid);

        match wait {
            Wait::Finished(status) => {
                let code = exit_code(status);
                self.conclude(job, status);
                code
            }
            Wait::Stopped | Wait::Running => {
                job.state = JobState::Stopped;
                if job.name == FOREGROUND {
                    job.name = self.next_name();
                }
                gray(&format!(
                    "%{} stopped — fg %{} to resume",
                    job.name, job.name
                ));
                self.jobs.push(job);
                // The same code bash reports for a job stopped by SIGTSTP.
                148
            }
        }
    }

    /// Concludes a finished job's transaction and reports the verdict in gray.
    ///
    /// Reports are printed here, synchronously, rather than pushed through the instrumentation
    /// pipe: a verdict must be on screen before the next prompt, and the pipe is drained by another
    /// thread.
    fn conclude(&mut self, job: Job, status: i32) {
        let outcome = tokio::task::block_in_place(|| self.mux.conclude_cmd(job.started, status));
        for line in repl::report_lines(&job.principal.to_string(), &outcome) {
            gray(&line);
        }
    }

    /// The next automatic job name, skipping any a live job already occupies.
    ///
    /// Monotonic within a session — a name is never reused while the console runs — because a job
    /// name is a principal, and reusing one would make two transactions indistinguishable in the
    /// capability history.
    pub fn next_name(&mut self) -> String {
        loop {
            let name = self.counter.to_string();
            self.counter += 1;
            if !self.jobs.iter().any(|job| job.name == name) {
                return name;
            }
        }
    }
}

/// The signal a `kill` flag names: `-9`, or `-TERM` and its siblings.
///
/// Only the signals a job control session has any use for are spelled out; anything else has to be
/// given by number, which keeps the table from pretending to be `kill -l`.
fn parse_signal(flag: &str) -> Option<libc::c_int> {
    // Exactly one leading `-`: `--9` and `--` are not signal specifications, and stripping every
    // dash would silently accept the first as `-9`.
    let name = flag.strip_prefix('-').unwrap_or(flag);
    if name.is_empty() {
        return None;
    }
    if let Ok(number) = name.parse::<libc::c_int>() {
        return (number > 0).then_some(number);
    }
    match name.to_ascii_uppercase().as_str() {
        "HUP" => Some(libc::SIGHUP),
        "INT" => Some(libc::SIGINT),
        "QUIT" => Some(libc::SIGQUIT),
        "KILL" => Some(libc::SIGKILL),
        "TERM" => Some(libc::SIGTERM),
        "CONT" => Some(libc::SIGCONT),
        "STOP" => Some(libc::SIGSTOP),
        "USR1" => Some(libc::SIGUSR1),
        "USR2" => Some(libc::SIGUSR2),
        _ => None,
    }
}

/// The exit code a raw wait status means, in shell terms.
fn exit_code(status: i32) -> u8 {
    if libc::WIFEXITED(status) {
        u8::try_from(libc::WEXITSTATUS(status)).unwrap_or(u8::MAX)
    } else if libc::WIFSIGNALED(status) {
        128u8.saturating_add(u8::try_from(libc::WTERMSIG(status)).unwrap_or(0))
    } else {
        1
    }
}

/// Signals a job's whole process group.
fn signal_group(pid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` with a negated pid signals that process group; it has no memory-safety
    // requirements. A job that has already exited yields `ESRCH`, which is not actionable.
    unsafe { libc::kill(-pid, signal) };
}

/// Makes `pgid` the terminal's foreground process group.
///
/// This is the whole of "attaching" a job: the terminal driver decides where Ctrl-C, Ctrl-Z and
/// terminal reads go by process group, so a job that owns the terminal gets keyboard signals
/// natively and full-screen programs work without the console mediating anything.
fn set_foreground(tty: &std::fs::File, pgid: libc::pid_t) {
    // SAFETY: `tcsetpgrp` takes a terminal descriptor and a process group id. `SIGTTOU` is ignored
    // here, so this succeeds even though the console is a background group while a job holds the
    // terminal.
    unsafe { libc::tcsetpgrp(tty.as_raw_fd(), pgid) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signal grammar is the one part of `kill` that is a pure function of its argument, and
    /// getting it wrong would signal the wrong thing rather than fail.
    #[test]
    fn kill_flags_name_signals_by_number_or_name() {
        assert_eq!(parse_signal("-9"), Some(libc::SIGKILL));
        assert_eq!(parse_signal("-KILL"), Some(libc::SIGKILL));
        assert_eq!(parse_signal("-kill"), Some(libc::SIGKILL));
        assert_eq!(parse_signal("-TERM"), Some(libc::SIGTERM));
        assert_eq!(parse_signal("-CONT"), Some(libc::SIGCONT));
        assert_eq!(parse_signal("-USR2"), Some(libc::SIGUSR2));
        for rejected in ["-", "-0", "-SIGKILL", "-nope", "--", "--9"] {
            assert_eq!(parse_signal(rejected), None, "{rejected} is not a signal");
        }
    }

    /// A wait status is the only evidence a transaction has of how its command ended, so the
    /// translation into a shell exit code has to be exact at the signalled boundary.
    #[test]
    fn wait_statuses_become_shell_exit_codes() {
        // Exited with status n: the low byte is the code, per `wait(2)`'s encoding.
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(3 << 8), 3);
        // Killed by signal n: 128 + n, the same convention bash reports.
        assert_eq!(exit_code(libc::SIGINT), 130);
        assert_eq!(exit_code(libc::SIGKILL), 137);
    }
}
