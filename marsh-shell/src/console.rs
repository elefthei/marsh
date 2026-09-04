//! The job table, the terminal it hands out, and the instrumentation stream everything reports on.
//!
//! This is the effectful half of the console: snapshots, traced children, `waitpid`, `tcsetpgrp`
//! and the mux calls that conclude a transaction. The pure half — the line grammar and the report
//! text — is [`crate::repl`].
//!
//! A job is a *sandbox*, not a command: `sd NAME DIR` opens one over a directory read relative to
//! the current job's, typed lines run in whichever one is current, and `fg`/`bg`/`jobs`/`kill`
//! operate on whatever command that sandbox is running right now. A job's name is its principal,
//! which is what makes the job table a picture of the capability contention against the seed:
//! `%foo` and `%bar` race exactly as two agents would.
//!
//! The foreground command owns the real terminal, so full-screen programs (`less`, `vim`, an agent
//! TUI) work exactly as they would in any shell, and Ctrl-C and Ctrl-Z reach it through the
//! terminal rather than through a key handler here.

use std::io::{BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use brush_interactive::LinePrinter;
use shellmux::{MuxError, Sandbox, Session, ShellMux, StartedCmd};

use crate::repl::{self, FOREGROUND};

/// The instrumentation stream: fd 3 of this process, and of every job it starts.
///
/// It is brush-core's third standard stream, not a number this crate invented, so a builtin's
/// `stdinstr()` writer and a job's `echo x >&3` are the same channel.
pub const INSTRUMENTATION_FD: RawFd = brush_core::openfiles::OpenFiles::STDINSTR_FD;

/// Signals the console must not receive, so the foreground job receives them instead.
///
/// The terminal delivers Ctrl-Z to the *foreground process group*, which is the job's, not ours.
/// Ignoring these here is also what makes the tcsetpgrp handoff work at all: a background process
/// group that writes to or reconfigures the terminal would otherwise be stopped by `SIGTTOU`, and
/// that group is us for as long as a job holds the terminal. `SIGQUIT` and `SIGTSTP` stay ignored
/// because an interactive shell neither core-dumps nor suspends itself.
///
/// `SIGINT` is deliberately absent — see [`on_interrupt`].
const IGNORED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

/// Interrupts delivered since the current line was submitted.
static INTERRUPTS: AtomicU32 = AtomicU32::new(0);

/// What the first interrupt prints. Raw bytes because a signal handler may neither allocate nor
/// format, and CRLF-framed because the terminal may be in raw mode.
const INTERRUPT_NOTICE: &[u8] = b"\r\nmarsh: interrupt \xe2\x80\x94 press Ctrl-C again to quit\r\n";

/// The interrupt notice as text. Same words as [`INTERRUPT_NOTICE`], which cannot be derived from
/// it: a signal handler may not format, so its copy is a CRLF-framed byte literal.
const INTERRUPT_TEXT: &str = "marsh: interrupt — press Ctrl-C again to quit";

/// Notes an interrupt; quits on the second one.
///
/// `SIGINT` is deliberately not ignored like the other terminal signals. A job owns the terminal
/// while it runs, so an interrupt aimed at a command never reaches this process; the interrupts
/// that do reach it arrive while the console is doing its own work — concluding a transaction,
/// sweeping at exit — and ignoring those is what left a session with no way out. The second one
/// restores the default disposition and re-raises, so the user is never trapped, whatever the
/// console is in the middle of.
extern "C" fn on_interrupt(_signal: libc::c_int) {
    if INTERRUPTS.fetch_add(1, Ordering::SeqCst) == 0 {
        // SAFETY: `write` is async-signal-safe, and the buffer is a `'static` constant.
        unsafe {
            libc::write(
                libc::STDERR_FILENO,
                INTERRUPT_NOTICE.as_ptr().cast(),
                INTERRUPT_NOTICE.len(),
            );
        }
        return;
    }
    // SAFETY: `signal` is async-signal-safe, and `SIG_DFL` is always a valid disposition.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    // SAFETY: `raise` is async-signal-safe; the default disposition restored just above is what
    // makes this re-raise terminate the process instead of re-entering this handler.
    unsafe {
        libc::raise(libc::SIGINT);
    }
}

/// Counts one interrupt that arrived as a keystroke and reports whether the session should end.
///
/// The line editor holds the terminal in raw mode while it reads, so Ctrl-C at the prompt is input,
/// not a signal, and [`on_interrupt`] never runs. Advancing the same counter here is what makes the
/// promise [`INTERRUPT_NOTICE`] prints true at the prompt as well: `true` on the second consecutive
/// interrupt. Unlike the signal path, the caller can then leave through the ordinary exit, so the
/// sweep still runs.
pub fn note_interrupt() -> bool {
    if INTERRUPTS.fetch_add(1, Ordering::SeqCst) == 0 {
        eprintln!("{INTERRUPT_TEXT}");
        return false;
    }
    true
}

/// Forgets the interrupts counted against the previous line.
pub fn arm_interrupts() {
    INTERRUPTS.store(0, Ordering::SeqCst);
}

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

/// Where instrumentation goes while a line editor holds the terminal.
static PRINTER: OnceLock<LinePrinter> = OnceLock::new();

/// Publishes `printer` as the sink [`gray`] offers its lines to first.
///
/// Not an error to call twice: a second console would be the bug, a second printer would not.
pub fn install_printer(printer: LinePrinter) {
    let _ = PRINTER.set(printer);
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
    // SAFETY: `signal` installs a disposition for one signal number; `on_interrupt` is
    // async-signal-safe.
    let _ = unsafe {
        libc::signal(
            libc::SIGINT,
            on_interrupt as *const () as libc::sighandler_t,
        )
    };
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
/// A line editor gets first refusal. A raw write to a terminal reedline is holding is erased by its
/// next repaint, because it repaints from a cursor origin cached before the write; handing the line
/// to the editor instead makes it print above the prompt and redraw around it.
pub fn gray(line: &str) {
    let text = format!("{GRAY}{line}\x1b[0m");
    if PRINTER
        .get()
        .is_some_and(|printer| printer.try_print(&text))
    {
        return;
    }
    // No editor is holding the terminal, or its queue was full. Framed for a raw-mode terminal
    // anyway — a job may have put it in one — and written once, so a job's output and the
    // console's reports cannot tear into each other.
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(format!("\r\x1b[K{text}\r\n").as_bytes());
    let _ = stdout.flush();
}

/// Whether a job's command is running or parked by a stop signal.
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

/// One job: a named sandbox, and whatever command is running in it.
struct Job {
    /// The handle `jobs` prints and `fg %name` resolves.
    name: String,
    /// The sandbox every command of this job runs in.
    sandbox: Sandbox,
    /// The command currently running in it, if any.
    running: Option<Running>,
}

/// The half of a job that exists only while a command is in flight.
struct Running {
    /// The command line, for `jobs` and the job's start line.
    cmd: String,
    /// Process id of the traced child — also its process-group id, so `kill(-pid, …)` reaches the
    /// tracer, the shell it traces and every descendant together.
    pid: libc::pid_t,
    /// Whether it is running or stopped.
    state: JobState,
    /// The open transaction.
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
    /// The sandboxes of this session, in creation order.
    jobs: Vec<Job>,
    /// Name of the job typed lines run in.
    current: String,
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
    ///
    /// Opens the default job in the same breath: `main`, rooted where marsh was started, so a bare
    /// `ls` lists that directory's contents and a session is usable before anything is typed.
    ///
    /// # Errors
    ///
    /// Fails when the `main` sandbox's snapshot cannot be taken.
    pub fn open(
        mux: Arc<ShellMux>,
        tty: std::fs::File,
        own_pgid: libc::pid_t,
    ) -> Result<Self, MuxError> {
        // The default job is rooted at the current directory *inside* the seed, which is the whole
        // point of deriving the session from where marsh was started. Canonicalized because the
        // seed is; a directory that cannot be read falls through to the seed root.
        let cwd = std::env::current_dir()
            .and_then(|dir| dir.canonicalize())
            .unwrap_or_default();
        let dir = mux.session().default_dir(&cwd);
        let sandbox = mux.open_sandbox(FOREGROUND, &dir)?;
        Ok(Self {
            mux,
            jobs: vec![Job {
                name: FOREGROUND.to_string(),
                sandbox,
                running: None,
            }],
            current: FOREGROUND.to_string(),
            tty,
            own_pgid,
            counter: 1,
            exit_armed: false,
        })
    }

    /// The session every transaction is against.
    pub fn session(&self) -> &Session {
        self.mux.session()
    }

    /// The prompt for the current job: the id of its snapshot, then the seed directory it is
    /// rooted at.
    ///
    /// Different for every job by construction — a uid names one snapshot and nothing else's
    /// — so the prompt answers the only question a multi-job session makes ambiguous: where does
    /// the next line I type run.
    ///
    /// Backslashes are doubled because the outer shell still parses prompt escapes (`\w`, `\$`).
    /// Nothing else needs quoting: that shell is built with `promptvars` off, so the composed
    /// prompt is never expanded as a word, and a directory named `$(rm -rf ~)` stays text.
    pub fn prompt(&self) -> String {
        let Some(job) = self.jobs.get(self.current_index()) else {
            return format!("{FOREGROUND}$ ");
        };
        format!(
            "{}@{}$ ",
            job.sandbox.uid,
            dir_label(&job.sandbox).replace('\\', "\\\\")
        )
    }

    /// The directory the current job's commands run in: its work snapshot, plus the sandbox's
    /// seed-relative directory.
    ///
    /// This is what the outer shell's completion resolves paths against, so a Tab at the prompt
    /// offers what the next line would actually see.
    pub fn current_dir(&self) -> PathBuf {
        let Some(job) = self.jobs.get(self.current_index()) else {
            return self.mux.session().seed.clone();
        };
        self.mux
            .session()
            .work(&job.sandbox.uid)
            .join(&job.sandbox.dir)
    }

    /// Index of the current job.
    ///
    /// The table always holds `main` and a job is only ever removed by the exit sweep, so the
    /// lookup cannot fail; the fallback keeps a lost pointer from panicking a live session.
    fn current_index(&self) -> usize {
        self.jobs
            .iter()
            .position(|job| job.name == self.current)
            .unwrap_or(0)
    }

    /// Reaps finished and newly stopped commands, concluding the transactions of the finished ones.
    ///
    /// Called once per loop turn, between one line's execution and the next prompt, which is where
    /// bash reports job status too: a merge that lands while the user is typing would otherwise
    /// scribble over the line being edited.
    pub fn reap(&mut self) {
        for index in 0..self.jobs.len() {
            let Some(running) = self.jobs[index].running.as_ref() else {
                continue;
            };
            match wait_job(running.pid, libc::WNOHANG | libc::WUNTRACED) {
                Wait::Running => {}
                Wait::Stopped => {
                    let name = self.jobs[index].name.clone();
                    if let Some(running) = self.jobs[index].running.as_mut()
                        && running.state != JobState::Stopped
                    {
                        running.state = JobState::Stopped;
                        gray(&format!("%{name} stopped — fg %{name} to resume"));
                    }
                }
                Wait::Finished(status) => self.conclude(index, status),
            }
        }
    }

    /// Forgets a pending `exit` warning, because something other than `exit` was submitted.
    pub const fn disarm_exit(&mut self) {
        self.exit_armed = false;
    }

    /// Whether the session may end now, warning once while a command is still running.
    ///
    /// The warning is not paternalism: a running command is an open transaction, and quitting kills
    /// it before it can merge.
    pub fn may_exit(&mut self, err: &mut dyn Write) -> bool {
        if self.jobs.iter().any(|job| job.running.is_some()) && !self.exit_armed {
            let _ = writeln!(
                err,
                "marsh: there are running jobs (exit again to kill them)"
            );
            self.exit_armed = true;
            return false;
        }
        true
    }

    /// Hangs up, kills and concludes every running command, then closes every sandbox.
    ///
    /// Runs after the loop has returned, whether the session ended with `exit`, with Ctrl-D or with
    /// an error. Merges can still land here — a command that finishes its work while being hung up
    /// has earned its capabilities — and the ones that die of the signal roll back as failed
    /// executions. Closing the sandboxes is what leaves `snap/` empty: a snapshot nobody concludes
    /// is a subvolume nobody deletes.
    pub fn sweep(&mut self) {
        for job in &self.jobs {
            if let Some(running) = &job.running {
                // SIGCONT after SIGHUP: a stopped job would not run its hangup until it is resumed.
                signal_group(running.pid, libc::SIGHUP);
                signal_group(running.pid, libc::SIGCONT);
            }
        }

        let deadline = Instant::now() + SWEEP_GRACE;
        while self.jobs.iter().any(|job| job.running.is_some()) && Instant::now() < deadline {
            for index in 0..self.jobs.len() {
                let Some(running) = self.jobs[index].running.as_ref() else {
                    continue;
                };
                if let Wait::Finished(status) = wait_job(running.pid, libc::WNOHANG) {
                    self.conclude(index, status);
                }
            }
            if self.jobs.iter().any(|job| job.running.is_some()) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        for index in 0..self.jobs.len() {
            let Some(running) = self.jobs[index].running.as_ref() else {
                continue;
            };
            let pid = running.pid;
            signal_group(pid, libc::SIGKILL);
            let status = match wait_job(pid, 0) {
                Wait::Finished(status) => status,
                // A stop cannot survive SIGKILL, and a blocking wait does not return "running".
                _ => libc::SIGKILL,
            };
            self.conclude(index, status);
        }

        for job in &self.jobs {
            self.mux.close_sandbox(&job.sandbox);
        }
        self.jobs.clear();
    }

    /// Opens a job named `name`, a sandbox rooted at `dir` as typed at `sd` — a path in the
    /// current job, or seed-rooted when it starts with `/` — and makes it current.
    pub fn open_sandbox(&mut self, name: String, dir: &str, err: &mut dyn Write) -> u8 {
        if self.jobs.iter().any(|job| job.name == name) {
            let _ = writeln!(err, "sd: %{name} already exists");
            return 1;
        }
        let dir = repl::job_dir(
            self.jobs
                .get(self.current_index())
                .map_or("", |job| job.sandbox.dir.as_str()),
            dir,
        );
        let sandbox = match tokio::task::block_in_place(|| self.mux.open_sandbox(&name, &dir)) {
            Ok(sandbox) => sandbox,
            Err(error) => {
                let _ = writeln!(err, "marsh: {error}");
                return 1;
            }
        };
        gray(&format!("%{name} -> {}", dir_label(&sandbox)));
        self.jobs.push(Job {
            name: name.clone(),
            sandbox,
            running: None,
        });
        self.current = name;
        0
    }

    /// Starts `cmd` in the current job, reporting a busy job or a failed start to `err`.
    ///
    /// Returns the job's index, or `None` when nothing started — the caller's exit code is then 1.
    fn start_current(&mut self, cmd: String, err: &mut dyn Write) -> Option<usize> {
        let index = self.current_index();
        if self.jobs[index].running.is_some() {
            let _ = writeln!(
                err,
                "marsh: %{} is busy — wait for it or start another with sd",
                self.jobs[index].name
            );
            return None;
        }
        if let Err(error) = self.start(index, cmd) {
            let _ = writeln!(err, "marsh: {error}");
            return None;
        }
        Some(index)
    }

    /// Runs `cmd` in the current job, attached to the terminal.
    pub fn foreground(&mut self, cmd: String, err: &mut dyn Write) -> u8 {
        match self.start_current(cmd, err) {
            Some(index) => self.attach(index, false),
            None => 1,
        }
    }

    /// Starts `cmd` in the current job without waiting for it.
    ///
    /// Background jobs inherit the real terminal, bash-style: their output interleaves live, and a
    /// background read from the terminal earns `SIGTTIN`, which stops the job for `fg` to service.
    pub fn background(&mut self, cmd: String, err: &mut dyn Write) -> u8 {
        match self.start_current(cmd, err) {
            Some(index) => {
                let job = &self.jobs[index];
                if let Some(running) = &job.running {
                    gray(&format!("%{} $ {}", job.name, running.cmd));
                }
                0
            }
            None => 1,
        }
    }

    /// Makes a job current, and attaches its command to the terminal if it has one.
    ///
    /// Bare `fg` takes the most recent job.
    pub fn fg(&mut self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(index) = self.resolve(name, "fg", None, err) else {
            return 1;
        };
        self.current = self.jobs[index].name.clone();
        let Some(cmd) = self.jobs[index]
            .running
            .as_ref()
            .map(|running| running.cmd.clone())
        else {
            gray(&format!("%{} is current", self.jobs[index].name));
            return 0;
        };
        // The user typed `fg`, not the command, so the command line is worth repeating.
        gray(&format!("%{} $ {cmd}", self.jobs[index].name));
        self.attach(index, true)
    }

    /// Resumes a stopped command in the background: bare `bg` takes the most recent stopped one.
    pub fn bg(&mut self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(index) = self.resolve(name, "bg", Some(JobState::Stopped), err) else {
            return 1;
        };
        let job_name = self.jobs[index].name.clone();
        let Some(running) = self.jobs[index].running.as_mut() else {
            let _ = writeln!(err, "bg: %{job_name} is not running");
            return 1;
        };
        if running.state == JobState::Running {
            let _ = writeln!(err, "bg: job %{job_name} already running");
            return 1;
        }
        running.state = JobState::Running;
        let (pid, cmd) = (running.pid, running.cmd.clone());
        signal_group(pid, libc::SIGCONT);
        gray(&format!("%{job_name} continued: {cmd}"));
        0
    }

    /// Signals jobs and process ids.
    ///
    /// A `%name` target signals the job's whole process group, because a running command *is* a
    /// process group: the tracer, the shell it traces and every descendant have to receive the
    /// signal together, or a `kill` would leave the transaction's tracer alive around a dead child.
    /// A bare pid is signalled as itself, exactly as `kill(1)` does.
    pub fn kill(&mut self, args: &[String], err: &mut dyn Write) -> u8 {
        let (signal, targets) = match args.split_first() {
            Some((first, rest)) if first.starts_with('-') => {
                let Some(signal) = parse_signal(first) else {
                    let _ = writeln!(err, "kill: {first}: invalid signal specification");
                    return 1;
                };
                (signal, rest)
            }
            _ => (libc::SIGTERM, args),
        };
        if targets.is_empty() {
            let _ = writeln!(err, "kill: usage: kill [-SIGNAL] %NAME|PID…");
            return 1;
        }

        let mut code = 0;
        for target in targets {
            if let Some(name) = target.strip_prefix('%') {
                if let Some(job) = self.jobs.iter().find(|job| job.name == name) {
                    if let Some(running) = &job.running {
                        signal_group(running.pid, signal);
                    } else {
                        let _ = writeln!(err, "kill: %{name} is not running");
                        code = 1;
                    }
                } else {
                    let _ = writeln!(err, "kill: no such job: %{name}");
                    code = 1;
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
    /// command, while `fg` is meaningful for any job.
    fn resolve(
        &self,
        name: Option<&str>,
        verb: &str,
        default_state: Option<JobState>,
        err: &mut dyn Write,
    ) -> Option<usize> {
        if let Some(name) = name {
            let index = self.jobs.iter().position(|job| job.name == name);
            if index.is_none() {
                let _ = writeln!(err, "{verb}: no such job: %{name}");
            }
            return index;
        }
        let index = match default_state {
            Some(state) => self.jobs.iter().rposition(|job| {
                job.running
                    .as_ref()
                    .is_some_and(|running| running.state == state)
            }),
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

    /// Writes the job table to `out`, one row per sandbox.
    pub fn print_jobs(&self, out: &mut dyn Write) {
        for job in &self.jobs {
            let marker = if job.name == self.current { "*" } else { "" };
            let dir = dir_label(&job.sandbox);
            let (state, cmd) = job.running.as_ref().map_or(("idle", ""), |running| {
                (running.state.label(), running.cmd.as_str())
            });
            let _ = writeln!(
                out,
                "{}",
                format!(
                    "%{}{marker} {dir} {} {state} {cmd}",
                    job.name, job.sandbox.uid
                )
                .trim_end()
            );
        }
    }

    /// Refreshes the job's snapshot and spawns `cmd` as its own process group.
    fn start(&mut self, index: usize, cmd: String) -> Result<(), MuxError> {
        let sandbox = self.jobs[index].sandbox.clone();
        // `block_in_place`: `start_cmd` builds the principal's shell on the mux's own runtime, and
        // blocking on a nested runtime from an async context panics unless the thread is marked as
        // blocking.
        let started = tokio::task::block_in_place(|| {
            self.mux.start_cmd(&sandbox, &cmd, Some(INSTRUMENTATION_FD))
        })?;
        let pid = started.pid();
        // Also set from the child's side. Doing it here too closes the race where the parent hands
        // the terminal to a group the child has not created yet; `EACCES` (the child already
        // exec'd) and `ESRCH` (it already exited) are both benign.
        // SAFETY: `setpgid` only manipulates process group membership.
        unsafe { libc::setpgid(pid, pid) };
        self.jobs[index].running = Some(Running {
            cmd,
            pid,
            state: JobState::Running,
            started,
        });
        Ok(())
    }

    /// Gives job `index`'s command the terminal and waits for it to exit or stop.
    ///
    /// Returns the exit code the console reports for the line. A command that stops leaves its job
    /// in the table as a background one — that is what Ctrl-Z means.
    fn attach(&mut self, index: usize, resume: bool) -> u8 {
        let Some(pid) = self.jobs[index].running.as_ref().map(|running| running.pid) else {
            return 0;
        };
        set_foreground(&self.tty, pid);
        if resume {
            signal_group(pid, libc::SIGCONT);
        }
        let wait = wait_job(pid, libc::WUNTRACED);
        set_foreground(&self.tty, self.own_pgid);

        match wait {
            Wait::Finished(status) => {
                let code = exit_code(status);
                self.conclude(index, status);
                code
            }
            Wait::Stopped | Wait::Running => {
                let name = self.jobs[index].name.clone();
                if let Some(running) = self.jobs[index].running.as_mut() {
                    running.state = JobState::Stopped;
                }
                gray(&format!("%{name} stopped — fg %{name} to resume"));
                // The same code bash reports for a job stopped by SIGTSTP.
                148
            }
        }
    }

    /// Concludes the finished command of job `index` and reports the verdict in gray.
    ///
    /// Reports are printed here, synchronously, rather than pushed through the instrumentation
    /// pipe: a verdict must be on screen before the next prompt, and the pipe is drained by another
    /// thread. The sandbox keeps its snapshots — they are the job's, not the command's.
    fn conclude(&mut self, index: usize, status: i32) {
        let Some(running) = self.jobs[index].running.take() else {
            return;
        };
        let name = self.jobs[index].name.clone();
        let outcome =
            tokio::task::block_in_place(|| self.mux.conclude_cmd(running.started, status));
        for line in repl::report_lines(&name, &outcome) {
            gray(&line);
        }
    }

    /// The next automatic job name, skipping any a job already occupies.
    ///
    /// Monotonic within a session — a name is never reused while the console runs — because a job
    /// name is a principal, and reusing one would make two sandboxes indistinguishable in the
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

/// How a sandbox's directory is shown: `.` for the seed root, the path otherwise.
fn dir_label(sandbox: &Sandbox) -> &str {
    if sandbox.dir.is_empty() {
        "."
    } else {
        &sandbox.dir
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

    /// The promise `INTERRUPT_NOTICE` prints: the first interrupt warns, the second ends the
    /// session. Sole test touching `INTERRUPTS`, which is process-global.
    #[test]
    fn the_second_consecutive_interrupt_asks_to_quit() {
        arm_interrupts();
        assert!(!note_interrupt(), "the first interrupt only warns");
        assert!(note_interrupt(), "the second ends the session");
        arm_interrupts();
        assert!(
            !note_interrupt(),
            "submitting a line forgets the previous one"
        );
    }
}
