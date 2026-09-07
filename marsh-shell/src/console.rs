//! The terminal a job is handed, and the instrumentation stream everything reports on.
//!
//! This is the effectful half of the console: the tty, `tcsetpgrp`, the merge queue and the mux
//! calls that open a job, start a command in one and conclude its transaction. The job table
//! itself is the mux's ([`shellmux::ShellMux::spawn`]), because a job's name is a principal; the
//! pure half — the line grammar and the report text — is [`crate::repl`].
//!
//! A job is a *sandbox*, not a command: `sd NAME DIR` opens one over a directory read relative to
//! the current job's, a trailing `&` opens one for the line it ends, typed lines run in whichever
//! one is current, and `fg`/`bg`/`jobs`/`stop` operate on whatever command that sandbox is running
//! right now. A job's name is its principal, which is what makes the job table a picture of the
//! capability contention against the seed: `%foo` and `%bar` race exactly as two agents would.
//!
//! The foreground command owns the real terminal, so full-screen programs (`less`, `vim`, an agent
//! TUI) work exactly as they would in any shell, and Ctrl-C and Ctrl-Z reach it through the
//! terminal rather than through a key handler here.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use brush_interactive::LinePrinter;
use shellmux::{JobState, MuxError, Reaped, Sandbox, Session, ShellMux, StartedCmd};

use crate::error::Error;
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
/// that do reach it arrive while the console is doing its own work — concluding a transaction —
/// and ignoring those is what left a session with no way out. The second one restores the default
/// disposition and re-raises, so the user is never trapped, whatever the console is doing.
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
/// interrupt. Unlike the signal path, the caller can then leave through the ordinary exit.
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
pub fn install(console: Arc<Mutex<Console>>) -> Result<(), crate::error::Error> {
    CONSOLE.set(console).map_err(|_| Error::ConsoleInstalled)
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
///
/// `SIGCHLD` is the one disposition not installed here: it needs its wakeup pipe to exist first,
/// so [`watch_children`] installs it.
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
pub fn open_instrumentation() -> Result<std::fs::File, crate::error::Error> {
    let mut ends: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `pipe2` writes exactly two descriptors through the pointer we pass.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::CreateInstrumentation(std::io::Error::last_os_error()));
    }
    let [mut read_end, write_end] = ends;

    // The kernel hands out the lowest free descriptors, so the read end can *be* fd 3 — in which
    // case the `dup2` below would silently close it. Move it out of the way first.
    if read_end == INSTRUMENTATION_FD {
        // SAFETY: duplicating a descriptor we own to the lowest free number above fd 3.
        let moved = unsafe { libc::fcntl(read_end, libc::F_DUPFD_CLOEXEC, INSTRUMENTATION_FD + 1) };
        if moved < 0 {
            return Err(Error::RelocateInstrumentation(
                std::io::Error::last_os_error(),
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
            return Err(Error::ShareInstrumentation(std::io::Error::last_os_error()));
        }
    } else {
        // SAFETY: both arguments are open descriptors we own; `dup2` closes fd 3 first if it was
        // in use (an inherited fd 3 is exactly what a session is meant to replace).
        if unsafe { libc::dup2(write_end, INSTRUMENTATION_FD) } < 0 {
            return Err(Error::InstallInstrumentation(
                std::io::Error::last_os_error(),
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

/// The write end of the child-watch pipe, or `-1` before [`watch_children`] runs.
///
/// A signal handler may not allocate or lock, so the descriptor it writes to has to be reachable as
/// a plain integer.
static CHILD_NOTIFY: AtomicI32 = AtomicI32::new(-1);

/// Wakes the reaper thread: one byte per child that changed state.
///
/// The byte carries nothing — [`Console::reap`] polls every job — so a write that fails because the
/// pipe is full is not a lost wakeup: one is already pending.
extern "C" fn on_child(_signal: libc::c_int) {
    let notify = CHILD_NOTIFY.load(Ordering::SeqCst);
    if notify < 0 {
        return;
    }
    let byte = 1u8;
    // SAFETY: `write` is async-signal-safe, the descriptor is this process's own, and the buffer is
    // one byte on this frame.
    unsafe { libc::write(notify, std::ptr::from_ref(&byte).cast(), 1) };
}

/// Starts the watcher that concludes a job's transaction as soon as the job ends.
///
/// A merge that waits for the next prompt is a merge that can lose a race it had already won, so
/// `SIGCHLD` — not the loop turn — is what drives it. The handler only writes a byte; the thread
/// does the work, because reaping takes the console lock. The merge itself is handed on once more,
/// to the thread [`spawn_merger`] starts, which takes no console lock at all.
///
/// Must be called after [`install`]: the thread reaps through [`shared`].
///
/// # Errors
///
/// Fails when the wakeup pipe cannot be created or configured.
pub fn watch_children() -> Result<(), crate::error::Error> {
    let mut ends: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `pipe2` writes exactly two descriptors through the pointer we pass.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::CreateChildWatch(std::io::Error::last_os_error()));
    }
    let [read_end, write_end] = ends;
    // Non-blocking, because a signal handler that blocks on a full pipe would stop the process it
    // is meant to be reporting about.
    // SAFETY: setting the status flags of a descriptor we own.
    if unsafe { libc::fcntl(write_end, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(Error::ConfigureChildWatch(std::io::Error::last_os_error()));
    }
    CHILD_NOTIFY.store(write_end, Ordering::SeqCst);
    // SAFETY: `signal` installs a disposition for one signal number; `on_child` is
    // async-signal-safe.
    let _ = unsafe { libc::signal(libc::SIGCHLD, on_child as *const () as libc::sighandler_t) };

    // SAFETY: `read_end` is an open descriptor this function owns and never touches again.
    let mut wakeups = unsafe { std::fs::File::from_raw_fd(read_end) };
    let _ = std::thread::spawn(move || {
        let mut buffer = [0u8; 64];
        loop {
            match wakeups.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
            let Some(console) = shared() else {
                continue;
            };
            let console = console.lock().unwrap_or_else(PoisonError::into_inner);
            console.reap();
        }
    });
    Ok(())
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

/// One command's conclusion, waiting for the merge thread.
struct Merge {
    /// The job it ran in; its verdict is reported under this name.
    name: String,
    /// The open transaction whose wait has already ended.
    ///
    /// Boxed, as [`Reaped::Ended`] hands it over: a queue entry is a pointer rather than a whole
    /// transaction, and the conclusion unboxes it once.
    started: Box<StartedCmd>,
    /// Raw `waitpid(2)` status the command exited with.
    status: i32,
}

/// The conclusions handed off, and what each job still owes.
struct MergeQueue {
    /// Conclusions the worker has not taken yet.
    pending: VecDeque<Merge>,
    /// Per-job count of conclusions submitted and not yet reported.
    active: HashMap<String, usize>,
    /// Set when the session ends: the worker returns once the queue drains.
    closed: bool,
}

/// The merge thread's half of the console.
///
/// `ShellMux::conclude_cmd` walks the seed and the snapshot to compute the write set, which on a
/// large seed takes seconds. Doing that under the console mutex is what made `jobs` wait for the
/// previous command, so the console only ever *submits* here and the worker does the work.
struct Merges {
    /// The queue and its bookkeeping.
    queue: Mutex<MergeQueue>,
    /// Signals a submission to the worker, and a completion to [`Merges::wait_for`].
    signal: Condvar,
}

impl Merges {
    /// An empty queue.
    fn new() -> Self {
        Self {
            queue: Mutex::new(MergeQueue {
                pending: VecDeque::new(),
                active: HashMap::new(),
                closed: false,
            }),
            signal: Condvar::new(),
        }
    }

    /// The queue, recovering a poisoned lock like the rest of this file: a thread that died holding
    /// it left the queue itself intact, and refusing to serve it would strand every open merge.
    fn lock(&self) -> MutexGuard<'_, MergeQueue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands `merge` to the worker and counts it against its job.
    fn submit(&self, merge: Merge) {
        let mut queue = self.lock();
        if queue.closed {
            return;
        }
        *queue.active.entry(merge.name.clone()).or_insert(0) += 1;
        queue.pending.push_back(merge);
        drop(queue);
        self.signal.notify_all();
    }

    /// The next conclusion, or `None` once the queue is closed and empty. Blocks.
    fn take(&self) -> Option<Merge> {
        let mut queue = self.lock();
        loop {
            if queue.closed {
                return None;
            }
            if let Some(merge) = queue.pending.pop_front() {
                return Some(merge);
            }
            queue = self
                .signal
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Marks one conclusion reported and wakes whoever waits on that job.
    fn finish(&self, name: &str) {
        let mut queue = self.lock();
        if let Some(count) = queue.active.get_mut(name) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                queue.active.remove(name);
            }
        }
        drop(queue);
        self.signal.notify_all();
    }

    /// Blocks until job `name` owes no conclusion.
    fn wait_for(&self, name: &str) {
        let mut queue = self.lock();
        while !queue.closed && queue.active.contains_key(name) {
            queue = self
                .signal
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(queue);
    }

    /// Whether `name` has a conclusion in flight — what `jobs` prints as `merging`.
    fn is_merging(&self, name: &str) -> bool {
        self.lock().active.contains_key(name)
    }

    /// Closes the queue immediately; no further conclusion may start.
    fn cancel(&self) {
        let mut queue = self.lock();
        queue.closed = true;
        drop(queue);
        self.signal.notify_all();
    }
}

/// Starts the detached thread that concludes transactions off the console lock.
fn spawn_merger(mux: Arc<ShellMux>, merges: Arc<Merges>) {
    let _ = std::thread::spawn(move || {
        while let Some(Merge {
            name,
            started,
            status,
        }) = merges.take()
        {
            let outcome = mux.conclude_cmd(*started, status);
            for line in repl::report_lines(&name, &outcome) {
                gray(&line);
            }
            // A job the `1`, `2`, … series named for one `&` line has nothing left once that line
            // has merged and been reported. Silent: the verdict above already named the job, and a
            // second line per background command would be noise.
            mux.close_if_transient(&name);
            merges.finish(&name);
        }
    });
}

/// The console: the terminal, and the front-end's view of the mux's job table.
pub struct Console {
    /// The multiplexer every line is a transaction against, and the job table it owns.
    mux: Arc<ShellMux>,
    /// Name of the job typed lines run in. The mux has no current job: a batch caller has none,
    /// and which one a reader is looking at is the terminal's question.
    current: String,
    /// The terminal, for handing the foreground process group to a job and taking it back.
    tty: std::fs::File,
    /// This process's group id: what the terminal goes back to when a job releases it.
    own_pgid: libc::pid_t,
    /// Whether a preceding `exit` already warned about live jobs.
    exit_armed: bool,
    /// Conclusions handed to the merge thread, and the jobs that still owe one.
    merges: Arc<Merges>,
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
        mux.spawn(&dir, Some(FOREGROUND.to_string()), None)?;
        let merges = Arc::new(Merges::new());
        spawn_merger(Arc::clone(&mux), Arc::clone(&merges));
        Ok(Self {
            mux,
            current: FOREGROUND.to_string(),
            tty,
            own_pgid,
            exit_armed: false,
            merges,
        })
    }

    /// The session every transaction is against.
    pub fn session(&self) -> &Session {
        self.mux.session()
    }

    /// The prompt for the current job: its name, then the seed directory it is rooted at.
    ///
    /// The name rather than the snapshot's uid: a job's name is unique among the open ones by
    /// construction — [`ShellMux::spawn`] refuses one a live job holds — so it answers the only
    /// question a multi-job session makes ambiguous, where does the next line I type run, and it
    /// answers it in the same word `jobs` prints and `fg` takes. `main` is the job a session opens
    /// with; a job nobody named is `1`, `2`, … in turn.
    ///
    /// Backslashes are doubled because the outer shell still parses prompt escapes (`\w`, `\$`) —
    /// in the name as well as the directory, since `CMD &"a name"` admits one. Nothing else needs
    /// quoting: that shell is built with `promptvars` off, so the composed prompt is never expanded
    /// as a word, and a directory named `$(rm -rf ~)` stays text.
    pub fn prompt(&self) -> String {
        let Some(job) = self.mux.job(&self.current) else {
            return format!("{FOREGROUND}$ ");
        };
        format!(
            "{}@{}$ ",
            job.name.replace('\\', "\\\\"),
            dir_label(&job.sandbox).replace('\\', "\\\\")
        )
    }

    /// The directory the current job's commands run in: its work snapshot, plus the sandbox's
    /// seed-relative directory.
    ///
    /// This is what the outer shell's completion resolves paths against, so a Tab at the prompt
    /// offers what the next line would actually see.
    pub fn current_dir(&self) -> PathBuf {
        let Some(job) = self.mux.job(&self.current) else {
            return self.mux.session().seed.clone();
        };
        let work = self
            .mux
            .session()
            .work(&job.sandbox.uid)
            .join(&job.sandbox.dir);
        if work.is_dir() {
            return work;
        }
        // No command has needed a snapshot in this job yet. The seed is what the next one will
        // copy, so it is also what completion should be offering.
        self.mux.session().seed.join(&job.sandbox.dir)
    }

    /// Reaps finished and newly stopped commands, concluding the transactions of the finished ones.
    ///
    /// Driven by `SIGCHLD` through [`watch_children`], so a background job's merge and verdict land
    /// as soon as it exits rather than at the next prompt turn; `before_prompt` and `jobs` reap too,
    /// as backstops. Reports go through [`gray`], which hands a line to the editor rather than
    /// writing over the one being typed.
    pub fn reap(&self) {
        for reaped in self.mux.reap() {
            match reaped {
                Reaped::Stopped { name } => gray(&format!(
                    "{0} stopped — fg {0} to resume",
                    shellmux::job_ref(&name)
                )),
                Reaped::Ended {
                    name,
                    started,
                    status,
                } => self.conclude(name, started, status),
            }
        }
    }

    /// Forgets a pending `exit` warning, because something other than `exit` was submitted.
    pub const fn disarm_exit(&mut self) {
        self.exit_armed = false;
    }

    /// Whether the session may end now, warning once while a command is still running.
    ///
    /// The warning is not paternalism: a running command is an open transaction, a starting one is
    /// a transaction whose snapshot is being taken, and quitting kills either before it can merge.
    pub fn may_exit(&mut self, err: &mut dyn Write) -> bool {
        if self
            .mux
            .jobs()
            .iter()
            .any(|job| job.running.is_some() || job.starting)
            && !self.exit_armed
        {
            let _ = writeln!(
                err,
                "marsh: there are running jobs (exit again to kill them)"
            );
            self.exit_armed = true;
            return false;
        }
        true
    }

    /// Cancels queued conclusions without waiting for running work or reclaiming persistent state.
    pub(crate) fn end_session(&self) {
        self.merges.cancel();
    }

    /// Opens a job over `dir` — a path in the current job, or seed-rooted when it starts with `/` —
    /// and either makes it current or starts `cmd` in it.
    ///
    /// The one way a job is opened: `sd NAME DIR` is `spawn(dir, Some(name), None)`, `sda DIR` is
    /// `spawn(dir, None, None)`, `CMD &` is `spawn(".", None, Some(cmd))` and `CMD &NAME` is
    /// `spawn(".", Some(name), Some(cmd))`.
    ///
    /// A job opened without a command becomes current, because that is what `sd` is for. One opened
    /// with a command does not: `&` runs a line *beside* what is being worked on, so the prompt,
    /// completion and the next typed line all stay where they were.
    ///
    /// A command is *reserved* by `spawn` and launched on a thread of its own. The launch retakes
    /// the snapshot, builds the principal's shell and spawns a tracer, which on a large seed takes
    /// seconds, and this method runs under the console lock on the line the user just submitted:
    /// doing it inline is what made `CMD &NAME` hold the prompt for all of it, and what made a
    /// second `&` line announce itself only after the first job's verdict. The exit code reports
    /// the *opening* — a taken name, a directory outside the seed — because that is the only part
    /// that has happened when the prompt comes back; a launch that fails reports itself through
    /// [`gray`] like any other job event.
    pub fn spawn(
        &mut self,
        dir: &str,
        name: Option<String>,
        cmd: Option<String>,
        err: &mut dyn Write,
    ) -> u8 {
        let dir = repl::job_dir(
            &self
                .mux
                .job(&self.current)
                .map_or_else(String::new, |job| job.sandbox.dir),
            dir,
        );
        let spawned = match self.mux.spawn(&dir, name, cmd.as_deref()) {
            Ok(spawned) => spawned,
            Err(error) => {
                let _ = writeln!(err, "marsh: {error}");
                return 1;
            }
        };
        gray(&format!(
            "{} -> {}",
            shellmux::job_ref(&spawned.name),
            dir_label(&spawned.sandbox)
        ));
        let Some(cmd) = cmd else {
            self.current = spawned.name;
            return 0;
        };
        gray(&format!("{} $ {cmd}", shellmux::job_ref(&spawned.name)));

        // A thread of its own rather than a queue: `launch_into` holds only the authority *read*
        // lock over its snapshot, so two jobs snapshot at the same time, and a single worker would
        // serialize exactly the concurrency the mux is built for. There can never be more of these
        // than there are open jobs: the job is `starting` from the moment `spawn` returned, and
        // nothing else may launch into one.
        //
        // It takes no console lock, ever — the same rule the merge thread keeps.
        let mux = Arc::clone(&self.mux);
        let _ = std::thread::spawn(move || {
            if let Err(error) = mux.launch_into(&spawned.name, &cmd, Some(INSTRUMENTATION_FD)) {
                // The line that opened the job has already been answered, so there is no exit code
                // left to carry this: it goes where every other job event goes.
                gray(&format!(
                    "{} did not start: {error}",
                    shellmux::job_ref(&spawned.name)
                ));
                // Nothing ever ran in it, so the row would be one more name between a reader and
                // the real jobs, and its tree one nobody would look at.
                mux.close_sandbox(&spawned.sandbox);
            }
        });
        0
    }

    /// Runs `cmd` in the current job, attached to the terminal.
    ///
    /// One command at a time per job: a job already running one is reported busy rather than
    /// queued, because the second command would want a snapshot the first has not merged yet.
    pub fn foreground(&self, cmd: &str, err: &mut dyn Write) -> u8 {
        let name = self.current.clone();
        if self
            .mux
            .job(&name)
            .is_some_and(|job| job.running.is_some() || job.starting)
        {
            let _ = writeln!(
                err,
                "marsh: {} is busy — wait for it, or append & to run in a new job",
                shellmux::job_ref(&name)
            );
            return 1;
        }
        // A command may not start before its predecessor's merge has landed: the launch retakes the
        // snapshot from the seed, so starting early would copy a seed the merge has not reached yet
        // — and would delete the very tree that merge is diffing.
        self.merges.wait_for(&name);
        if let Err(error) =
            tokio::task::block_in_place(|| self.mux.start_in(&name, cmd, Some(INSTRUMENTATION_FD)))
        {
            let _ = writeln!(err, "marsh: {error}");
            return 1;
        }
        self.attach(&name, false)
    }

    /// Makes a job current, and attaches its command to the terminal if it has one.
    ///
    /// Bare `fg` takes the most recent job.
    pub fn fg(&mut self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(name) = self.resolve(name, "fg", None, err) else {
            return 1;
        };
        // A reader who brought this job to the foreground means to look at it, so it is no longer
        // one the series can reclaim on its own.
        self.mux.keep(&name);
        self.current.clone_from(&name);
        // A job whose launch is in flight has no command to hand the terminal to yet, and `fg` is
        // exactly the ask to wait for one: without this it would make the job current and report
        // "is current" for a command that starts a moment later.
        tokio::task::block_in_place(|| self.await_launch(&name));
        let Some(cmd) = self
            .mux
            .job(&name)
            .and_then(|job| job.running)
            .map(|running| running.cmd)
        else {
            gray(&format!("{} is current", shellmux::job_ref(&name)));
            return 0;
        };
        // The user typed `fg`, not the command, so the command line is worth repeating.
        gray(&format!("{} $ {cmd}", shellmux::job_ref(&name)));
        self.attach(&name, true)
    }

    /// Resumes a stopped command in the background: bare `bg` takes the most recent stopped one.
    pub fn bg(&self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(name) = self.resolve(name, "bg", Some(JobState::Stopped), err) else {
            return 1;
        };
        if self
            .mux
            .job(&name)
            .and_then(|job| job.running)
            .is_some_and(|running| running.state == JobState::Running)
        {
            let _ = writeln!(err, "bg: job {} already running", shellmux::job_ref(&name));
            return 1;
        }
        let Some((pid, cmd)) = self.mux.resume(&name) else {
            let _ = writeln!(err, "bg: {} is not running", shellmux::job_ref(&name));
            return 1;
        };
        signal_group(pid, libc::SIGCONT);
        gray(&format!("{} continued: {cmd}", shellmux::job_ref(&name)));
        0
    }

    /// Signals a job's process group, defaulting to `SIGTERM`.
    ///
    /// A job's whole process group, because a running command *is* one: the tracer, the shell it
    /// traces and every descendant have to receive the signal together, or the transaction's tracer
    /// would be left alive around a dead child.
    pub fn stop(&self, args: &[String], err: &mut dyn Write) -> u8 {
        let (signal, target) = match args.split_first() {
            Some((first, rest)) if first.starts_with('-') => {
                let Some(signal) = parse_signal(first) else {
                    let _ = writeln!(err, "stop: {first}: invalid signal specification");
                    return 1;
                };
                (signal, rest.first())
            }
            _ => (libc::SIGTERM, args.first()),
        };
        let Some(name) = target else {
            let _ = writeln!(err, "stop: usage: stop [-SIGNAL] JOB");
            return 1;
        };
        let Some(job) = self.mux.job(name) else {
            let _ = writeln!(err, "stop: no such job: {}", shellmux::job_ref(name));
            return 1;
        };
        if job.starting {
            let _ = writeln!(err, "stop: {} is still starting", shellmux::job_ref(name));
            return 1;
        }
        let Some(running) = job.running else {
            let _ = writeln!(
                err,
                "stop: {0} has no command running (close {0} to end the job)",
                shellmux::job_ref(name)
            );
            return 1;
        };
        signal_group(running.pid, signal);
        // A stopped job runs nothing until it is resumed, so a signal it is meant to act on would
        // sit undelivered. The table is told the job is running again, so a reap that observes it
        // does not report a second stop.
        if running.state == JobState::Stopped && signal != libc::SIGSTOP {
            signal_group(running.pid, libc::SIGCONT);
            let _ = self.mux.resume(name);
        }
        0
    }

    /// Ends a job: its row, its sandbox and its snapshot.
    ///
    /// A job with a command in flight is refused rather than killed, because closing deletes the
    /// tree that command is running in and its transaction has not been concluded yet — `stop` is
    /// the way to end the command, and this is the way to end the job.
    pub fn close(&mut self, name: Option<&str>, err: &mut dyn Write) -> u8 {
        let Some(name) = name else {
            let _ = writeln!(err, "close: usage: close JOB");
            return 1;
        };
        if name == FOREGROUND {
            let _ = writeln!(
                err,
                "close: {} is the console's own job",
                shellmux::job_ref(name)
            );
            return 1;
        }
        // Before the tree goes: a pending merge is still diffing this snapshot against the seed.
        self.merges.wait_for(name);
        let sandbox = match self.mux.close_job(name) {
            Ok(sandbox) => sandbox,
            Err(MuxError::JobBusy(job)) => {
                let _ = writeln!(err, "close: {job} is still running — stop {job} first");
                return 1;
            }
            Err(error) => {
                let _ = writeln!(err, "close: {error}");
                return 1;
            }
        };
        // The prompt names the current job, so it may not name one that no longer exists.
        if self.current == name {
            self.current = FOREGROUND.to_string();
        }
        self.mux.close_sandbox(&sandbox);
        gray(&format!("{} closed", shellmux::job_ref(name)));
        0
    }

    /// Signals process ids.
    ///
    /// Jobs are [`Self::stop`]'s, not this one's: `kill` is `kill(1)`. A pid is signalled as
    /// itself, exactly as `kill(1)` does.
    pub fn kill(&self, args: &[String], err: &mut dyn Write) -> u8 {
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
            let _ = writeln!(err, "kill: usage: kill [-SIGNAL] PID…");
            return 1;
        }

        let mut code = 0;
        for target in targets {
            if let Ok(pid) = target.parse::<libc::pid_t>() {
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
                let _ = writeln!(err, "kill: {target}: arguments must be process ids");
                code = 1;
            }
        }
        code
    }

    /// Resolves a `fg`/`bg` argument to the name of a job in the table, reporting failure to `err`.
    ///
    /// `default_state` restricts what a bare `fg`/`bg` picks: `bg` only makes sense for a stopped
    /// command, while `fg` is meaningful for any job.
    fn resolve(
        &self,
        name: Option<&str>,
        verb: &str,
        default_state: Option<JobState>,
        err: &mut dyn Write,
    ) -> Option<String> {
        if let Some(name) = name {
            if self.mux.job(name).is_none() {
                let _ = writeln!(err, "{verb}: no such job: {}", shellmux::job_ref(name));
                return None;
            }
            return Some(name.to_string());
        }
        let jobs = self.mux.jobs();
        let found = match default_state {
            Some(state) => jobs.iter().rfind(|job| {
                job.running
                    .as_ref()
                    .is_some_and(|running| running.state == state)
            }),
            None => jobs.last(),
        };
        if found.is_none() {
            match default_state {
                Some(JobState::Stopped) => {
                    let _ = writeln!(err, "{verb}: no stopped jobs");
                }
                _ => {
                    let _ = writeln!(err, "{verb}: no jobs");
                }
            }
        }
        found.map(|job| job.name.clone())
    }

    /// Writes the job table to `out`, one row per sandbox.
    pub fn print_jobs(&self, out: &mut dyn Write) {
        for job in self.mux.jobs() {
            let marker = if job.name == self.current { "*" } else { "" };
            let dir = dir_label(&job.sandbox);
            let (state, cmd) = job.running.as_ref().map_or_else(
                || {
                    // `starting` is a state of its own: the snapshot is being retaken and the
                    // tracer spawned, which is neither idle nor a command anyone can signal yet.
                    let state = if job.starting {
                        "starting"
                    } else if self.merges.is_merging(&job.name) {
                        "merging"
                    } else {
                        "idle"
                    };
                    (state, "")
                },
                |running| (running.state.label(), running.cmd.as_str()),
            );
            let _ = writeln!(
                out,
                "{}",
                format!(
                    "{}{marker} {dir} {} {state} {cmd}",
                    shellmux::job_ref(&job.name),
                    job.sandbox.uid
                )
                .trim_end()
            );
        }
    }

    /// Blocks until nothing is being launched into job `name`.
    ///
    /// `starting` is the mux's own answer to "a command is being launched into this job" — the flag
    /// `close_job` and `start_in` refuse on — so the console keeps no second record of it. `spawn`
    /// sets it before it returns, so there is no window in which a launch is pending and this says
    /// otherwise.
    ///
    /// Polled because the launch runs on a thread nothing here holds a handle to; 20 ms is invisible
    /// to a `fg` a reader just typed. A launch is a snapshot and a fork, never a user's command, so
    /// it always ends.
    fn await_launch(&self, name: &str) {
        while self.mux.job(name).is_some_and(|job| job.starting) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Gives job `name`'s command the terminal and waits for it to exit or stop.
    ///
    /// Returns the exit code the console reports for the line. A command that stops leaves its job
    /// in the table as a background one — that is what Ctrl-Z means.
    fn attach(&self, name: &str, resume: bool) -> u8 {
        let Some(pid) = self
            .mux
            .job(name)
            .and_then(|job| job.running)
            .map(|running| running.pid)
        else {
            return 0;
        };
        set_foreground(&self.tty, pid);
        if resume {
            signal_group(pid, libc::SIGCONT);
        }
        let observed = tokio::task::block_in_place(|| self.mux.wait_for_job(name));
        set_foreground(&self.tty, self.own_pgid);

        match observed {
            Some(Reaped::Ended {
                name,
                started,
                status,
            }) => {
                let code = exit_code(status);
                self.conclude(name, started, status);
                code
            }
            Some(Reaped::Stopped { name }) => stopped(&name),
            None => stopped(name),
        }
    }

    /// Hands a finished command to the merge thread.
    ///
    /// The conclusion itself — two full tree walks against the seed — happens there, not here: it
    /// needs neither the job table nor the terminal, and doing it under the console mutex is what
    /// made `jobs` wait for the previous command. The verdict is printed by that thread through
    /// [`gray`], which draws above the line being edited. The sandbox keeps its snapshots — they
    /// are the job's, not the command's.
    fn conclude(&self, name: String, started: Box<StartedCmd>, status: i32) {
        self.merges.submit(Merge {
            name,
            started,
            status,
        });
    }
}

/// Reports a stopped job and returns the exit code the console reports for its line.
fn stopped(name: &str) -> u8 {
    gray(&format!(
        "{0} stopped — fg {0} to resume",
        shellmux::job_ref(name)
    ));
    // The same code bash reports for a job stopped by SIGTSTP.
    148
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
