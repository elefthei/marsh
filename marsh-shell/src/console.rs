//! The terminal a job's bytes are forwarded to, and the instrumentation stream everything reports
//! on.
//!
//! This is the effectful half of the console: the tty, the byte forwarding between it and a job's
//! pseudoterminal, and the mux calls that open a job, start a command in one and close it. The job
//! table itself is the mux's ([`shellmux::ShellMux::spawn`]), because a job's name is a principal;
//! the pure half — the line grammar and the report text — is [`shellmux::repl`].
//!
//! A job is a *sandbox*, not a command: `sd NAME DIR` and `bg DIR` open one over a directory read
//! relative to the current job's, a trailing `&` opens one for the line it ends, typed lines run in
//! whichever one is current, and `fg`/`jobs`/`stop` operate on whatever command that sandbox is
//! running right now. A job's name is its principal, which is what makes the job table a picture of
//! the capability contention against the seed: `%foo` and `%bar` race exactly as two agents would.
//!
//! Every job runs on a pseudoterminal the mux owns, so a full-screen program (`less`, `vim`, an
//! agent TUI) sees a real terminal whatever this process is doing with its own. While a command is
//! in the foreground the console puts the real terminal in raw mode and forwards bytes both ways,
//! so Ctrl-C reaches the job through its own line discipline rather than through a key handler
//! here. Ctrl-Z does not: the terminal's suspend character is disabled for the whole session,
//! because a suspended transaction is one holding a snapshot nothing will conclude.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use brush_core::openfiles::OpenFile;
use brush_core::sys::terminal::{Config, SuspendKeyGuard};
use brush_interactive::LinePrinter;
use shellmux::{
    FrontendBinding, FrontendEvent, MarshFrontend, MuxError, OnFinish, Sandbox, ShellId, ShellMux,
    Spawned,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;

use crate::error::Error;
use shellmux::repl::{self, FOREGROUND};

/// The instrumentation stream: fd 3 of this process.
///
/// It is brush-core's third standard stream, not a number this crate invented, so a console
/// builtin's `stdinstr()` writer reaches the same gray line printer a job's `echo x >&3` does —
/// by way of the mux, which gives every job its own fd 3.
pub const INSTRUMENTATION_FD: RawFd = brush_core::openfiles::OpenFiles::STDINSTR_FD;

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
/// `SIGINT` is deliberately not ignored like the other terminal signals. While a command is in the
/// foreground the real terminal is raw, so Ctrl-C is a *byte* forwarded to the job's own
/// pseudoterminal and never reaches this process at all; the interrupts that do reach it arrive
/// while the console is doing its own work, and ignoring those is what left a session with no way
/// out. The second one restores the default disposition and re-raises, so the user is never
/// trapped, whatever the console is doing.
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
///
/// # Errors
///
/// Fails with [`Error::ConsoleInstalled`] when one is already installed.
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
#[must_use]
pub fn shared() -> Option<&'static Arc<Mutex<Console>>> {
    CONSOLE.get()
}

/// Ignores the terminal signals that must not stop this process, and claims `SIGINT`.
pub fn claim_terminal_signals() {
    shellmux::jobctl::ignore_terminal_job_signals();
    // SAFETY: `signal` installs a disposition for one signal number; `on_interrupt` is
    // async-signal-safe.
    let _ = unsafe {
        libc::signal(
            libc::SIGINT,
            on_interrupt as *const () as libc::sighandler_t,
        )
    };
}

/// Creates the instrumentation pipe and puts its write end on this process's fd 3.
///
/// Returns the read end. `dup2` clears close-on-exec, which is exactly what makes the stream
/// inheritable: the outer shell's own file table finds the pipe at fd 3 without being told about
/// it. A *job's* fd 3 is the mux's, not this one.
///
/// # Errors
///
/// Fails when the pipe cannot be created, relocated or installed.
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

    // SAFETY: `write_end` is an open descriptor this function owns and hands over.
    install_instrumentation_fd(unsafe { OwnedFd::from_raw_fd(write_end) })?;

    // SAFETY: `read_end` is an open descriptor this function owns and never touches again.
    Ok(unsafe { std::fs::File::from_raw_fd(read_end) })
}

/// Puts `fd` on this process's fd 3, so every child inherits it as its instrumentation stream.
///
/// # Errors
///
/// Fails when the descriptor cannot be made inheritable or placed on fd 3.
fn install_instrumentation_fd(fd: OwnedFd) -> Result<(), Error> {
    if fd.as_raw_fd() == INSTRUMENTATION_FD {
        // Already in place. Only the close-on-exec flag has to go, or no child would inherit it —
        // and `dup2(3, 3)` is defined to do nothing at all, flag included.
        // SAFETY: clearing the descriptor flags of a descriptor we own.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
            return Err(Error::ShareInstrumentation(std::io::Error::last_os_error()));
        }
        // The descriptor lives for the whole process: nothing closes fd 3 again.
        let _ = fd.into_raw_fd();
        return Ok(());
    }
    // SAFETY: both arguments are open descriptors we own; `dup2` closes fd 3 first if it was in
    // use (an inherited fd 3 is exactly what a session is meant to replace).
    if unsafe { libc::dup2(fd.as_raw_fd(), INSTRUMENTATION_FD) } < 0 {
        return Err(Error::InstallInstrumentation(
            std::io::Error::last_os_error(),
        ));
    }
    // The original is now redundant; dropping `fd` closes it.
    Ok(())
}

/// Puts `/dev/null` on this process's fd 3, for a session with no instrumentation printer.
///
/// `brush_core::openfiles::OpenFiles::new` seeds a command's standard instrumentation from
/// whatever *this* process holds on fd 3, so the number must be claimed before any other file is
/// opened whether or not anything reads it — otherwise the mux's write-ahead log lands there. The
/// full-screen interface has no outer shell and no line printer, so its fd 3 is a sink rather than
/// a pipe.
///
/// # Errors
///
/// Fails when `/dev/null` cannot be opened or placed on fd 3.
pub fn reserve_instrumentation_fd() -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let sink = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/null")
        .map_err(Error::CreateInstrumentation)?;
    install_instrumentation_fd(OwnedFd::from(sink))
}

/// Prints everything written to this process's own instrumentation pipe, one gray line at a time.
///
/// Line-buffered on purpose: two writers at once interleave by line rather than mid-word. The pipe
/// never reaches end of file while this process holds fd 3, so the thread simply lives as long as
/// the session.
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
    // anyway — a job's bytes may have put it in one — and written once, so a job's output and the
    // console's reports cannot tear into each other.
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(format!("\r\x1b[K{text}\r\n").as_bytes());
    let _ = stdout.flush();
}

/// The console's half of the mux's frontend contract: what a job's bytes, results and closures do
/// to this process's own terminal.
///
/// Separate from [`Console`] rather than implemented on it, because the console is the
/// process-global controller a job-control builtin reaches through [`shared`], and a controller
/// that had to exist before the mux did could only have unbound fields. This holds what the mux
/// hands out — the [`Spawned`] handles, the closures worth announcing, and the instrumentation
/// bytes that have not reached a newline yet — and nothing else.
pub struct ConsoleFrontend {
    /// Geometry, mux binding and live handles: the part of this frontend the mux contract
    /// dictates.
    binding: FrontendBinding,
    /// Sandboxes a reader explicitly asked to close, whose closure is therefore worth announcing.
    ///
    /// By sandbox uid, not by name: a name may be handed out again the moment the old row is
    /// claimed, and the second job's closure is not the first's.
    announce: HashSet<String>,
    /// Per-sandbox instrumentation bytes with no newline yet.
    ///
    /// A stream is chunked wherever the pipe filled up, so a gray line is only whole once its
    /// newline arrives; the remainder is flushed when the job closes.
    pending: HashMap<String, Vec<u8>>,
}

impl ConsoleFrontend {
    /// The mux this console drives, or `None` while it is unbound.
    #[must_use]
    pub fn mux(&self) -> Option<Arc<ShellMux>> {
        self.binding.mux()
    }

    /// The handle for `id`, if the console still holds one.
    fn handle(&self, id: &ShellId) -> Option<Spawned> {
        self.binding.handle(id)
    }

    /// Prints whatever complete gray lines `bytes` finishes, keeping the remainder.
    fn absorb_instrumentation(&mut self, uid: &str, bytes: &[u8]) {
        let pending = self.pending.entry(uid.to_string()).or_default();
        pending.extend_from_slice(bytes);
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=newline).collect();
            gray(String::from_utf8_lossy(&line[..newline]).trim_end_matches('\r'));
        }
    }

    /// Reports a closed job: its last unterminated instrumentation line and the closure a reader
    /// asked for.
    fn close(&mut self, shell: &Sandbox) {
        if let Some(pending) = self.pending.remove(&shell.uid)
            && !pending.is_empty()
        {
            gray(&String::from_utf8_lossy(&pending));
        }
        if self.announce.remove(&shell.uid) {
            gray(&format!("{} closed", shell.id.reference()));
        }
    }
}

impl MarshFrontend for ConsoleFrontend {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            binding: FrontendBinding::new(rows, cols),
            announce: HashSet::new(),
            pending: HashMap::new(),
        }
    }

    fn size(&self) -> (u16, u16) {
        self.binding.size()
    }

    fn bind(&mut self, mux: Weak<ShellMux>) {
        self.binding.bind(mux);
        if !self.binding.is_bound() {
            // The session is over: an unfinished line has nothing left to complete it.
            self.announce.clear();
            self.pending.clear();
        }
    }

    /// The rendering the console used to do from three per-job tasks, in one place.
    ///
    /// [`FrontendEvent::Changed`] needs no display cache here: the prompt and `jobs` query the mux
    /// when they are asked, so there is nothing to invalidate.
    fn update(&mut self, event: FrontendEvent<'_>) {
        self.binding.observe(event);
        match event {
            FrontendEvent::Opened(_) => {}
            FrontendEvent::Terminal { bytes, .. } => {
                // No decoding and no line buffering: escape sequences, non-UTF-8 output and a final
                // line with no newline all reach the reader exactly as the command wrote them.
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(bytes);
                let _ = stdout.flush();
            }
            FrontendEvent::Instrumentation { shell, bytes } => {
                self.absorb_instrumentation(&shell.uid, bytes);
            }
            FrontendEvent::Finished { shell, outcome, .. } => {
                for line in repl::report_lines(&shell.id, outcome) {
                    gray(&line);
                }
            }
            FrontendEvent::Closed(shell) => self.close(shell),
            FrontendEvent::Resized { .. } => {}
            FrontendEvent::IoError { shell, error } => {
                gray(&format!("marsh: {}: {error}", shell.id.reference()));
            }
            FrontendEvent::Changed => {}
        }
    }
}

/// The console state the asynchronous operations act on.
///
/// Held behind an `Arc` so a job-control builtin can take the console's own lock, clone this, drop
/// the lock, and then await: no console lock is ever held across a mux call.
pub struct ConsoleShared {
    /// The multiplexer every line is a transaction against, and the job table it owns.
    mux: Arc<ShellMux>,
    /// The real terminal, for raw-mode forwarding while a command is in the foreground.
    tty: OpenFile,
    /// The frontend the mux delivers to, and the owner of this console's per-job handles and
    /// pending close announcements.
    frontend: Arc<Mutex<ConsoleFrontend>>,
}

impl ConsoleShared {
    /// The frontend, recovering a poisoned lock: a callback that panicked left the console's own
    /// state intact, and refusing to serve it afterwards would strand every open job.
    fn frontend(&self) -> std::sync::MutexGuard<'_, ConsoleFrontend> {
        self.frontend.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The handle for `id`, if the console still holds one.
    fn handle(&self, id: &ShellId) -> Option<Spawned> {
        self.frontend().handle(id)
    }

    /// Records that `uid`'s closure was asked for, so it is announced exactly once.
    fn mark_announcement(&self, uid: &str) {
        self.frontend().announce.insert(uid.to_string());
    }

    /// Withdraws an announcement whose request was refused.
    fn clear_announcement(&self, uid: &str) {
        self.frontend().announce.remove(uid);
    }

    /// Opens a job over `dir` and either makes it current or starts `cmd` in it.
    ///
    /// A job opened without a command becomes current, because that is what `sd` is for. One opened
    /// with a command does not: `&` runs a line *beside* what is being worked on, so the prompt,
    /// completion and the next typed line all stay where they were. The command itself is launched
    /// by a task the mux owns, so the prompt is never held for a snapshot and a tracer spawn.
    ///
    /// # Errors
    ///
    /// Returns the message to print when the name is taken or the directory is not in the seed.
    pub async fn open_job(
        self: &Arc<Self>,
        dir: &str,
        id: Option<ShellId>,
        cmd: Option<String>,
    ) -> Result<(), String> {
        let base = self
            .mux
            .current_job()
            .map_or_else(String::new, |job| job.sandbox.dir);
        let dir = repl::job_dir(&base, dir);
        let spawned = self
            .mux
            .spawn(&dir, id, cmd.as_deref())
            .await
            .map_err(|error| format!("marsh: {error}"))?;
        gray(&format!(
            "{} -> {}",
            spawned.id.reference(),
            shellmux::jobctl::dir_label(&spawned.sandbox)
        ));
        let id = spawned.id;
        match cmd {
            Some(cmd) => gray(&format!("{} $ {cmd}", id.reference())),
            None => {
                let _ = self.mux.switch(&id).await;
            }
        }
        Ok(())
    }

    /// Runs `cmd` in the current job, forwarding the real terminal to it.
    ///
    /// One command at a time per job: a job already running one is reported busy rather than
    /// queued, because the second command would want a snapshot the first has not merged yet.
    ///
    /// # Errors
    ///
    /// Returns the message to print when the job is busy or the command could not be started.
    pub async fn foreground(self: &Arc<Self>, cmd: &str) -> Result<u8, String> {
        let Some(current) = self.mux.current_job() else {
            return Err("marsh: no current job".to_string());
        };
        if current.running.is_some() || current.starting {
            return Err(format!(
                "marsh: {} is busy — wait for it, or append & to run in a new job",
                current.id.reference()
            ));
        }
        let (done, finished) = finish_channel();
        self.mux
            .start_in(&current.id, cmd, Some(done))
            .await
            .map_err(|error| format!("marsh: {error}"))?;
        Ok(self.attach(&current.id, finished).await)
    }

    /// Makes a job current, and forwards the terminal to its command if it has one.
    ///
    /// Bare `fg` takes the most recent job. A job a reader has already stopped is refused: an
    /// explicit stop is a decision, not a default this may quietly cancel by selecting the job.
    ///
    /// # Errors
    ///
    /// Returns the message to print when no job answers, or the job is closing.
    pub async fn fg(self: &Arc<Self>, id: Option<ShellId>) -> Result<u8, String> {
        let id = self.resolve(id)?;
        // `switch` keeps the job, waits for a launch already in flight, and selects it — which is
        // exactly what `fg` means.
        let view = self
            .mux
            .switch(&id)
            .await
            .map_err(|error| format!("fg: {error}"))?;
        let Some(running) = view.running else {
            gray(&format!("{} is current", id.reference()));
            return Ok(0);
        };
        // The user typed `fg`, not the command, so the command line is worth repeating.
        gray(&format!("{} $ {}", id.reference(), running.cmd));
        let (done, finished) = finish_channel();
        if !self.mux.on_finish(&id, done) {
            // Its command ended between the table read above and this registration: the answer an
            // idle job already gets.
            return Ok(0);
        }
        Ok(self.attach(&id, finished).await)
    }

    /// Closes the job named `id`, gracefully or by force.
    ///
    /// Graceful is the default and it waits for nobody: the job takes no further command, finishes
    /// the one it has, merges it, and then goes. Force kills that command's whole process group and
    /// the job leaves the table at once; its storage is reclaimed when the killed transaction's
    /// lifecycle is over, never before.
    ///
    /// `main` is refused: it is the job this console runs its own lines in, and `exit` is how a
    /// session ends.
    ///
    /// # Errors
    ///
    /// Returns the message to print when the job is `main`, or when nothing answers to `id`.
    pub async fn stop(self: &Arc<Self>, id: &ShellId, force: bool) -> Result<(), String> {
        if id.as_str() == FOREGROUND {
            return Err(format!("stop: {} is the console's own job", id.reference()));
        }
        let selected = self.mux.current_job().is_some_and(|job| &job.id == id);
        // The sandbox, not the name: a name outlives the job that held it, and the announcement is
        // owed by this one. Marked before the request, so a job that concludes the instant it is
        // accepted still finds it owed rather than racing past it.
        let uid = self.mux.job(id).map(|view| view.sandbox.uid);
        if let Some(uid) = &uid {
            self.mark_announcement(uid);
        }
        if let Err(error) = self.mux.stop(id, force).await {
            if let Some(uid) = &uid {
                self.clear_announcement(uid);
            }
            return Err(format!("stop: {error}"));
        }
        // The prompt names the current job, and this one is either gone already or on its way out.
        if selected {
            let _ = self.mux.switch(&ShellId::from(FOREGROUND)).await;
        }
        // Force has already taken the job out of the table, so there is nothing to promise: the
        // closure is announced when the job's own stream ends, which is once its storage is gone.
        if !force && self.mux.job(id).is_some() {
            gray(&format!("{} will close when idle", id.reference()));
        }
        Ok(())
    }

    /// Forwards the real terminal to job `id`'s command until it finishes.
    ///
    /// Raw mode on both sides of the handoff: the job's own pseudoterminal has the line discipline
    /// now, so every keystroke — Ctrl-C included — has to reach it as a byte. The terminal is
    /// restored the moment the wait ends, and the suspend character is disabled again because a
    /// command may have run `stty sane`.
    async fn attach(self: &Arc<Self>, id: &ShellId, done: oneshot::Receiver<i32>) -> u8 {
        let Some(job) = self.handle(id) else {
            return 0;
        };
        let saved = match self.enter_raw_mode() {
            Ok(saved) => saved,
            Err(error) => {
                gray(&format!("marsh: {error}"));
                return 1;
            }
        };
        let pump = self.pump_input(job.clone());
        let observed = done.await;
        if let Some(pump) = pump {
            pump.abort();
        }
        let restored = self.leave_raw_mode(&saved);

        let code = match observed {
            Ok(exit_code) => u8::try_from(exit_code).unwrap_or(1),
            // The mux dropped the callback with the job: the same answer this function's own
            // missing-handle guard gives.
            Err(_) => 0,
        };
        if let Err(error) = restored {
            gray(&format!("marsh: {}", Error::SuspendKey(error)));
            return 1;
        }
        code
    }

    /// Puts the real terminal in raw mode, returning what it was.
    fn enter_raw_mode(&self) -> Result<Config, Error> {
        let saved = Config::from_term(&self.tty).map_err(Error::SuspendKey)?;
        let mut raw = saved.clone();
        raw.update(
            &brush_core::terminal::Settings::builder()
                .echo_input(false)
                .line_input(false)
                .interrupt_signals(false)
                .build(),
        );
        raw.apply_to_term(&self.tty).map_err(Error::SuspendKey)?;
        Ok(saved)
    }

    /// Restores `saved` and reasserts the disabled suspend character.
    fn leave_raw_mode(&self, saved: &Config) -> Result<(), brush_core::Error> {
        saved.apply_to_term(&self.tty)?;
        SuspendKeyGuard::disable(&self.tty)
    }

    /// Starts the task forwarding real keystrokes into `job`'s terminal.
    ///
    /// A private non-blocking duplicate of the terminal, so aborting the task between readiness
    /// polls cannot leave the shared descriptor in a state the line editor did not ask for. A byte
    /// is only ever consumed once the read has already happened, which is what makes the abort
    /// safe.
    fn pump_input(&self, job: Spawned) -> Option<tokio::task::JoinHandle<()>> {
        let terminal = self.tty.try_borrow_as_fd().ok()?;
        // SAFETY: `fcntl` receives an open descriptor and scalar arguments, and returns a new
        // descriptor this process owns.
        let copy = unsafe {
            libc::fcntl(
                terminal.as_raw_fd(),
                libc::F_DUPFD_CLOEXEC,
                INSTRUMENTATION_FD + 1,
            )
        };
        if copy < 0 {
            return None;
        }
        // SAFETY: `copy` is a fresh descriptor nothing else refers to.
        let copy = unsafe { OwnedFd::from_raw_fd(copy) };
        // SAFETY: `fcntl` receives an open descriptor and a scalar flag word.
        if unsafe { libc::fcntl(copy.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return None;
        }
        let input = AsyncFd::new(copy).ok()?;
        let mux = Arc::clone(&self.mux);
        Some(tokio::spawn(async move {
            forward_input(&mux, &job, &input).await;
        }))
    }

    /// Resolves an `fg` argument to a job in the table.
    ///
    /// Bare `fg` takes the most recent job: every job is one a reader may look at.
    fn resolve(&self, id: Option<ShellId>) -> Result<ShellId, String> {
        if let Some(id) = id {
            if self.mux.job(&id).is_none() {
                return Err(format!("fg: no such job: {}", id.reference()));
            }
            return Ok(id);
        }
        self.mux
            .jobs()
            .last()
            .map(|job| job.id.clone())
            .ok_or_else(|| "fg: no jobs".to_string())
    }

    /// Cancels queued conclusions, terminates outstanding commands and joins the mux's own tasks.
    pub async fn shutdown(&self) {
        if let Err(error) = self.mux.shutdown().await {
            eprintln!("marsh: {error}");
        }
    }
}

/// The console: the terminal, and the front-end's view of the mux's job table.
pub struct Console {
    /// Everything the asynchronous operations need, shared so no lock is held across a mux call.
    shared: Arc<ConsoleShared>,
    /// Whether a preceding `exit` already warned about live jobs.
    exit_armed: bool,
}

impl Console {
    /// Creates the console over the mux `frontend` is bound to, opening the default job in the
    /// same breath.
    ///
    /// `main` is rooted where marsh was started, so a bare `ls` lists that directory's contents and
    /// a session is usable before anything is typed. The `main` job's handle is not taken here:
    /// [`FrontendEvent::Opened`] installs it in `frontend` while `spawn` is still running.
    ///
    /// # Errors
    ///
    /// Fails when `frontend` is not bound to a mux, or when the `main` job's terminal or shell
    /// could not be created.
    pub async fn open(
        frontend: Arc<Mutex<ConsoleFrontend>>,
        tty: OpenFile,
    ) -> Result<Self, MuxError> {
        let mux = frontend
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mux()
            .ok_or_else(|| MuxError::Exec("frontend is not bound to a mux".to_string()))?;
        // The default job is rooted at the current directory *inside* the seed, which is the whole
        // point of deriving the seed from where marsh was started. Canonicalized because the seed
        // is; a directory that cannot be read falls through to the seed root.
        let cwd = std::env::current_dir()
            .and_then(|dir| dir.canonicalize())
            .unwrap_or_default();
        let dir = mux.persistence().default_dir(&cwd);
        let shared = Arc::new(ConsoleShared {
            mux: Arc::clone(&mux),
            tty,
            frontend,
        });
        mux.spawn(&dir, Some(ShellId::from(FOREGROUND)), None)
            .await?;
        mux.switch(&ShellId::from(FOREGROUND)).await?;
        Ok(Self {
            shared,
            exit_armed: false,
        })
    }

    /// The shared half, for an operation that must await without holding the console's lock.
    #[must_use]
    pub fn shared(&self) -> Arc<ConsoleShared> {
        Arc::clone(&self.shared)
    }

    /// The persistent storage every transaction is against.
    #[must_use]
    pub fn persistence(&self) -> &shellmux::PersistenceLayer {
        self.shared.mux.persistence()
    }

    /// The prompt for the current job: its name, then the seed directory it is rooted at.
    ///
    /// The name rather than the snapshot's uid: a job's name is unique among the open ones by
    /// construction, so it answers the only question a multi-job session makes ambiguous — where
    /// does the next line I type run — and it answers it in the same word `jobs` prints and `fg`
    /// takes.
    ///
    /// Backslashes are doubled because the outer shell still parses prompt escapes (`\w`, `\$`) —
    /// in the name as well as the directory, since `CMD &"a name"` admits one. Nothing else needs
    /// quoting: that shell is built with `promptvars` off, so the composed prompt is never expanded
    /// as a word, and a directory named `$(rm -rf ~)` stays text.
    #[must_use]
    pub fn prompt(&self) -> String {
        let Some(job) = self.shared.mux.current_job() else {
            return format!("{FOREGROUND}$ ");
        };
        format!(
            "{}@{}$ ",
            job.id.replace('\\', "\\\\"),
            shellmux::jobctl::dir_label(&job.sandbox).replace('\\', "\\\\")
        )
    }

    /// The directory the current job's commands run in: its work snapshot, plus the sandbox's
    /// seed-relative directory.
    ///
    /// This is what the outer shell's completion resolves paths against, so a Tab at the prompt
    /// offers what the next line would actually see.
    #[must_use]
    pub fn current_dir(&self) -> PathBuf {
        let persistence = self.shared.mux.persistence();
        let Some(job) = self.shared.mux.current_job() else {
            return persistence.seed.clone();
        };
        let work = persistence.work(&job.sandbox.uid).join(&job.sandbox.dir);
        if work.is_dir() {
            return work;
        }
        // No command has needed a snapshot in this job yet. The seed is what the next one will
        // copy, so it is also what completion should be offering.
        persistence.seed.join(&job.sandbox.dir)
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
            .shared
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

    /// Writes the job table to `out`, one row per sandbox.
    ///
    /// The rows themselves are [`shellmux::jobctl::print_jobs`]: what a job table says is the same
    /// in every frontend.
    pub fn print_jobs(&self, out: &mut dyn Write) {
        shellmux::jobctl::print_jobs(&self.shared.mux, out);
    }
}

/// Forwards real keystrokes into a job's terminal until the terminal or the job is gone.
async fn forward_input(mux: &ShellMux, job: &Spawned, input: &AsyncFd<OwnedFd>) {
    let mut buffer = [0u8; 1024];
    loop {
        let Ok(mut guard) = input.readable().await else {
            return;
        };
        let attempt = guard.try_io(|inner| {
            // SAFETY: `read` receives an open descriptor, a valid writable pointer and the length
            // of the slice behind it.
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
        let count = match attempt {
            Ok(Ok(0)) => return,
            Ok(Ok(count)) => count,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(_)) => return,
            Err(_would_block) => continue,
        };
        if mux.write_input(job, &buffer[..count]).await.is_err() {
            return;
        }
    }
}

/// A callback that reports a command's status to the returned receiver.
///
/// The receiver resolves to `Err` when the mux dropped the callback with the job: the row and its
/// terminal are gone, so there is no status left to report.
fn finish_channel() -> (OnFinish, oneshot::Receiver<i32>) {
    let (sender, receiver) = oneshot::channel();
    (
        Box::new(move |exit_code| {
            let _ = sender.send(exit_code);
        }),
        receiver,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
