//! The application: tabs, workers, input routing and rendering.
//!
//! One job is one tab, plus the reserved `caps` tab. Everything the session *does* to the mux —
//! opening, launching, switching, closing — goes through a single FIFO lifecycle worker, so two
//! UI events can never race for one job name; everything the session *learns* arrives through
//! [`crate::TuiFrontend`]. Rendering reads cached views and borrowed emulator screens and never
//! calls the mux.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crossterm::event::{
    Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use futures_util::StreamExt as _;
use ratatui::DefaultTerminal;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui_textarea::TextArea;
use shellmux::{
    Event, JobView, MarshFrontend as _, MuxError, ShellId, ShellMux, Spawned, jobctl, repl,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tui_term::widget::PseudoTerminal;

use crate::caps::CapsView;
use crate::error::Error;
use crate::frontend::TuiFrontend;
use crate::terminal::{encode_key, encode_mouse, escape_controls};

/// How many bytes of unwritten input one job may have queued.
const INPUT_QUEUE_LIMIT: usize = 1024 * 1024;

/// The shortest interval between two redraws.
const FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_millis(16);

/// The gray diagnostics and instrumentation are rendered in.
const GRAY: Color = Color::Rgb(0x9e, 0x9e, 0x9e);

/// Which tab the user is looking at.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Selection {
    /// The reserved capability browser.
    Caps,
    /// One job, by sandbox uid so a reused name cannot move the selection.
    Job(String),
}

/// One lifecycle operation, performed in the order it was enqueued.
enum Lifecycle {
    /// Open a job, and select it when asked.
    Spawn {
        /// Seed-relative directory.
        dir: String,
        /// The name, or `None` for the next number.
        id: Option<ShellId>,
        /// A command to start once the job exists.
        cmd: Option<String>,
        /// Whether the new job becomes the selected tab.
        select: bool,
    },
    /// Start a command in an existing job.
    Start {
        /// The job's name.
        id: ShellId,
        /// The sandbox this command was aimed at.
        uid: String,
        /// The command line.
        cmd: String,
    },
    /// Make a job current.
    Switch {
        /// The job's name.
        id: ShellId,
        /// The sandbox the request was aimed at.
        uid: String,
        /// Which focus request this is, so an older completion cannot override a newer one.
        generation: u64,
    },
    /// Close a job.
    Stop {
        /// The job's name.
        id: ShellId,
        /// Whether its command is killed now.
        force: bool,
    },
    /// Stop accepting work, force-close every job and shut the mux down.
    Shutdown,
}

/// What a worker reports back to the event loop.
enum Message {
    /// A job was opened, or could not be.
    Opened {
        /// Whether the request asked for this job to be selected.
        select: bool,
        /// The outcome.
        result: Result<Spawned, MuxError>,
    },
    /// A command launch settled.
    Started {
        /// The sandbox it was aimed at.
        uid: String,
        /// The job's name, for diagnostics.
        id: ShellId,
        /// The outcome.
        result: Result<(), MuxError>,
    },
    /// A switch settled.
    Switched {
        /// Which focus request it answers.
        generation: u64,
        /// The outcome.
        result: Result<(), MuxError>,
    },
    /// A close settled.
    Stopped {
        /// The job's name.
        id: ShellId,
        /// The outcome.
        result: Result<(), MuxError>,
    },
    /// A resize settled.
    Resized(Result<(), MuxError>),
    /// A capability read settled.
    Caps {
        /// The binding generation the read was started under.
        epoch: u64,
        /// The projection, or the reason the query task failed.
        result: Result<Vec<Event>, String>,
    },
}

/// One job's serialized input writer.
struct InputWriter {
    /// Queued packets, in the order they were produced.
    sender: mpsc::UnboundedSender<Vec<u8>>,
    /// Bytes enqueued and not yet written.
    queued: Arc<AtomicUsize>,
    /// The task draining the queue.
    task: JoinHandle<()>,
}

impl InputWriter {
    /// Starts a writer for `job`.
    fn start(mux: Arc<ShellMux>, job: Spawned) -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel::<Vec<u8>>();
        let queued = Arc::new(AtomicUsize::new(0));
        let accounted = Arc::clone(&queued);
        let task = tokio::spawn(async move {
            while let Some(bytes) = receiver.recv().await {
                accounted.fetch_sub(bytes.len(), Ordering::SeqCst);
                if mux.write_input(&job, &bytes).await.is_err() {
                    return;
                }
            }
        });
        Self {
            sender,
            queued,
            task,
        }
    }

    /// Enqueues one whole packet, or reports that the queue is full.
    ///
    /// A packet is never split: half a paste is text the user never typed.
    fn send(&self, bytes: Vec<u8>) -> bool {
        if self.queued.load(Ordering::SeqCst) + bytes.len() > INPUT_QUEUE_LIMIT {
            return false;
        }
        self.queued.fetch_add(bytes.len(), Ordering::SeqCst);
        self.sender.send(bytes).is_ok()
    }
}

/// The state of the capability browser's asynchronous reads.
#[derive(Default)]
struct CapsQuery {
    /// Whether a read is in flight.
    running: bool,
    /// Whether state changed while a read was in flight.
    stale: bool,
    /// Whether a result has ever been accepted.
    loaded: bool,
    /// The reason the last read failed.
    error: Option<String>,
}

/// The whole session.
pub struct App {
    /// The frontend the mux delivers to.
    frontend: Arc<Mutex<TuiFrontend>>,
    /// The mux this session drives.
    mux: Arc<ShellMux>,
    /// The real terminal, taken out of the struct for the length of one draw.
    terminal: Option<DefaultTerminal>,
    /// The job table as last observed.
    jobs: Vec<JobView>,
    /// The selected tab.
    selection: Selection,
    /// One command draft per job.
    drafts: HashMap<String, TextArea<'static>>,
    /// One input writer per job.
    writers: HashMap<String, InputWriter>,
    /// Jobs whose command submission has not yet reached the mux.
    pending: HashSet<String>,
    /// Child input held while a job is still starting its command.
    queued_input: HashMap<String, Vec<u8>>,
    /// The capability browser.
    caps: CapsView,
    /// Its query state.
    caps_query: CapsQuery,
    /// Whether the diagnostic overlay is open.
    overlay: bool,
    /// How far the overlay is scrolled.
    overlay_scroll: usize,
    /// Whether `Ctrl-]` was pressed and is waiting for a suffix.
    prefix: bool,
    /// What the footer shows until the session has produced a diagnostic.
    status: String,
    /// Whether an exit request has already warned about running jobs.
    exit_armed: bool,
    /// Whether teardown has been requested.
    exiting: bool,
    /// Focus requests issued so far.
    focus_generation: u64,
    /// Where each drawn tab starts and how wide it is, for click routing.
    tab_hits: Vec<(u16, u16, Selection)>,
    /// The lifecycle worker's queue.
    lifecycle: mpsc::UnboundedSender<Lifecycle>,
    /// The lifecycle worker itself.
    lifecycle_task: JoinHandle<()>,
    /// Newest pending geometry for the resize worker.
    resize: tokio::sync::watch::Sender<(u16, u16)>,
    /// The resize worker.
    resize_task: JoinHandle<()>,
    /// Worker results.
    messages: mpsc::UnboundedReceiver<Message>,
    /// The sender workers report through.
    reporter: mpsc::UnboundedSender<Message>,
}

impl App {
    /// Builds the session over an already-open mux.
    pub fn new(
        frontend: Arc<Mutex<TuiFrontend>>,
        mux: Arc<ShellMux>,
        terminal: DefaultTerminal,
    ) -> Self {
        let (reporter, messages) = mpsc::unbounded_channel();
        let (lifecycle, lifecycle_rx) = mpsc::unbounded_channel();
        let lifecycle_task = tokio::spawn(lifecycle_worker(
            Arc::clone(&mux),
            lifecycle_rx,
            reporter.clone(),
        ));
        let size = lock(&frontend).geometry();
        let (resize, resize_rx) = tokio::sync::watch::channel(size);
        let resize_task =
            tokio::spawn(resize_worker(Arc::clone(&mux), resize_rx, reporter.clone()));
        Self {
            frontend,
            mux,
            terminal: Some(terminal),
            jobs: Vec::new(),
            selection: Selection::Caps,
            drafts: HashMap::new(),
            writers: HashMap::new(),
            pending: HashSet::new(),
            queued_input: HashMap::new(),
            caps: CapsView::new(),
            caps_query: CapsQuery::default(),
            overlay: false,
            overlay_scroll: 0,
            prefix: false,
            status: String::new(),
            exit_armed: false,
            exiting: false,
            focus_generation: 0,
            tab_hits: Vec::new(),
            lifecycle,
            lifecycle_task,
            resize,
            resize_task,
            messages,
            reporter,
        }
    }

    /// Runs the session until it is asked to end, then restores the mux.
    pub async fn run(mut self) -> Result<(), Error> {
        let (seed, root) = {
            let persistence = self.mux.persistence();
            (
                persistence.seed.display().to_string(),
                persistence.root.display().to_string(),
            )
        };
        self.status = format!("seed {seed} · state {root}");

        // The console's own first job, opened and made current the same way.
        let cwd = std::env::current_dir()
            .and_then(|dir| dir.canonicalize())
            .unwrap_or_default();
        let dir = self.mux.persistence().default_dir(&cwd);
        self.enqueue(Lifecycle::Spawn {
            dir,
            id: Some(ShellId::from(repl::FOREGROUND)),
            cmd: None,
            select: true,
        });

        let notify = lock(&self.frontend).notify();
        let mut events = crossterm::event::EventStream::new();
        let mut interrupt = signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate = signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = signal(tokio::signal::unix::SignalKind::hangup())?;

        let mut result = Ok(());
        let mut redraw = true;
        while !self.exiting {
            if redraw {
                self.refresh();
                if let Err(error) = self.draw() {
                    result = Err(error);
                    break;
                }
                redraw = false;
            }
            tokio::select! {
                event = events.next() => match event {
                    Some(Ok(event)) => { self.on_terminal_event(event); redraw = true; }
                    Some(Err(error)) => { result = Err(Error::Input(error)); break; }
                    None => break,
                },
                () = notify.notified() => {
                    // Coalesced: a burst of terminal chunks is one frame, not one frame each.
                    tokio::time::sleep(FRAME_INTERVAL).await;
                    redraw = true;
                }
                message = self.messages.recv() => {
                    let Some(message) = message else { break };
                    self.on_message(message);
                    redraw = true;
                }
                _ = interrupt.recv() => self.exiting = true,
                _ = terminate.recv() => self.exiting = true,
                _ = hangup.recv() => self.exiting = true,
            }
        }

        self.teardown().await;
        result
    }

    /// Stops accepting work, settles the workers and shuts the mux down.
    async fn teardown(mut self) {
        // Queued but not-yet-started requests are discarded by the worker itself; the current one
        // may be an uncancellable launch holding job descriptors, so it is awaited rather than
        // aborted.
        let _ = self.lifecycle.send(Lifecycle::Shutdown);
        self.writers.clear();
        let _ = self.lifecycle_task.await;
        self.resize_task.abort();
        let _ = self.resize_task.await;
        lock(&self.frontend).bind(std::sync::Weak::new());
    }

    /// Enqueues one lifecycle operation.
    fn enqueue(&self, request: Lifecycle) {
        let _ = self.lifecycle.send(request);
    }

    /// Rereads the job table and keeps the selection on something that exists.
    fn refresh(&mut self) {
        let (_, caps_dirty) = lock(&self.frontend).take_dirty();
        self.jobs = self.mux.jobs();
        self.sync_writers();
        self.drain_replies();

        let live: HashSet<String> = self
            .jobs
            .iter()
            .map(|job| job.sandbox.uid.clone())
            .collect();
        self.drafts.retain(|uid, _| live.contains(uid));
        self.queued_input.retain(|uid, _| live.contains(uid));
        self.pending.retain(|uid| live.contains(uid));
        if let Selection::Job(uid) = &self.selection
            && !live.contains(uid)
        {
            self.select_fallback();
        }

        if caps_dirty {
            self.caps_query.stale = true;
        }
        if matches!(self.selection, Selection::Caps) && self.caps_query.stale {
            self.start_caps_query();
        }
    }

    /// Selects `main`, then the first remaining job, then `caps`.
    fn select_fallback(&mut self) {
        let main = ShellId::from(repl::FOREGROUND);
        let next = self
            .jobs
            .iter()
            .find(|job| job.id == main)
            .or_else(|| self.jobs.first())
            .map(|job| job.sandbox.uid.clone());
        self.selection = next.map_or(Selection::Caps, Selection::Job);
        self.overlay = false;
    }

    /// Starts a writer for every job that has a handle and none yet, and drops the rest.
    fn sync_writers(&mut self) {
        let live: HashSet<String> = self
            .jobs
            .iter()
            .map(|job| job.sandbox.uid.clone())
            .collect();
        self.writers.retain(|uid, writer| {
            let keep = live.contains(uid);
            if !keep {
                writer.task.abort();
            }
            keep
        });
        for job in &self.jobs {
            if self.writers.contains_key(&job.sandbox.uid) {
                continue;
            }
            let Some(handle) = lock(&self.frontend).handle(&job.id) else {
                // A reservation with no resources yet: it is opening, and accepts no input.
                continue;
            };
            if handle.sandbox.uid != job.sandbox.uid {
                continue;
            }
            self.writers.insert(
                job.sandbox.uid.clone(),
                InputWriter::start(Arc::clone(&self.mux), handle),
            );
        }
    }

    /// Hands every queued emulator reply to its own job's writer.
    fn drain_replies(&self) {
        let replies = lock(&self.frontend).drain_replies();
        for (uid, bytes) in replies {
            if let Some(writer) = self.writers.get(&uid) {
                let _ = writer.send(bytes);
            }
        }
    }

    /// Asks for the authority's active capabilities, at most one read at a time.
    fn start_caps_query(&mut self) {
        if self.caps_query.running {
            return;
        }
        self.caps_query.running = true;
        self.caps_query.stale = false;
        let epoch = lock(&self.frontend).epoch();
        let mux = Arc::clone(&self.mux);
        let reporter = self.reporter.clone();
        drop(tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || mux.active_capabilities())
                .await
                .map_err(|error| error.to_string());
            let _ = reporter.send(Message::Caps { epoch, result });
        }));
    }

    /// Applies one worker result.
    fn on_message(&mut self, message: Message) {
        match message {
            Message::Opened { select, result } => match result {
                Ok(spawned) => {
                    self.jobs = self.mux.jobs();
                    if select {
                        self.selection = Selection::Job(spawned.sandbox.uid.clone());
                        self.overlay = false;
                    }
                    let line = format!(
                        "{} -> {}",
                        spawned.id.reference(),
                        jobctl::dir_label(&spawned.sandbox)
                    );
                    self.report(&line);
                }
                Err(error) => self.report(&format!("marsh: {error}")),
            },
            Message::Started { uid, id, result } => {
                self.pending.remove(&uid);
                match result {
                    Ok(()) => {
                        if let Some(bytes) = self.queued_input.remove(&uid)
                            && let Some(writer) = self.writers.get(&uid)
                            && !writer.send(bytes)
                        {
                            self.report("Terminal input queue full; input not sent");
                        }
                    }
                    Err(error) => {
                        self.queued_input.remove(&uid);
                        self.report(&format!("{}: {error}", id.reference()));
                    }
                }
            }
            Message::Switched { generation, result } => {
                if let Err(error) = result {
                    self.report(&format!("marsh: {error}"));
                    if generation == self.focus_generation
                        && matches!(self.selection, Selection::Job(_))
                    {
                        self.select_fallback();
                    }
                }
            }
            Message::Stopped { id, result } => {
                if let Err(error) = result {
                    self.report(&format!("{}: {error}", id.reference()));
                }
            }
            Message::Resized(result) => {
                if let Err(error) = result {
                    self.report(&format!("marsh: {error}"));
                }
            }
            Message::Caps { epoch, result } => {
                self.caps_query.running = false;
                let frontend = lock(&self.frontend);
                let current = frontend.epoch();
                let bound = frontend.mux().is_some();
                drop(frontend);
                if !accepts_caps(epoch, current, bound) {
                    // A replaced or detached session: this answer is about someone else's jobs.
                    return;
                }
                match result {
                    Ok(events) => {
                        self.caps.refresh(&events);
                        self.caps_query.loaded = true;
                        self.caps_query.error = None;
                    }
                    Err(error) => self.caps_query.error = Some(error),
                }
                if self.caps_query.stale && matches!(self.selection, Selection::Caps) {
                    self.start_caps_query();
                }
            }
        }
    }

    /// Records one line as the footer's message and in the selected job's diagnostics.
    fn report(&self, line: &str) {
        let line = escape_controls(line);
        match &self.selection {
            Selection::Job(uid) => {
                let uid = uid.clone();
                lock(&self.frontend).record(&uid, line);
            }
            Selection::Caps => lock(&self.frontend).note(line),
        }
    }

    /// Routes one terminal event.
    fn on_terminal_event(&mut self, event: TermEvent) {
        match event {
            TermEvent::Key(key) => self.on_key(key),
            TermEvent::Paste(text) => self.on_paste(text),
            TermEvent::Mouse(mouse) => self.on_mouse(mouse),
            TermEvent::Resize(cols, rows) => {
                let body = rows.saturating_sub(3).max(1);
                let _ = self.resize.send((body, cols.max(1)));
            }
            TermEvent::FocusGained | TermEvent::FocusLost => {}
        }
    }
}

/// A key that acts on the session itself, whatever tab is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hotkey {
    /// Arm the `Ctrl-]` prefix.
    Prefix,
    /// Select the next tab, wrapping.
    CycleTab,
    /// Open and select a new numbered tab.
    NewTab,
    /// Force-close the selected tab.
    KillTab,
}

/// The session-level hotkey `key` is, if it is one.
///
/// Spellings follow what terminals send rather than what keyboards label. `0x1d` (`Ctrl-]`) is
/// decoded by Crossterm as Ctrl with `'5'`. Shift-Tab is `BackTab` from both the legacy `ESC[Z`
/// and the kitty `CSI 9;2u` encodings; the `Tab`+SHIFT spelling covers xterm's modifyOtherKeys.
/// Ctrl-Shift-T is distinguishable from Ctrl-T only under the kitty protocol, so `NewTab`
/// requires an actually reported Shift — a legacy `0x14` stays a byte for the child.
const fn hotkey(key: KeyEvent) -> Option<Hotkey> {
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    if matches!(key.code, KeyCode::BackTab) || (matches!(key.code, KeyCode::Tab) && shift) {
        return Some(Hotkey::CycleTab);
    }
    if !key.modifiers.contains(KeyModifiers::CONTROL) {
        return None;
    }
    match key.code {
        KeyCode::Char(']' | '5') => Some(Hotkey::Prefix),
        // An uppercase report only arises from a shifted key (kitty alternate-keys clears the
        // SHIFT bit when it substitutes the shifted character), so 'T' needs no guard.
        KeyCode::Char('T') => Some(Hotkey::NewTab),
        KeyCode::Char('t') if shift => Some(Hotkey::NewTab),
        KeyCode::Char('c' | 'C') => Some(Hotkey::KillTab),
        _ => None,
    }
}

/// Whether a capability read started under `query_epoch` still belongs to this session.
///
/// A read runs on the blocking pool and can finish after the frontend was rebound or detached; its
/// answer is then about jobs that are not these.
const fn accepts_caps(query_epoch: u64, current_epoch: u64, bound: bool) -> bool {
    bound && query_epoch == current_epoch
}

/// A row count as a signed offset, saturating rather than wrapping.
fn index_as_isize(value: usize) -> isize {
    isize::try_from(value).unwrap_or(isize::MAX)
}

/// The frontend, recovering a poisoned lock like the rest of the workspace.
fn lock(frontend: &Mutex<TuiFrontend>) -> std::sync::MutexGuard<'_, TuiFrontend> {
    frontend.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One termination signal stream.
fn signal(kind: tokio::signal::unix::SignalKind) -> Result<tokio::signal::unix::Signal, Error> {
    tokio::signal::unix::signal(kind).map_err(Error::Signals)
}

/// The FIFO worker every lifecycle call goes through.
///
/// One worker means no two UI events can create, launch or close the same name concurrently, so
/// the staleness check immediately before each operation is decisive: no replacement can appear
/// between the check and the call.
async fn lifecycle_worker(
    mux: Arc<ShellMux>,
    mut requests: mpsc::UnboundedReceiver<Lifecycle>,
    reporter: mpsc::UnboundedSender<Message>,
) {
    while let Some(request) = requests.recv().await {
        match request {
            Lifecycle::Spawn {
                dir,
                id,
                cmd,
                select,
            } => {
                // Always without a command: an anonymous auto-closing job would race the UI, so a
                // command is a separate launch into a job that outlives it.
                let result = mux.spawn(&dir, id, None).await;
                if let Ok(spawned) = &result {
                    let id = spawned.id.clone();
                    let uid = spawned.sandbox.uid.clone();
                    let _ = reporter.send(Message::Opened {
                        select,
                        result: Ok(spawned.clone()),
                    });
                    if select {
                        let _ = mux.switch(&id).await;
                    }
                    if let Some(cmd) = cmd {
                        let result = mux.start_in(&id, &cmd, None).await;
                        let _ = reporter.send(Message::Started { uid, id, result });
                    }
                    continue;
                }
                let _ = reporter.send(Message::Opened { select, result });
            }
            Lifecycle::Start { id, uid, cmd } => {
                let result = match current_uid(&mux, &id) {
                    Some(live) if live == uid => mux.start_in(&id, &cmd, None).await,
                    _ => Err(MuxError::NoSuchJob(id.clone())),
                };
                let _ = reporter.send(Message::Started { uid, id, result });
            }
            Lifecycle::Switch {
                id,
                uid,
                generation,
            } => {
                let result = match current_uid(&mux, &id) {
                    Some(live) if live == uid => mux.switch(&id).await.map(|_| ()),
                    _ => Err(MuxError::NoSuchJob(id.clone())),
                };
                let _ = reporter.send(Message::Switched { generation, result });
            }
            Lifecycle::Stop { id, force } => {
                let result = mux.stop(&id, force).await;
                let _ = reporter.send(Message::Stopped { id, result });
            }
            Lifecycle::Shutdown => {
                requests.close();
                while requests.recv().await.is_some() {}
                for job in mux.jobs() {
                    let _ = mux.stop(&job.id, true).await;
                }
                let _ = mux.shutdown().await;
                return;
            }
        }
    }
}

/// The sandbox uid the job named `id` has right now.
fn current_uid(mux: &ShellMux, id: &ShellId) -> Option<String> {
    mux.job(id).map(|job| job.sandbox.uid)
}

/// The worker that applies geometry, keeping only the newest pending dimensions.
async fn resize_worker(
    mux: Arc<ShellMux>,
    mut sizes: tokio::sync::watch::Receiver<(u16, u16)>,
    reporter: mpsc::UnboundedSender<Message>,
) {
    while sizes.changed().await.is_ok() {
        let (rows, cols) = *sizes.borrow_and_update();
        let result = mux.resize(rows, cols).await;
        if result.is_err() {
            let _ = reporter.send(Message::Resized(result));
        }
    }
}

impl App {
    /// The job the selection names, if it is a job and it still exists.
    fn selected_job(&self) -> Option<&JobView> {
        let Selection::Job(uid) = &self.selection else {
            return None;
        };
        self.jobs.iter().find(|job| &job.sandbox.uid == uid)
    }

    /// Whether the selected job is executing something.
    fn selected_busy(&self) -> bool {
        self.selected_job().is_some_and(|job| {
            job.running.is_some() || job.starting || self.pending.contains(&job.sandbox.uid)
        })
    }

    /// The draft for `uid`, created empty on first use.
    fn draft(&mut self, uid: &str) -> &mut TextArea<'static> {
        self.drafts.entry(uid.to_string()).or_insert_with(|| {
            let mut area = TextArea::default();
            area.set_cursor_line_style(Style::default());
            area.remove_line_number();
            area.set_hard_tab_indent(true);
            area
        })
    }

    /// Sends `bytes` to the selected job's child, queueing them while it is still starting.
    fn send_to_child(&mut self, bytes: Vec<u8>) {
        let Some(job) = self.selected_job() else {
            return;
        };
        let uid = job.sandbox.uid.clone();
        if self.pending.contains(&uid) || job.starting {
            let queued = self.queued_input.entry(uid).or_default();
            if queued.len() + bytes.len() > INPUT_QUEUE_LIMIT {
                self.report("Terminal input queue full; input not sent");
                return;
            }
            queued.extend_from_slice(&bytes);
            return;
        }
        if job.running.is_none() {
            // No command is reading this pseudoterminal; bytes written now would be echoed into
            // the next command's input.
            return;
        }
        let sent = self
            .writers
            .get(&uid)
            .is_some_and(|writer| writer.send(bytes));
        if !sent {
            self.report("Terminal input queue full; input not sent");
        }
    }
}

/// The tabs, left to right: the reserved browser, then the jobs in the mux's own order.
impl App {
    /// Every tab's label and what selecting it means.
    fn tabs(&self) -> Vec<(Selection, String)> {
        let mut tabs = vec![(Selection::Caps, "caps".to_string())];
        for job in &self.jobs {
            tabs.push((
                Selection::Job(job.sandbox.uid.clone()),
                escape_controls(&job.id.reference()),
            ));
        }
        tabs
    }

    /// Moves the selection `delta` tabs, wrapping through the whole list.
    fn cycle_tab(&mut self, delta: isize) {
        let tabs = self.tabs();
        if tabs.is_empty() {
            return;
        }
        let current = index_as_isize(
            tabs.iter()
                .position(|(selection, _)| *selection == self.selection)
                .unwrap_or(0),
        );
        let count = index_as_isize(tabs.len());
        let next = (current + delta).rem_euclid(count);
        if let Some((selection, _)) = tabs.get(next.unsigned_abs()) {
            self.select(selection.clone());
        }
    }

    /// Selects `selection`, asking the mux to make a job current through the lifecycle worker.
    ///
    /// Rendering and input do not wait for that acceptance: the tab is already drawn from its own
    /// buffer and its handle already exists.
    fn select(&mut self, selection: Selection) {
        self.overlay = false;
        match &selection {
            Selection::Caps => {
                self.selection = Selection::Caps;
                if self.caps_query.stale || !self.caps_query.loaded {
                    self.start_caps_query();
                }
            }
            Selection::Job(uid) => {
                let Some(job) = self.jobs.iter().find(|job| &job.sandbox.uid == uid) else {
                    return;
                };
                let (id, uid) = (job.id.clone(), job.sandbox.uid.clone());
                self.selection = selection;
                self.focus_generation += 1;
                let generation = self.focus_generation;
                self.enqueue(Lifecycle::Switch {
                    id,
                    uid,
                    generation,
                });
            }
        }
    }

    /// Ends the session, warning once while anything is still executing.
    fn request_exit(&mut self) {
        let busy = self
            .jobs
            .iter()
            .any(|job| job.running.is_some() || job.starting || self.mux.is_merging(&job.id));
        if busy && !self.exit_armed {
            self.exit_armed = true;
            self.report("marsh: there are running jobs (exit again to kill them)");
            return;
        }
        self.exiting = true;
    }

    /// Scrolls the selected job's own history.
    fn scroll_terminal(&self, delta: isize) {
        let Selection::Job(uid) = &self.selection else {
            return;
        };
        let uid = uid.clone();
        let mut frontend = lock(&self.frontend);
        if let Some(buffer) = frontend.buffer_mut(&uid) {
            let next = (index_as_isize(buffer.scrollback) + delta)
                .max(0)
                .unsigned_abs();
            buffer.scrollback = next;
            buffer.parser.screen_mut().set_scrollback(next);
        }
    }

    /// Returns the selected job's view to live output.
    fn resume_live_output(&self, uid: &str) {
        let mut frontend = lock(&self.frontend);
        if let Some(buffer) = frontend.buffer_mut(uid)
            && buffer.scrollback != 0
        {
            buffer.scrollback = 0;
            buffer.parser.screen_mut().set_scrollback(0);
        }
    }

    /// Routes one key.
    fn on_key(&mut self, key: KeyEvent) {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }
        if std::mem::take(&mut self.prefix) {
            self.on_prefix(key);
            return;
        }
        if let Some(action) = hotkey(key) {
            // A running tab keeps Ctrl-C as the child's own interrupt byte; the kill applies to an
            // idle tab, where 0x03 would otherwise go nowhere.
            let forward_interrupt = matches!(action, Hotkey::KillTab) && self.selected_busy();
            if !forward_interrupt {
                if matches!(key.kind, KeyEventKind::Repeat) {
                    // Consumed without effect: a held hotkey must not cascade kills or spawns, and
                    // must not leak its bytes to the child either.
                    return;
                }
                match action {
                    Hotkey::Prefix => self.prefix = true,
                    Hotkey::CycleTab => self.cycle_tab(1),
                    Hotkey::NewTab => self.open_numbered_tab(),
                    Hotkey::KillTab => self.close_selected(true),
                }
                return;
            }
        }
        if key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::PageUp | KeyCode::PageDown)
        {
            let page = isize::from(i16::try_from(self.body_rows()).unwrap_or(i16::MAX)).max(1);
            self.scroll_terminal(if key.code == KeyCode::PageUp {
                page
            } else {
                -page
            });
            return;
        }

        match self.selection.clone() {
            Selection::Caps => self.on_caps_key(key),
            Selection::Job(uid) if self.overlay => self.on_overlay_key(key, &uid),
            Selection::Job(uid) => {
                if self.selected_busy() {
                    let bytes = lock(&self.frontend)
                        .buffer(&uid)
                        .map(|buffer| encode_key(key, buffer.parser.screen()));
                    if let Some(bytes) = bytes
                        && !bytes.is_empty()
                    {
                        self.resume_live_output(&uid);
                        self.send_to_child(bytes.to_vec());
                    }
                } else {
                    self.on_prompt_key(key, &uid);
                }
            }
        }
    }

    /// Routes the key after `Ctrl-]`.
    fn on_prefix(&mut self, key: KeyEvent) {
        if matches!(hotkey(key), Some(Hotkey::Prefix)) {
            // A doubled prefix is the literal byte, for a child that wants it.
            if self.selected_busy() {
                self.send_to_child(vec![0x1d]);
            }
            return;
        }
        match key.code {
            KeyCode::Char('c') => self.select(Selection::Caps),
            KeyCode::Char('n') => self.open_numbered_tab(),
            KeyCode::Char('[') => self.cycle_tab(-1),
            KeyCode::Char(']') => self.cycle_tab(1),
            KeyCode::Char('w') => self.close_selected(false),
            KeyCode::Char('x') => self.close_selected(true),
            KeyCode::Char('i') => {
                self.overlay = !self.overlay && matches!(self.selection, Selection::Job(_));
                self.overlay_scroll = 0;
            }
            KeyCode::Char('q') => self.request_exit(),
            _ => {}
        }
    }

    /// Closes the selected job, as `stop` does.
    fn close_selected(&self, force: bool) {
        let Some(job) = self.selected_job() else {
            return;
        };
        let id = job.id.clone();
        if id.as_str() == repl::FOREGROUND {
            self.report("stop: %main is the console's own job");
            return;
        }
        self.enqueue(Lifecycle::Stop { id, force });
    }

    /// Opens and selects the next numbered job at the current job's directory, or the seed root
    /// when `caps` is selected.
    fn open_numbered_tab(&self) {
        let dir = self
            .selected_job()
            .map_or_else(String::new, |job| job.sandbox.dir.clone());
        self.enqueue(Lifecycle::Spawn {
            dir,
            id: None,
            cmd: None,
            select: true,
        });
    }

    /// Routes a key while the diagnostic overlay is open.
    fn on_overlay_key(&mut self, key: KeyEvent, uid: &str) {
        let page = usize::from(self.body_rows()).max(1);
        let lines = lock(&self.frontend)
            .buffer(uid)
            .map_or(0, |buffer| buffer.diagnostics.len());
        let last = lines.saturating_sub(1);
        match key.code {
            KeyCode::Up => self.overlay_scroll = self.overlay_scroll.saturating_sub(1),
            KeyCode::Down => self.overlay_scroll = (self.overlay_scroll + 1).min(last),
            KeyCode::PageUp => self.overlay_scroll = self.overlay_scroll.saturating_sub(page),
            KeyCode::PageDown => self.overlay_scroll = (self.overlay_scroll + page).min(last),
            KeyCode::Esc => self.overlay = false,
            _ => {}
        }
    }

    /// Routes a key in the capability browser.
    fn on_caps_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('r') {
            self.caps_query.stale = true;
            self.start_caps_query();
            return;
        }
        let page = usize::from(self.body_rows()).max(1);
        let state = self.caps.state_mut();
        // Each call reports whether anything changed; the next frame redraws regardless.
        let _moved = match key.code {
            KeyCode::Up => state.key_up(),
            KeyCode::Down => state.key_down(),
            KeyCode::PageUp => {
                state.select_relative(|at| at.map_or(0, |at| at.saturating_sub(page)))
            }
            KeyCode::PageDown => {
                state.select_relative(|at| at.map_or(0, |at| at.saturating_add(page)))
            }
            KeyCode::Home => state.select_first(),
            KeyCode::End => state.select_last(),
            KeyCode::Right | KeyCode::Enter => state.key_right(),
            KeyCode::Left => state.key_left(),
            _ => false,
        };
    }

    /// Routes a key at an idle job's prompt.
    fn on_prompt_key(&mut self, key: KeyEvent, uid: &str) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Enter if alt => self.draft(uid).insert_newline(),
            KeyCode::Enter => self.submit(uid),
            KeyCode::Char('d') if ctrl => {
                if self.draft(uid).is_empty() {
                    self.request_exit();
                }
            }
            _ => {
                self.draft(uid).input(key);
            }
        }
    }

    /// Routes pasted text.
    fn on_paste(&mut self, text: String) {
        let Selection::Job(uid) = self.selection.clone() else {
            return;
        };
        if self.overlay {
            return;
        }
        if self.selected_busy() {
            let bracketed = lock(&self.frontend)
                .buffer(&uid)
                .is_some_and(|buffer| buffer.parser.screen().bracketed_paste());
            let mut bytes = Vec::with_capacity(text.len() + 12);
            if bracketed {
                bytes.extend_from_slice(b"\x1b[200~");
            }
            bytes.extend_from_slice(text.as_bytes());
            if bracketed {
                bytes.extend_from_slice(b"\x1b[201~");
            }
            self.resume_live_output(&uid);
            self.send_to_child(bytes);
            return;
        }
        // An idle prompt: pasted text is edited, never executed, until Enter is pressed.
        self.draft(&uid).insert_str(text);
    }

    /// Routes a mouse event.
    fn on_mouse(&mut self, mouse: MouseEvent) {
        if mouse.row == 0 {
            if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
                && let Some(selection) = self.tab_at(mouse.column)
            {
                self.select(selection);
            }
            return;
        }
        let Selection::Job(uid) = self.selection.clone() else {
            return;
        };
        if self.overlay {
            return;
        }
        let body_rows = self.body_rows();
        if mouse.row == 0 || mouse.row > body_rows {
            return;
        }
        let (row, col) = (mouse.row - 1, mouse.column);
        let report = lock(&self.frontend)
            .buffer(&uid)
            .and_then(|buffer| encode_mouse(mouse, row, col, buffer.parser.screen()));
        if let Some(report) = report {
            self.send_to_child(report.to_vec());
            return;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => self.scroll_terminal(3),
            MouseEventKind::ScrollDown => self.scroll_terminal(-3),
            _ => {}
        }
    }

    /// The tab a click at `column` lands on.
    fn tab_at(&self, column: u16) -> Option<Selection> {
        self.tab_hits
            .iter()
            .find(|(start, width, _)| column >= *start && column < start.saturating_add(*width))
            .map(|(_, _, selection)| selection.clone())
    }

    /// Submits the draft of the job `uid`.
    fn submit(&mut self, uid: &str) {
        let line = self.draft(uid).lines().join("\n");
        let input = repl::parse(&line);
        if !matches!(input, repl::Input::Exit) {
            self.exit_armed = false;
        }
        let base = self
            .selected_job()
            .map_or_else(String::new, |job| job.sandbox.dir.clone());
        let id = self.selected_job().map(|job| job.id.clone());
        match input {
            repl::Input::Empty => {}
            repl::Input::Foreground(cmd) => {
                let Some(id) = id else { return };
                if self.mux.is_merging(&id) {
                    self.report(&format!(
                        "{}: still merging its last command",
                        id.reference()
                    ));
                    return;
                }
                if self.selected_busy() {
                    self.report(&format!("{} is busy", id.reference()));
                    return;
                }
                // Marked before the launch is enqueued, so the window between submission and the
                // mux reporting `starting` is not one in which a second command can slip through.
                self.pending.insert(uid.to_string());
                self.enqueue(Lifecycle::Start {
                    id,
                    uid: uid.to_string(),
                    cmd,
                });
                self.draft(uid).clear();
            }
            repl::Input::SpawnDir { name, dir } => {
                self.enqueue(Lifecycle::Spawn {
                    dir: repl::job_dir(&base, &dir),
                    id: name.map(ShellId::from),
                    cmd: None,
                    select: true,
                });
                self.draft(uid).clear();
            }
            repl::Input::Background { cmd, name } => {
                self.enqueue(Lifecycle::Spawn {
                    dir: repl::job_dir(&base, "."),
                    id: name.map(ShellId::from),
                    cmd: Some(cmd),
                    select: false,
                });
                self.draft(uid).clear();
            }
            repl::Input::Fg(name) => {
                let target = match name {
                    Some(name) => self
                        .jobs
                        .iter()
                        .find(|job| job.id.as_str() == name)
                        .map(|job| job.sandbox.uid.clone()),
                    None => self.jobs.last().map(|job| job.sandbox.uid.clone()),
                };
                match target {
                    Some(uid) => self.select(Selection::Job(uid)),
                    None => self.report("marsh: no such job"),
                }
                self.draft(uid).clear();
            }
            repl::Input::Jobs => {
                let mut out = Vec::new();
                jobctl::print_jobs(&self.mux, &mut out);
                self.show(&out);
                self.draft(uid).clear();
            }
            repl::Input::Stop(args) => {
                match repl::parse_stop(&args) {
                    Ok(args) if args.job == repl::FOREGROUND => {
                        self.report("stop: %main is the console's own job");
                    }
                    Ok(args) => self.enqueue(Lifecycle::Stop {
                        id: ShellId::from(args.job),
                        force: args.force,
                    }),
                    Err(message) => self.show(message.as_bytes()),
                }
                self.draft(uid).clear();
            }
            repl::Input::Kill(args) => {
                let mut out = Vec::new();
                let _ = jobctl::kill(&args, &mut out);
                self.show(&out);
                self.draft(uid).clear();
            }
            repl::Input::Exit => {
                self.draft(uid).clear();
                self.request_exit();
            }
            repl::Input::Invalid(message) => {
                self.report(&message);
                self.draft(uid).clear();
            }
        }
    }

    /// Puts captured output into the selected job's diagnostics and the footer.
    fn show(&self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            self.report(line);
        }
    }
}

/// Rendering: cached views and borrowed emulator screens, and no mux call at all.
impl App {
    /// How many rows the body has, which is also every job's terminal height.
    fn body_rows(&self) -> u16 {
        lock(&self.frontend).geometry().0
    }

    /// Draws one frame.
    fn draw(&mut self) -> Result<(), Error> {
        let Some(mut terminal) = self.terminal.take() else {
            return Ok(());
        };
        let result = terminal.draw(|frame| self.render(frame)).map(|_| ());
        self.terminal = Some(terminal);
        result.map_err(Error::Terminal)
    }

    /// Renders the tab bar, the body, the command line and the footer.
    fn render(&mut self, frame: &mut ratatui::Frame<'_>) {
        let [tab_area, body, input_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        self.render_tabs(frame, tab_area);
        self.render_body(frame, body);
        self.render_input(frame, input_area);
        self.render_footer(frame, footer_area);
    }

    /// Draws the tab bar through a contiguous window that always contains the selected tab.
    fn render_tabs(&mut self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let tabs = self.tabs();
        let widths: Vec<u16> = tabs
            .iter()
            .map(|(_, label)| u16::try_from(label.chars().count()).unwrap_or(u16::MAX))
            .collect();
        let selected = tabs
            .iter()
            .position(|(selection, _)| *selection == self.selection)
            .unwrap_or(0);

        let (mut first, mut last) = (selected, selected);
        let mut used = widths.get(selected).copied().unwrap_or(0);
        loop {
            let mut grew = false;
            if last + 1 < tabs.len() {
                let extra = widths[last + 1].saturating_add(1);
                if used + extra <= area.width {
                    used += extra;
                    last += 1;
                    grew = true;
                }
            }
            if first > 0 {
                let extra = widths[first - 1].saturating_add(1);
                if used + extra <= area.width {
                    used += extra;
                    first -= 1;
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        self.tab_hits.clear();
        let mut spans = Vec::new();
        let mut column = area.x;
        for (index, (selection, label)) in tabs.iter().enumerate() {
            if index < first || index > last {
                continue;
            }
            if !spans.is_empty() {
                spans.push(Span::raw(" "));
                column += 1;
            }
            let style = if *selection == self.selection {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(GRAY)
            };
            self.tab_hits
                .push((column, widths[index], selection.clone()));
            column += widths[index];
            spans.push(Span::styled(label.clone(), style));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// Draws whatever the selected tab shows.
    fn render_body(&mut self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        match self.selection.clone() {
            Selection::Caps => self.render_caps(frame, area),
            Selection::Job(uid) if self.overlay => {
                let lines: Vec<Line<'_>> = lock(&self.frontend)
                    .buffer(&uid)
                    .map(|buffer| {
                        buffer
                            .diagnostics
                            .iter()
                            .skip(self.overlay_scroll)
                            .take(area.height as usize)
                            .map(|line| Line::styled(line.clone(), Style::default().fg(GRAY)))
                            .collect()
                    })
                    .unwrap_or_default();
                frame.render_widget(Paragraph::new(lines), area);
            }
            Selection::Job(uid) => {
                let frontend = lock(&self.frontend);
                let Some(buffer) = frontend.buffer(&uid) else {
                    drop(frontend);
                    frame.render_widget(
                        Paragraph::new(Line::styled("opening…", Style::default().fg(GRAY))),
                        area,
                    );
                    return;
                };
                let screen = buffer.parser.screen();
                let live = buffer.scrollback == 0;
                let cursor = (!screen.hide_cursor() && live).then(|| screen.cursor_position());
                frame.render_widget(PseudoTerminal::new(screen), area);
                drop(frontend);
                if let Some((row, col)) = cursor
                    && self.selected_busy()
                {
                    frame.set_cursor_position(Position::new(
                        area.x.saturating_add(col),
                        area.y.saturating_add(row),
                    ));
                }
            }
        }
    }

    /// Draws the capability browser.
    fn render_caps(&mut self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let bound = lock(&self.frontend).mux().is_some();
        if !bound {
            frame.render_widget(Paragraph::new("No active Marsh session"), area);
            return;
        }
        if let Some(error) = &self.caps_query.error {
            frame.render_widget(
                Paragraph::new(format!("cannot read capabilities: {error}")),
                area,
            );
            return;
        }
        if !self.caps_query.loaded {
            frame.render_widget(Paragraph::new("Loading capabilities…"), area);
            return;
        }
        if self.caps.is_empty() {
            frame.render_widget(Paragraph::new("No active granted capabilities"), area);
            return;
        }
        self.caps.render(area, frame.buffer_mut());
    }

    /// The prompt of `job`, as the input line labels it: name, `@`, directory, `$ `.
    fn prompt(job: &JobView) -> String {
        format!(
            "{}@{}$ ",
            escape_controls(job.id.as_str()),
            escape_controls(jobctl::dir_label(&job.sandbox))
        )
    }

    /// The input line of a job that is executing something.
    ///
    /// While the mux reports a command running, the prompt followed by that command — so a tab
    /// opened by `cmd &NAME`, whose line was typed elsewhere, still says what it is doing. While
    /// the launch is in flight and the mux reports no command yet, the state alone.
    fn busy_line(job: &JobView) -> String {
        job.running.as_ref().map_or_else(
            || {
                format!(
                    "{} running — keys go to the command",
                    escape_controls(&job.id.reference())
                )
            },
            |running| format!("{}{}", Self::prompt(job), escape_controls(&running.cmd)),
        )
    }

    /// Draws the command line of the selected job: the prompt and its draft while it is idle, the
    /// prompt and the command it is running while it is busy.
    fn render_input(&mut self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        match self.selection.clone() {
            Selection::Caps => frame.render_widget(
                Paragraph::new(Line::styled(
                    format!("caps · {}", self.mux.persistence().seed.display()),
                    Style::default().fg(GRAY),
                )),
                area,
            ),
            Selection::Job(uid) => {
                if self.selected_busy() {
                    let line = self
                        .selected_job()
                        .map_or_else(String::new, Self::busy_line);
                    frame.render_widget(
                        Paragraph::new(Line::styled(line, Style::default().fg(GRAY))),
                        area,
                    );
                    return;
                }
                let prompt = self.selected_job().map_or_else(String::new, Self::prompt);
                let width = u16::try_from(prompt.chars().count()).unwrap_or(0);
                let [label, editor] =
                    Layout::horizontal([Constraint::Length(width), Constraint::Min(1)]).areas(area);
                frame.render_widget(Paragraph::new(prompt), label);
                frame.render_widget(&*self.draft(&uid), editor);
            }
        }
    }

    /// Draws the footer: the prefix help, the selected resource, or the latest diagnostic.
    fn render_footer(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let text = if self.prefix {
            "^] c caps · n new · [ ] tabs · w close · x kill · i diagnostics · q quit".to_string()
        } else if matches!(self.selection, Selection::Caps) {
            self.caps.detail().unwrap_or_else(|| self.status.clone())
        } else {
            // The latest diagnostic, whatever produced it; the startup line until there is one.
            lock(&self.frontend)
                .last_diagnostic()
                .map_or_else(|| self.status.clone(), str::to_string)
        };
        frame.render_widget(
            Paragraph::new(Line::styled(text, Style::default().fg(GRAY))),
            area,
        );
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use shellmux::{RunningView, Sandbox};

    /// A capability read that outlived its binding must be discarded: rebinding bumps the epoch,
    /// and a detached frontend has no session to answer about.
    #[test]
    fn a_capability_read_from_an_old_binding_is_rejected() {
        let mut frontend = TuiFrontend::new(24, 80);
        let first = frontend.epoch();
        assert!(accepts_caps(first, frontend.epoch(), true));

        frontend.bind(std::sync::Weak::new());
        assert_ne!(frontend.epoch(), first, "rebinding starts a new generation");
        assert!(
            !accepts_caps(first, frontend.epoch(), true),
            "an answer from the previous session is not this session's"
        );
        assert!(
            !accepts_caps(frontend.epoch(), frontend.epoch(), false),
            "and a detached frontend accepts none at all"
        );
    }

    /// Hotkeys are classified by the bytes terminals actually send: Shift-Tab is `BackTab` in both
    /// encodings, Ctrl-Shift-T requires a genuinely reported Shift (legacy Ctrl-T stays a child
    /// byte), and plain letters are never session hotkeys.
    #[test]
    fn hotkeys_are_classified_by_their_byte_reality() {
        let press = |code, modifiers| KeyEvent::new(code, modifiers);
        let (ctrl, shift, none) = (
            KeyModifiers::CONTROL,
            KeyModifiers::SHIFT,
            KeyModifiers::NONE,
        );

        assert_eq!(
            hotkey(press(KeyCode::Char('t'), ctrl | shift)),
            Some(Hotkey::NewTab)
        );
        assert_eq!(
            hotkey(press(KeyCode::Char('T'), ctrl)),
            Some(Hotkey::NewTab)
        );
        assert_eq!(
            hotkey(press(KeyCode::Char('t'), ctrl)),
            None,
            "a legacy 0x14 is indistinguishable from Ctrl-T and stays a child byte"
        );
        assert_eq!(
            hotkey(press(KeyCode::BackTab, shift)),
            Some(Hotkey::CycleTab)
        );
        assert_eq!(
            hotkey(press(KeyCode::BackTab, none)),
            Some(Hotkey::CycleTab)
        );
        assert_eq!(
            hotkey(press(KeyCode::Tab, shift)),
            Some(Hotkey::CycleTab),
            "modifyOtherKeys spells Shift-Tab as Tab+SHIFT"
        );
        assert_eq!(hotkey(press(KeyCode::Tab, none)), None);
        assert_eq!(
            hotkey(press(KeyCode::Char('c'), ctrl)),
            Some(Hotkey::KillTab)
        );
        assert_eq!(
            hotkey(press(KeyCode::Char(']'), ctrl)),
            Some(Hotkey::Prefix)
        );
        assert_eq!(
            hotkey(press(KeyCode::Char('5'), ctrl)),
            Some(Hotkey::Prefix)
        );
        assert_eq!(hotkey(press(KeyCode::Char('c'), none)), None);
    }

    /// A busy tab's input line says what the job is doing: the command the mux reports running,
    /// behind that job's own prompt — which is how a tab opened by `cmd &NAME` shows a line that
    /// was typed in another tab — and the launch state alone while no command is reported yet.
    /// Control characters in a command are shown, never drawn.
    #[test]
    fn a_busy_input_line_names_the_running_command() {
        let mut job = JobView {
            id: ShellId::from("foo"),
            sandbox: Sandbox {
                id: ShellId::from("foo"),
                dir: "api".to_string(),
                uid: "u".to_string(),
            },
            running: Some(RunningView {
                cmd: "sleep 5".to_string(),
                pid: 0,
            }),
            starting: false,
            closing: false,
        };
        assert_eq!(App::busy_line(&job), "foo@api$ sleep 5");

        job.running = Some(RunningView {
            cmd: "printf '\u{1b}[2J'".to_string(),
            pid: 0,
        });
        assert_eq!(App::busy_line(&job), "foo@api$ printf '\\x1b[2J'");

        job.running = None;
        job.starting = true;
        assert_eq!(
            App::busy_line(&job),
            "%foo running — keys go to the command",
            "a launch the mux has not yet published a command for shows its state"
        );
    }
}
