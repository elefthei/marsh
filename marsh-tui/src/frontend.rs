//! What the mux tells this session, and the per-job buffers it keeps.
//!
//! The frontend is the only thing the mux's byte pumps touch, so every callback here is short: it
//! writes into memory and wakes the application. Nothing draws, awaits, or calls back into the mux
//! under this lock — the mux's own contract allows a callback to read the mux, and holding a
//! frontend mutex across a mux call is how a session deadlocks itself.
//!
//! Buffers are keyed by [`shellmux::Sandbox::uid`], never by job name: a name handed out again is
//! a different job, and its predecessor's scrollback is not its own.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};

use shellmux::{FrontendBinding, FrontendEvent, MarshFrontend, ShellId, ShellMux, Spawned, repl};
use tokio::sync::Notify;

use crate::terminal::{TerminalReplies, escape_controls};

/// How much history one job's terminal keeps.
const SCROLLBACK: usize = 10_000;

/// How many diagnostic lines one job keeps.
const DIAGNOSTIC_LINES: usize = 1_000;

/// How long an unfinished instrumentation line may grow before it is reported truncated.
const MAX_PENDING_INSTRUMENTATION: usize = 16 * 1024;

/// One job's emulated terminal and the diagnostics it produced.
pub struct JobBuffer {
    /// The job's name at the time it opened, for labels.
    pub id: ShellId,
    /// The emulator, fed every byte of the job's terminal stream verbatim.
    pub parser: vt100::Parser<TerminalReplies>,
    /// How far back in the scrollback this job is being viewed; zero is live output.
    pub scrollback: usize,
    /// Instrumentation bytes with no newline yet.
    pending: Vec<u8>,
    /// Whether the unfinished instrumentation line was cut for length.
    truncated: bool,
    /// The retained diagnostic lines, oldest first.
    pub diagnostics: VecDeque<String>,
}

impl JobBuffer {
    /// A buffer for a job whose terminal is `rows` × `cols`.
    fn new(id: ShellId, rows: u16, cols: u16) -> Self {
        Self {
            id,
            parser: vt100::Parser::new_with_callbacks(
                rows,
                cols,
                SCROLLBACK,
                TerminalReplies::default(),
            ),
            scrollback: 0,
            pending: Vec::new(),
            truncated: false,
            diagnostics: VecDeque::new(),
        }
    }

    /// Appends one diagnostic line, dropping the oldest once the retention bound is reached.
    pub fn push_diagnostic(&mut self, line: String) {
        if self.diagnostics.len() == DIAGNOSTIC_LINES {
            self.diagnostics.pop_front();
        }
        self.diagnostics.push_back(line);
    }

    /// Absorbs an instrumentation chunk, emitting whatever lines it completes.
    fn absorb_instrumentation(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=newline).collect();
            let text = String::from_utf8_lossy(&line[..newline]);
            let text = escape_controls(text.trim_end_matches('\r'));
            let text = if std::mem::take(&mut self.truncated) {
                format!("{text} [truncated]")
            } else {
                text
            };
            self.push_diagnostic(text);
        }
        // A stream with no newline in it must not grow without bound. What is kept is the head of
        // the line, because that is where a diagnostic says what it is about.
        if self.pending.len() > MAX_PENDING_INSTRUMENTATION {
            self.pending.truncate(MAX_PENDING_INSTRUMENTATION);
            self.truncated = true;
        }
    }
}

/// The mux's view of a `marsh --tui` session.
pub struct TuiFrontend {
    /// Geometry, mux binding and live handles: the part the mux contract dictates.
    binding: FrontendBinding,
    /// Incremented on every bind, so work started for one session cannot land in the next.
    epoch: u64,
    /// One buffer per open job, by sandbox uid.
    buffers: HashMap<String, JobBuffer>,
    /// Whether the display is out of date.
    dirty: bool,
    /// Whether the capability view is out of date.
    caps_dirty: bool,
    /// The most recent diagnostic line, whatever job produced it.
    last_diagnostic: Option<String>,
    /// Wakes the application after a callback changed something.
    notify: Arc<Notify>,
}

impl TuiFrontend {
    /// The notification every callback signals.
    #[must_use]
    pub fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// The binding generation: work tagged with an older one belongs to a replaced session.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The bound mux, or `None` while unbound.
    #[must_use]
    pub fn mux(&self) -> Option<Arc<ShellMux>> {
        self.binding.mux()
    }

    /// The handle for `id`, if this session still holds one.
    #[must_use]
    pub fn handle(&self, id: &ShellId) -> Option<Spawned> {
        self.binding.handle(id)
    }

    /// The geometry every job's terminal is at, rows first.
    #[must_use]
    pub const fn geometry(&self) -> (u16, u16) {
        self.binding.size()
    }

    /// Takes the dirty flags: the display first, the capability view second.
    pub fn take_dirty(&mut self) -> (bool, bool) {
        (
            std::mem::take(&mut self.dirty),
            std::mem::take(&mut self.caps_dirty),
        )
    }

    /// Marks the capability view out of date.
    pub const fn invalidate_caps(&mut self) {
        self.caps_dirty = true;
    }

    /// The buffer for `uid`, if that job is open.
    #[must_use]
    pub fn buffer(&self, uid: &str) -> Option<&JobBuffer> {
        self.buffers.get(uid)
    }

    /// The buffer for `uid`, mutably.
    pub fn buffer_mut(&mut self, uid: &str) -> Option<&mut JobBuffer> {
        self.buffers.get_mut(uid)
    }

    /// The most recent diagnostic line.
    #[must_use]
    pub fn last_diagnostic(&self) -> Option<&str> {
        self.last_diagnostic.as_deref()
    }

    /// Records one diagnostic against `uid`, and as the latest line overall.
    pub fn record(&mut self, uid: &str, line: String) {
        if let Some(buffer) = self.buffers.get_mut(uid) {
            buffer.push_diagnostic(line.clone());
        }
        self.note(line);
    }

    /// Records one diagnostic that belongs to no job.
    pub fn note(&mut self, line: String) {
        self.last_diagnostic = Some(line);
        self.dirty = true;
    }

    /// Takes every queued terminal reply, tagged with the job that must receive it.
    pub fn drain_replies(&mut self) -> Vec<(String, Vec<u8>)> {
        let mut replies = Vec::new();
        for (uid, buffer) in &mut self.buffers {
            let bytes = buffer.parser.callbacks_mut().take();
            if !bytes.is_empty() {
                replies.push((uid.clone(), bytes));
            }
        }
        replies
    }

    /// Wakes the application.
    fn wake(&mut self) {
        self.dirty = true;
        self.notify.notify_one();
    }
}

impl MarshFrontend for TuiFrontend {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            binding: FrontendBinding::new(rows, cols),
            epoch: 0,
            buffers: HashMap::new(),
            dirty: true,
            caps_dirty: true,
            last_diagnostic: None,
            notify: Arc::new(Notify::new()),
        }
    }

    fn size(&self) -> (u16, u16) {
        self.binding.size()
    }

    fn bind(&mut self, mux: Weak<ShellMux>) {
        // A fresh binding at the same geometry: recreating it is what drops the previous session's
        // handles, which would otherwise hold pseudoterminal masters open past their mux.
        let (rows, cols) = self.binding.size();
        self.binding = FrontendBinding::new(rows, cols);
        self.epoch = self.epoch.wrapping_add(1);
        self.buffers.clear();
        self.last_diagnostic = None;
        self.binding.bind(mux);
        self.caps_dirty = true;
        self.wake();
    }

    fn update(&mut self, event: FrontendEvent<'_>) {
        self.binding.observe(event);
        let (rows, cols) = self.binding.size();
        match event {
            FrontendEvent::Opened(spawned) => {
                self.buffers.insert(
                    spawned.sandbox.uid.clone(),
                    JobBuffer::new(spawned.id.clone(), rows, cols),
                );
                self.caps_dirty = true;
            }
            FrontendEvent::Terminal { shell, bytes } => {
                if let Some(buffer) = self.buffers.get_mut(&shell.uid) {
                    buffer.parser.process(bytes);
                }
            }
            FrontendEvent::Instrumentation { shell, bytes } => {
                if let Some(buffer) = self.buffers.get_mut(&shell.uid) {
                    buffer.absorb_instrumentation(bytes);
                    self.last_diagnostic = buffer.diagnostics.back().cloned();
                }
            }
            FrontendEvent::Finished { shell, outcome, .. } => {
                let lines = repl::report_lines(&shell.id, outcome);
                if let Some(buffer) = self.buffers.get_mut(&shell.uid) {
                    for line in lines {
                        buffer.push_diagnostic(escape_controls(&line));
                    }
                    self.last_diagnostic = buffer.diagnostics.back().cloned();
                }
                self.caps_dirty = true;
            }
            FrontendEvent::Closed(shell) => {
                self.buffers.remove(&shell.uid);
                self.caps_dirty = true;
            }
            FrontendEvent::Resized { rows, cols } => {
                for buffer in self.buffers.values_mut() {
                    buffer.parser.screen_mut().set_size(rows, cols);
                    buffer.scrollback = 0;
                }
            }
            FrontendEvent::IoError { shell, error } => {
                // One stream is over; the job is not, so nothing is removed here.
                let line = escape_controls(&format!("{}: {error}", shell.id.reference()));
                self.last_diagnostic = Some(line.clone());
                if let Some(buffer) = self.buffers.get_mut(&shell.uid) {
                    buffer.push_diagnostic(line);
                }
            }
            FrontendEvent::Changed => self.caps_dirty = true,
        }
        self.wake();
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Buffers are uid-keyed, so a name handed out again never shows its predecessor's output and
    /// the old job's closure never takes the new job's buffer.
    #[test]
    fn a_reused_name_gets_its_own_buffer_and_the_old_closure_leaves_it_alone() {
        let mut frontend = TuiFrontend::new(24, 80);
        frontend.buffers.insert(
            "old".to_string(),
            JobBuffer::new(ShellId::from("build"), 24, 80),
        );
        frontend.buffers.insert(
            "new".to_string(),
            JobBuffer::new(ShellId::from("build"), 24, 80),
        );

        frontend
            .buffer_mut("old")
            .expect("the first job's buffer")
            .parser
            .process(b"first");
        frontend
            .buffer_mut("new")
            .expect("the second job's buffer")
            .parser
            .process(b"second");

        frontend.buffers.remove("old");
        assert!(frontend.buffer("old").is_none());
        assert!(
            frontend
                .buffer("new")
                .expect("the live job survives")
                .parser
                .screen()
                .contents()
                .starts_with("second")
        );
    }

    /// Instrumentation is framed per job, and an unterminated line cannot grow without bound.
    #[test]
    fn instrumentation_is_framed_by_line_and_bounded_in_length() {
        let mut buffer = JobBuffer::new(ShellId::from("main"), 24, 80);
        buffer.absorb_instrumentation(b"one\ntw");
        buffer.absorb_instrumentation(b"o\r\n");
        assert_eq!(
            buffer.diagnostics.iter().cloned().collect::<Vec<_>>(),
            vec!["one".to_string(), "two".to_string()],
        );

        buffer.absorb_instrumentation(&vec![b'x'; MAX_PENDING_INSTRUMENTATION + 10]);
        buffer.absorb_instrumentation(b"\n");
        let last = buffer.diagnostics.back().expect("a line was completed");
        assert!(last.ends_with("[truncated]"), "{last}");
        assert!(last.len() <= MAX_PENDING_INSTRUMENTATION + "[truncated]".len() + 1);
    }

    /// The body renders the emulator's own cells: color and wide characters survive to the screen.
    #[test]
    fn a_jobs_screen_renders_its_colors_and_wide_characters() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut buffer = JobBuffer::new(ShellId::from("1"), 4, 10);
        buffer
            .parser
            .process("\x1b[31mred\x1b[0m \u{754c}".as_bytes());

        let mut terminal =
            Terminal::new(TestBackend::new(10, 4)).expect("a test terminal is buildable");
        terminal
            .draw(|frame| {
                frame.render_widget(
                    tui_term::widget::PseudoTerminal::new(buffer.parser.screen()),
                    frame.area(),
                );
            })
            .expect("the frame renders");

        let rendered = terminal.backend().buffer().clone();
        assert_eq!(rendered[(0, 0)].symbol(), "r");
        assert_eq!(rendered[(0, 0)].fg, ratatui::style::Color::Indexed(1));
        assert_eq!(rendered[(2, 0)].fg, ratatui::style::Color::Indexed(1));
        assert_eq!(
            rendered[(4, 0)].symbol(),
            "\u{754c}",
            "a wide character keeps its own cell"
        );
    }

    /// A reply is queued against the job that asked for it, whatever tab is in front.
    #[test]
    fn replies_are_tagged_with_the_job_that_produced_them() {
        let mut frontend = TuiFrontend::new(24, 80);
        frontend
            .buffers
            .insert("a".to_string(), JobBuffer::new(ShellId::from("1"), 24, 80));
        frontend
            .buffers
            .insert("b".to_string(), JobBuffer::new(ShellId::from("2"), 24, 80));
        frontend
            .buffer_mut("b")
            .expect("the hidden job")
            .parser
            .process(b"\x1b[2;3H\x1b[6n");

        let replies = frontend.drain_replies();
        assert_eq!(replies, vec![("b".to_string(), b"\x1b[2;3R".to_vec())]);
        assert!(frontend.drain_replies().is_empty(), "replies drain once");
    }
}
