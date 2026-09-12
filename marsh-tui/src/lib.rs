//! `marsh --tui`: one real terminal tab per job, plus a `caps` tab over the authority's active
//! granted capabilities.
//!
//! This crate is a [`shellmux::MarshFrontend`] and nothing more. Shell execution, authorization
//! and job ownership stay in the mux: the session opens jobs, starts commands, forwards keystrokes
//! and draws what the mux tells it, and every capability decision is still the authority's.
//!
//! A job is a sandbox with a pseudoterminal, not a command. Tabs outlive the commands run in them,
//! including anonymous background ones, so a finished command leaves a terminal a user can read
//! and reuse. `caps` is reserved: a job literally named `caps` is the tab `%caps`.
//!
//! # Example
//!
//! ```no_run
//! # async fn wrapper() -> Result<(), marsh_tui::Error> {
//! marsh_tui::run(|_frontend, _environment| unimplemented!("the CLI supplies the bootstrap")).await
//! # }
//! ```

mod app;
mod caps;
mod error;
mod frontend;
mod terminal;

use std::io::IsTerminal as _;
use std::sync::{Arc, Mutex};

use shellmux::{MarshFrontend as _, MuxError, ShellMux, jobctl};

pub use crate::caps::{CapsView, Claim};
pub use crate::error::Error;
pub use crate::frontend::{JobBuffer, TuiFrontend};
pub use crate::terminal::{KeyBytes, TerminalReplies, encode_key, encode_mouse, escape_controls};

/// The fewest rows a tab bar, one body row, a command line and a footer fit in.
const MINIMUM_ROWS: u16 = 4;

/// The terminal modes this session enabled, undone exactly once however it ends.
struct Restore {
    /// Whether bracketed paste was enabled here.
    bracketed_paste: bool,
    /// Whether mouse capture was enabled here.
    mouse: bool,
    /// Whether keyboard-enhancement flags were pushed here.
    keyboard: bool,
    /// Whether the restoration has already run.
    done: bool,
}

impl Restore {
    /// Undoes whatever was enabled, then hands the terminal back.
    fn run(&mut self) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let mut out = std::io::stdout();
        if self.keyboard {
            let _ = crossterm::execute!(out, crossterm::event::PopKeyboardEnhancementFlags);
        }
        if self.mouse {
            let _ = crossterm::execute!(out, crossterm::event::DisableMouseCapture);
        }
        if self.bracketed_paste {
            let _ = crossterm::execute!(out, crossterm::event::DisableBracketedPaste);
        }
        ratatui::restore();
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        // Also the panic path: ratatui's own hook restores the screen, and these two extra modes
        // are this session's to undo.
        self.run();
    }
}

/// Runs the full-screen interface until the session ends.
///
/// `open_mux` is the caller's bootstrap: the CLI keeps deciding storage discovery and the purity
/// checker, while this crate supplies the frontend the mux delivers to and the environment its
/// jobs' shells are seeded from. It runs on the blocking pool, because opening a seed takes a
/// lease and touches the filesystem.
///
/// Must be awaited inside a multi-thread Tokio runtime: the session uses `spawn_blocking` and
/// selects over several streams at once.
///
/// # Errors
///
/// Fails when there is no terminal to draw on, when the terminal is too small or cannot be
/// configured, when signals or input cannot be read, or when the mux could not be opened.
pub async fn run<F>(open_mux: F) -> Result<(), Error>
where
    F: FnOnce(
            Arc<Mutex<TuiFrontend>>,
            brush_core::env::ShellEnvironment,
        ) -> Result<Arc<ShellMux>, MuxError>
        + Send
        + 'static,
{
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(Error::NotATerminal);
    }

    // Retained for the whole session: a stream dropped after construction would leave the default
    // disposition in place, and a SIGTERM would kill the session mid-transaction.
    let mut signals = TerminationSignals::new()?;
    jobctl::ignore_terminal_job_signals();

    let terminal = ratatui::try_init().map_err(Error::Terminal)?;
    let mut restore = Restore {
        bracketed_paste: false,
        mouse: false,
        keyboard: false,
        done: false,
    };
    let mut out = std::io::stdout();
    if crossterm::execute!(out, crossterm::event::EnableBracketedPaste).is_ok() {
        restore.bracketed_paste = true;
    }
    if crossterm::execute!(out, crossterm::event::EnableMouseCapture).is_ok() {
        restore.mouse = true;
    }
    // True Ctrl-Shift-T needs the kitty keyboard protocol: without it the terminal sends the
    // same byte for Ctrl-T and Ctrl-Shift-T. Support is probed (crossterm answers within 2s or
    // errors), and an unsupported or unqueryable terminal simply has no NewTab hotkey.
    if crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false)
        && crossterm::execute!(
            out,
            crossterm::event::PushKeyboardEnhancementFlags(
                crossterm::event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES,
            )
        )
        .is_ok()
    {
        restore.keyboard = true;
    }

    let result = session(terminal, &mut signals, open_mux).await;
    restore.run();
    result
}

/// The session proper, with the terminal already configured.
async fn session<F>(
    terminal: ratatui::DefaultTerminal,
    signals: &mut TerminationSignals,
    open_mux: F,
) -> Result<(), Error>
where
    F: FnOnce(
            Arc<Mutex<TuiFrontend>>,
            brush_core::env::ShellEnvironment,
        ) -> Result<Arc<ShellMux>, MuxError>
        + Send
        + 'static,
{
    let size = terminal.size().map_err(Error::Terminal)?;
    if size.height < MINIMUM_ROWS || size.width == 0 {
        // Before any storage is touched: refusing after taking the seed's lease would leave a
        // session nobody can see holding it.
        return Err(Error::TooSmall {
            rows: size.height,
            cols: size.width,
        });
    }
    let body_rows = size.height - 3;

    let frontend = Arc::new(Mutex::new(TuiFrontend::new(body_rows, size.width)));
    let environment = job_environment()?;

    let bootstrap = Arc::clone(&frontend);
    let mut opening = tokio::task::spawn_blocking(move || open_mux(bootstrap, environment));
    let mut interrupted = false;
    // The construction task is polled to completion whatever arrives meanwhile: it may be taking
    // the seed's exclusive lease, and abandoning it would leak one.
    let mux = loop {
        tokio::select! {
            result = &mut opening => break result,
            () = signals.any(), if !interrupted => interrupted = true,
        }
    };
    let mux = mux.map_err(Error::Startup)??;

    if interrupted {
        let _ = mux.shutdown().await;
        return Ok(());
    }

    app::App::new(frontend, mux, terminal).run().await
}

/// The environment every job's shell is seeded from.
///
/// `TERM` is this crate's, because a job's terminal is this emulator and not whatever the outer
/// terminal happens to be. The process environment is not touched: everything else keeps being
/// inherited exactly as the console inherits it.
fn job_environment() -> Result<brush_core::env::ShellEnvironment, Error> {
    let mut environment = brush_core::env::ShellEnvironment::new();
    let mut term = brush_core::ShellVariable::new("xterm-256color");
    term.export();
    environment
        .set_global("TERM", term)
        .map_err(Error::Environment)?;
    Ok(environment)
}

/// The termination signals a session shuts down on.
struct TerminationSignals {
    /// Ctrl-C delivered to this process rather than to a job.
    interrupt: tokio::signal::unix::Signal,
    /// A polite request to end.
    terminate: tokio::signal::unix::Signal,
    /// The terminal went away.
    hangup: tokio::signal::unix::Signal,
}

impl TerminationSignals {
    /// Registers all three.
    fn new() -> Result<Self, Error> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(Error::Signals)?,
            terminate: signal(SignalKind::terminate()).map_err(Error::Signals)?,
            hangup: signal(SignalKind::hangup()).map_err(Error::Signals)?,
        })
    }

    /// Resolves when any of them arrives.
    async fn any(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
        }
    }
}
