//! What ends a `marsh --tui` session.
//!
//! Everything here is fatal: the CLI prints one as `marsh: {error}` after the terminal has been
//! restored. A denied command, a busy job or a refused switch is not here — those are diagnostics
//! the session itself renders and keeps running.

/// A failure that ends a `marsh --tui` session.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The full-screen interface was asked for without a terminal to draw on.
    #[error("--tui requires a terminal on stdin and stdout")]
    NotATerminal,
    /// The terminal cannot hold a tab bar, one body row and a footer.
    #[error("terminal too small: {rows} rows x {cols} columns (--tui needs at least 4 rows)")]
    TooSmall {
        /// The terminal's height.
        rows: u16,
        /// The terminal's width.
        cols: u16,
    },
    /// Raw mode, the alternate screen or an input mode could not be configured.
    #[error("cannot configure the terminal: {0}")]
    Terminal(#[source] std::io::Error),
    /// The termination signals a session must shut down on could not be registered.
    #[error("cannot listen for termination signals: {0}")]
    Signals(#[source] std::io::Error),
    /// The terminal's input stream failed for a reason that is not end of file.
    #[error("cannot read terminal input: {0}")]
    Input(#[source] std::io::Error),
    /// The environment every job's shell is seeded from could not be built.
    #[error("cannot seed the job environment: {0}")]
    Environment(#[source] brush_core::Error),
    /// The task that opened the session panicked or was cancelled.
    #[error("the session could not be opened: {0}")]
    Startup(#[source] tokio::task::JoinError),
    /// The mux failed. Transparent because `MuxError`'s messages are already whole sentences.
    #[error(transparent)]
    Mux(#[from] shellmux::MuxError),
}
