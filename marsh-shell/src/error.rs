//! Failures that end a marsh session.
//!
//! Everything here is fatal to startup or to the interactive loop; [`crate::entry::run`] prints one
//! as `marsh: {error}` and exits non-zero. A command that merely failed, was denied or lost a race
//! is not here — those are [`shellmux::CmdOutcome`] variants the console renders as verdicts.

/// A failure that ends a marsh session.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A second console was installed over the first, which would mean two consoles competing for
    /// one job table.
    #[error("a console is already installed")]
    ConsoleInstalled,
    /// The instrumentation pipe could not be created.
    #[error("cannot create the instrumentation pipe: {0}")]
    CreateInstrumentation(#[source] std::io::Error),
    /// The instrumentation pipe's read end could not be moved off fd 3.
    #[error("cannot relocate the instrumentation pipe: {0}")]
    RelocateInstrumentation(#[source] std::io::Error),
    /// The instrumentation pipe's write end could not be made inheritable.
    #[error("cannot share the instrumentation pipe: {0}")]
    ShareInstrumentation(#[source] std::io::Error),
    /// The instrumentation pipe's write end could not be placed on fd 3.
    #[error("cannot install the instrumentation pipe: {0}")]
    InstallInstrumentation(#[source] std::io::Error),
    /// The seed containing the current directory could not be located.
    #[error("cannot read the current directory: {0}")]
    Storage(#[source] std::io::Error),
    /// `/dev/tty` could not be opened, so no job could be given the terminal.
    #[error("cannot open /dev/tty: {0}")]
    Terminal(#[source] std::io::Error),
    /// The terminal's suspend character could not be disabled, so Ctrl-Z would still park a job.
    #[error("cannot disable Ctrl-Z suspension: {0}")]
    SuspendKey(#[source] brush_core::Error),
    /// The async runtime could not be started.
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] std::io::Error),
    /// The outer shell could not be built.
    #[error("cannot build the shell: {0}")]
    Shell(#[source] brush_core::Error),
    /// The line editor could not be started.
    #[error("cannot start the line editor: {0}")]
    LineEditor(#[source] brush_interactive::ShellError),
    /// The interactive loop ended in a shell error.
    ///
    /// Transparent because `entry::run` already prefixes `marsh: `; a second prefix would read
    /// `marsh: the interactive loop failed: …`.
    #[error(transparent)]
    Interactive(#[from] brush_interactive::ShellError),
    /// The mux failed. Transparent for the same reason: `MuxError`'s messages are already written
    /// as the whole sentence a user reads.
    #[error(transparent)]
    Mux(#[from] shellmux::MuxError),
}
