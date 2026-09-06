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
    /// The child-watch pipe could not be created.
    #[error("cannot create the child-watch pipe: {0}")]
    CreateChildWatch(#[source] std::io::Error),
    /// The child-watch pipe's write end could not be made non-blocking.
    #[error("cannot configure the child-watch pipe: {0}")]
    ConfigureChildWatch(#[source] std::io::Error),
    /// `/dev/tty` could not be opened, so no job could be given the terminal.
    #[error("cannot open /dev/tty: {0}")]
    Terminal(#[source] std::io::Error),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The two transparent variants must add nothing: `entry::run` already writes the `marsh: `
    /// prefix, and a second one would read `marsh: the mux failed: no btrfs subvolume …`.
    #[test]
    fn wrapping_a_mux_failure_changes_nothing_about_its_message() {
        let inner = shellmux::MuxError::Exec("no strace".to_string());
        let message = inner.to_string();
        assert_eq!(Error::from(inner).to_string(), message);
    }

    /// A wrapped source is named in the message, because the bare OS error ("Too many open files")
    /// says nothing about which pipe failed.
    #[test]
    fn a_pipe_failure_names_the_pipe_and_the_step() {
        let error = Error::CreateChildWatch(std::io::Error::from_raw_os_error(libc::EMFILE));
        assert!(
            error
                .to_string()
                .starts_with("cannot create the child-watch pipe: "),
            "{error}"
        );
    }
}
