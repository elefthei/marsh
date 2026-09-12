//! Failures that end a marsh-rest session.
//!
//! Everything here is fatal to startup or to the server; [`crate::entry::run`] prints one as
//! `marsh-rest: {error}` and exits non-zero. A command that merely failed, was denied or lost a
//! race is not here — those are [`shellmux::CmdOutcome`] variants, and they reach clients as the
//! `finished` message on the event socket rather than as an HTTP status.

/// A failure that ends a marsh-rest session.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The seed containing the current directory could not be located.
    #[error("cannot read the current directory: {0}")]
    Storage(#[source] std::io::Error),
    /// The listening socket could not be taken.
    #[error("cannot bind {addr}: {source}")]
    Bind {
        /// The address that was asked for.
        addr: std::net::SocketAddr,
        /// Why the kernel refused it.
        #[source]
        source: std::io::Error,
    },
    /// The server stopped on an error rather than on its shutdown signal.
    #[error("server failed: {0}")]
    Serve(#[source] std::io::Error),
    /// The async runtime could not be started.
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] std::io::Error),
    /// The mux failed. Transparent because `entry::run` already prefixes `marsh-rest: `, and
    /// `MuxError`'s messages are already written as the whole sentence a user reads.
    #[error(transparent)]
    Mux(#[from] shellmux::MuxError),
}
