//! The user interface one mux delivers to, and the observations it delivers.
//!
//! A frontend is a rows-by-columns display over however many jobs the mux owns: a CLI writing one
//! job's bytes to the real terminal, a full-screen tab bar, a browser session. It is *given* to
//! [`ShellMux::new`] rather than built by it, because the geometry the mux opens every
//! pseudoterminal at is the frontend's own ([`MarshFrontend::size`]), and because a frontend that
//! could not exist before the mux did would have nowhere to render the mux's construction failure.
//!
//! The traffic is one-way. Everything a frontend *observes* arrives as a [`FrontendEvent`];
//! everything a frontend *does* is an ordinary mux call on the [`Weak<ShellMux>`] it was bound to:
//!
//! | UI action | Mux call |
//! |---|---|
//! | Add a shell | [`ShellMux::spawn`] |
//! | Remove a shell | [`ShellMux::stop`] with `force` |
//! | Graceful close | [`ShellMux::stop`] without it |
//! | Select a tab | [`ShellMux::switch`] |
//! | Submit a command line | [`ShellMux::start_in`] |
//! | Raw input, terminal reply | [`ShellMux::write_input`] |
//! | Resize | [`ShellMux::resize`] |
//!
//! There is no second controller and no snapshot type: [`FrontendEvent::Changed`] says the display
//! is out of date, and [`ShellMux::jobs`], [`ShellMux::current_job`] and [`ShellMux::is_merging`]
//! answer what it is now.
//!
//! Every callback is synchronous and short, and its borrowed data is valid only until it returns.
//! None of them runs under a job-table, merge, authority or background-task lock, so a callback may
//! queue work with Tokio — but it must not synchronously reenter a mutating mux method, and the
//! frontend's own mutex must be released before awaiting one.

use std::sync::{Mutex, MutexGuard, PoisonError, Weak};

use crate::jobs::{Reaped, Spawned};
use crate::mux::{Sandbox, ShellMux};

/// A user interface over the jobs one [`ShellMux`] owns.
///
/// Passed to [`ShellMux::new`] as an `Arc<Mutex<V>>`, which is what lets the frontend be driven
/// from the embedding application and from the mux's own byte pumps without either waiting on the
/// other for longer than one callback.
pub trait MarshFrontend: Send + 'static {
    /// A frontend for a terminal of `rows` × `cols`.
    ///
    /// Rows before columns, in that order, everywhere in this crate.
    fn new(rows: u16, cols: u16) -> Self
    where
        Self: Sized;

    /// The geometry every job's pseudoterminal is opened at, rows first.
    ///
    /// Read once by [`ShellMux::new`], before any storage is materialized: a geometry with a zero
    /// dimension is refused there, exactly as [`ShellMux::resize`] refuses one later.
    fn size(&self) -> (u16, u16);

    /// Binds this frontend to the mux that will deliver to it, or detaches it.
    ///
    /// A [`Weak`] rather than a strong reference, because the frontend outlives the mux by
    /// construction: the caller holds the original `Arc<Mutex<V>>`. An empty weak reference means
    /// detached, and a failed [`upgrade`](Weak::upgrade) is an absent session rather than an error.
    ///
    /// On detach a frontend releases the live [`Spawned`] handles and per-session buffers it holds;
    /// a recorder may keep its historical observations.
    fn bind(&mut self, mux: Weak<ShellMux>);

    /// Delivers one observation.
    fn update(&mut self, event: FrontendEvent<'_>);
}

/// One observation a mux delivers to its frontend.
///
/// Everything borrowed is the mux's and is valid only for the length of the call.
#[derive(Debug)]
pub enum FrontendEvent<'a> {
    /// The job table, the selection or a merge moved on, so the display is out of date.
    ///
    /// Carries no state: [`ShellMux::jobs`], [`ShellMux::current_job`] and
    /// [`ShellMux::is_merging`] are what a frontend reads afterwards, and a queued snapshot would
    /// only be a second, staler answer to the same question.
    Changed,
    /// A job is open, with the handle its input and its waits go through.
    ///
    /// Delivered once the job's terminal, shell and instrumentation pipe are published and its
    /// geometry is settled, and before any command the job was opened for is launched.
    Opened(&'a Spawned),
    /// Bytes a job's terminal produced: the merged stdout, stderr and echo of its pseudoterminal.
    ///
    /// A chunk, not a line and not text: it may split a UTF-8 sequence or an escape sequence, and
    /// preserving it byte for byte is what makes a full-screen program work.
    Terminal {
        /// The job that produced them, identified by [`Sandbox::uid`] rather than by name, so a
        /// reused name never mixes two jobs' contents.
        shell: &'a Sandbox,
        /// The bytes, exactly as they were read.
        bytes: &'a [u8],
    },
    /// Bytes a job's instrumentation stream produced: fd 3 of every command it runs.
    ///
    /// A separate stream from the terminal on purpose, and chunked for the same reason.
    Instrumentation {
        /// The job that produced them.
        shell: &'a Sandbox,
        /// The bytes, exactly as they were read.
        bytes: &'a [u8],
    },
    /// A command in a job ended, and its transaction was concluded.
    ///
    /// Delivered exactly once per command, an asynchronous launch failure included. It does not
    /// mean the job closed: a job outlives the commands that run in it.
    Reaped {
        /// The job whose command ended.
        shell: &'a Sandbox,
        /// What the wait observed.
        result: &'a Reaped,
    },
    /// A job's streams are over and its storage is reclaimed: the handle for it is now dead.
    Closed(&'a Sandbox),
    /// The mux accepted a new geometry, and every job's terminal was set to it.
    Resized {
        /// New height.
        rows: u16,
        /// New width.
        cols: u16,
    },
    /// Reading one of a job's streams failed for a reason that is not end of file.
    ///
    /// That stream is over; the job is not.
    IoError {
        /// The job whose stream failed.
        shell: &'a Sandbox,
        /// What the read reported.
        error: &'a std::io::Error,
    },
}

/// Delivers `event` to `frontend`, recovering a poisoned lock like the rest of this crate.
///
/// A frontend that panicked in one callback left the mux's own state untouched, and refusing to
/// deliver to it afterwards would silently stop a session that is otherwise still running.
pub(crate) fn notify(frontend: &Mutex<dyn MarshFrontend>, event: FrontendEvent<'_>) {
    let mut guard = frontend.lock().unwrap_or_else(PoisonError::into_inner);
    guard.update(event);
    drop(guard);
}

/// The frontend, with the same poisoning recovery as [`notify`].
///
/// For the two places that need more than one call under one guard: binding a fresh mux and
/// announcing its first state, and detaching at shutdown.
pub(crate) fn lock_frontend(
    frontend: &Mutex<dyn MarshFrontend>,
) -> MutexGuard<'_, dyn MarshFrontend> {
    frontend.lock().unwrap_or_else(PoisonError::into_inner)
}
