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
//! Composition: [`MarshFrontendJoin`] puts two frontends over one mux and delivers every event to
//! both; an `Arc<Mutex<F>>` is itself a frontend, for a display its owner keeps reaching after
//! handing it to a join; [`FrontendBinding`] is the state the contract makes every display keep.
//!
//! Every callback is synchronous and short, and its borrowed data is valid only until it returns.
//! None of them runs under a job-table, merge, authority or background-task lock, so a callback may
//! queue work with Tokio — but it must not synchronously reenter a mutating mux method, and the
//! frontend's own mutex must be released before awaiting one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use crate::error::MuxError;
use crate::jobs::{ShellId, Spawned};
use crate::mux::{CmdOutcome, Sandbox, ShellMux};

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
#[derive(Clone, Copy, Debug)]
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
    /// Delivered exactly once per command, an asynchronous launch failure included — that failure
    /// reports an `exit_code` of `-1`. It does not mean the job closed: a job outlives the commands
    /// that run in it.
    Finished {
        /// The job whose command ended; its `id` is the principal the transaction was decided for.
        shell: &'a Sandbox,
        /// Exit status of the command, in the shell's convention.
        exit_code: i32,
        /// What the transaction turned out to be.
        ///
        /// Shared rather than borrowed by value, because a frontend that records outcomes keeps
        /// them past the callback and neither [`CmdOutcome`] nor [`MuxError`] is cloneable.
        outcome: &'a Arc<Result<CmdOutcome, MuxError>>,
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

/// The mux-facing state the contract makes every frontend keep, so a display implements only its
/// rendering: the geometry, the binding, and the live handle per job name.
///
/// Handles are kept by name because that is what a UI resolves, and replaced wholesale when a name
/// is opened again; a [`FrontendEvent::Closed`] drops a handle only when its sandbox is the one
/// closing, because a name reopened while the old job was still draining belongs to the new job.
pub struct FrontendBinding {
    /// Rows first: what it was built with, then whatever the last [`FrontendEvent::Resized`] said.
    size: (u16, u16),
    /// The mux delivering to this frontend; empty before binding and again after shutdown.
    mux: Weak<ShellMux>,
    /// The current handle per job name, for input forwarding.
    handles: HashMap<ShellId, Spawned>,
}

impl FrontendBinding {
    /// A binding to no mux yet, at `rows` × `cols`.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            size: (rows, cols),
            mux: Weak::new(),
            handles: HashMap::new(),
        }
    }

    /// The geometry, rows first.
    #[must_use]
    pub const fn size(&self) -> (u16, u16) {
        self.size
    }

    /// The bound mux, or `None` while unbound or after shutdown.
    #[must_use]
    pub fn mux(&self) -> Option<Arc<ShellMux>> {
        self.mux.upgrade()
    }

    /// Whether a live mux is bound.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.mux.strong_count() > 0
    }

    /// The handle for `id`, if one is held.
    #[must_use]
    pub fn handle(&self, id: &ShellId) -> Option<Spawned> {
        self.handles.get(id).cloned()
    }

    /// Binds to `mux`, or detaches on an empty weak reference — releasing every handle, since a
    /// retained one would keep a pseudoterminal master open past the session.
    pub fn bind(&mut self, mux: Weak<ShellMux>) {
        self.mux = mux;
        if !self.is_bound() {
            self.handles.clear();
        }
    }

    /// Keeps the geometry and the handle table current. Every other event is the display's alone.
    pub fn observe(&mut self, event: FrontendEvent<'_>) {
        match event {
            FrontendEvent::Opened(spawned) => {
                self.handles.insert(spawned.id.clone(), spawned.clone());
            }
            FrontendEvent::Closed(shell) => {
                if self
                    .handles
                    .get(&shell.id)
                    .is_some_and(|held| held.sandbox.uid == shell.uid)
                {
                    self.handles.remove(&shell.id);
                }
            }
            FrontendEvent::Resized { rows, cols } => self.size = (rows, cols),
            FrontendEvent::Changed
            | FrontendEvent::Terminal { .. }
            | FrontendEvent::Instrumentation { .. }
            | FrontendEvent::Finished { .. }
            | FrontendEvent::IoError { .. } => {}
        }
    }
}

/// A frontend another owner keeps reaching after it was handed to a [`MarshFrontendJoin`].
///
/// The console holds its `Arc<Mutex<ConsoleFrontend>>` for input forwarding while the join the mux
/// delivers through holds a clone. Lock order is fixed: the mux takes the join's own mutex and
/// then this one, the owner takes only this one, so the two never wait on each other in a cycle.
/// Poisoning is recovered like everywhere else in this crate.
impl<F: MarshFrontend> MarshFrontend for Arc<Mutex<F>> {
    fn new(rows: u16, cols: u16) -> Self {
        // `Self::from`, not `Self::new`: the latter is this very method.
        Self::from(Mutex::new(F::new(rows, cols)))
    }

    fn size(&self) -> (u16, u16) {
        self.lock().unwrap_or_else(PoisonError::into_inner).size()
    }

    fn bind(&mut self, mux: Weak<ShellMux>) {
        self.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bind(mux);
    }

    fn update(&mut self, event: FrontendEvent<'_>) {
        self.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .update(event);
    }
}

/// Two frontends over one mux: a terminal and a browser session bound to the same jobs.
///
/// Every event reaches the left side and then the right; both bind to the same mux, so either
/// drives it through its own binding and the other sees the result as a [`FrontendEvent`]. A third
/// display nests: `MarshFrontendJoin<A, MarshFrontendJoin<B, C>>`. Sides a caller must go on
/// reaching are `Arc<Mutex<F>>` leaves.
///
/// The geometry is the one both displays fit — the smaller of each dimension — because a job
/// rendered wider or taller than one of its displays garbles there. Later resizes are the mux's:
/// [`ShellMux::resize`] applies whatever geometry it is last given, and both sides are told.
pub struct MarshFrontendJoin<L: MarshFrontend, R: MarshFrontend> {
    /// The side told first.
    pub left: L,
    /// The side told second.
    pub right: R,
}

impl<L: MarshFrontend, R: MarshFrontend> MarshFrontend for MarshFrontendJoin<L, R> {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            left: L::new(rows, cols),
            right: R::new(rows, cols),
        }
    }

    fn size(&self) -> (u16, u16) {
        let (left_rows, left_cols) = self.left.size();
        let (right_rows, right_cols) = self.right.size();
        (left_rows.min(right_rows), left_cols.min(right_cols))
    }

    fn bind(&mut self, mux: Weak<ShellMux>) {
        self.left.bind(mux.clone());
        self.right.bind(mux);
    }

    fn update(&mut self, event: FrontendEvent<'_>) {
        self.left.update(event);
        self.right.update(event);
    }
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

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A frontend that only records what it was told, so a join's fan-out is observable.
    struct Probe {
        /// What this side was told, in order: `"bind"`, `"detach"`, or an event's debug form.
        log: Vec<String>,
        /// Its geometry, which a [`FrontendEvent::Resized`] moves.
        size: (u16, u16),
    }

    impl MarshFrontend for Probe {
        fn new(rows: u16, cols: u16) -> Self {
            Self {
                log: Vec::new(),
                size: (rows, cols),
            }
        }

        fn size(&self) -> (u16, u16) {
            self.size
        }

        fn bind(&mut self, mux: Weak<ShellMux>) {
            self.log.push(
                if mux.strong_count() > 0 {
                    "bind"
                } else {
                    "detach"
                }
                .to_string(),
            );
        }

        fn update(&mut self, event: FrontendEvent<'_>) {
            self.log.push(format!("{event:?}"));
            if let FrontendEvent::Resized { rows, cols } = event {
                self.size = (rows, cols);
            }
        }
    }

    /// The log of a shared probe.
    fn log(probe: &Arc<Mutex<Probe>>) -> Vec<String> {
        probe
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .log
            .clone()
    }

    /// Both displays are told everything, in one order, and neither is rendered larger than it is:
    /// a job drawn wider than one side would garble there.
    #[test]
    fn a_join_delivers_every_event_to_both_sides() {
        let left: Arc<Mutex<Probe>> = MarshFrontend::new(24, 200);
        let right: Arc<Mutex<Probe>> = MarshFrontend::new(50, 80);
        let mut join = MarshFrontendJoin {
            left: Arc::clone(&left),
            right: Arc::clone(&right),
        };

        assert_eq!(join.size(), (24, 80));

        let shell = Sandbox {
            id: ShellId::from("a"),
            dir: String::new(),
            uid: "u1".to_string(),
        };
        let terminal = FrontendEvent::Terminal {
            shell: &shell,
            bytes: b"x",
        };
        join.bind(Weak::new());
        join.update(terminal);
        join.update(FrontendEvent::Changed);
        join.update(FrontendEvent::Resized { rows: 10, cols: 20 });

        let expected = vec![
            "detach".to_string(),
            format!("{terminal:?}"),
            "Changed".to_string(),
            "Resized { rows: 10, cols: 20 }".to_string(),
        ];
        assert_eq!(log(&left), expected);
        assert_eq!(log(&right), expected);
        assert_eq!(join.size(), (10, 20));
    }

    /// Built by the trait, a join is two displays at the geometry the mux was given.
    #[test]
    fn new_builds_both_sides_at_one_geometry() {
        let join = MarshFrontendJoin::<Probe, Probe>::new(7, 9);
        assert_eq!(join.left.size(), (7, 9));
        assert_eq!(join.right.size(), (7, 9));
        assert_eq!(join.size(), (7, 9));
    }
}
