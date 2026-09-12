//! The mux's view of a marsh-rest session: every observation, turned into one published message.
//!
//! The frontend holds no display state at all — no scrollback, no line buffers, no per-job caches.
//! It cannot: there is no one display to hold them for. Any number of browsers may be attached,
//! each with its own xterm emulator and its own idea of what it has already seen, so the only thing
//! this side can be is a *fan-out point* — every event becomes one owned message on a broadcast
//! channel, and what to remember is the client's problem.
//!
//! That is also why every callback here is trivially short, which the mux contract requires:
//! encoding a chunk and pushing it into a channel is the whole of the work, and
//! [`broadcast::Sender::send`] never blocks and never awaits. A send that fails — nobody attached —
//! is dropped, because a session with no browser on it is a session that keeps running.

use std::sync::{Arc, Weak};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use shellmux::{FrontendBinding, FrontendEvent, MarshFrontend, ShellId, ShellMux, Spawned};
use tokio::sync::broadcast;

use crate::dto::{JobsSnapshot, OutcomeDto, outcome_dto, snapshot};

/// How many published messages a slow client may fall behind by before it is resynchronized.
///
/// Terminal output is the reason this is not small: one command producing pages of text delivers
/// one message per read, and a client that lags loses those bytes for good — the mux does not
/// replay them. Falling behind is still survivable, because a lagging socket answers with a fresh
/// job snapshot rather than a desynchronized stream, but it shows as a gap in a scrollback.
const EVENT_CAPACITY: usize = 1024;

/// One observation, as it reaches a browser.
///
/// Owned rather than borrowed: the mux's data is valid only for the length of a callback, and this
/// is published to readers that run later, on other tasks.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The job table or the selection moved on. Also the socket's greeting, so a client that just
    /// connected draws from the same message a running one redraws from.
    Jobs(JobsSnapshot),
    /// Bytes a job's terminal produced, base64 because a chunk may split a UTF-8 sequence.
    Terminal {
        /// The job that produced them.
        job: ShellId,
        /// Its sandbox uid: the routing key, so a reused name never mixes two jobs' output.
        uid: String,
        /// The chunk, base64-encoded.
        data: String,
    },
    /// Bytes a job's instrumentation stream — fd 3 of each of its commands — produced.
    Instrumentation {
        /// The job that produced them.
        job: ShellId,
        /// Its sandbox uid.
        uid: String,
        /// The chunk, base64-encoded.
        data: String,
    },
    /// A command ended and its transaction was concluded. The job stays open.
    Finished {
        /// The job whose command ended.
        job: ShellId,
        /// Exit status of the command, in the shell's convention; `-1` for a launch that never
        /// produced one.
        exit_code: i32,
        /// What the transaction turned out to be.
        outcome: OutcomeDto,
    },
    /// A job's streams are over and its storage is reclaimed.
    Closed {
        /// The job that closed.
        job: ShellId,
        /// The sandbox that closed, which may not be the one the name now refers to.
        uid: String,
    },
    /// The mux accepted a new geometry, and every job's terminal was set to it.
    Resized {
        /// New height.
        rows: u16,
        /// New width.
        cols: u16,
    },
    /// Reading one of a job's streams failed. That stream is over; the job is not.
    IoError {
        /// The job whose stream failed.
        job: ShellId,
        /// What the read reported.
        message: String,
    },
}

/// What a browser sends on the socket.
///
/// Input only, and deliberately so: it is the one thing with no reply, no status and no ordering
/// against anything else. Every action that *has* an answer — spawning, starting, selecting,
/// stopping, resizing — is a REST call, so its failure is a status code rather than a message a
/// client has to correlate.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Raw keystrokes for a job's terminal, base64-encoded for the same reason output is.
    Input {
        /// The job to write them to.
        job: ShellId,
        /// The bytes, base64-encoded.
        data: String,
    },
}

/// The mux's frontend for a marsh-rest session: a publisher, and the binding the contract dictates.
pub struct RestFrontend {
    /// Geometry, mux binding and live handles: the part of this frontend the mux contract
    /// dictates.
    binding: FrontendBinding,
    /// Where every observation goes. Kept even with no subscribers, because a browser may attach
    /// at any time and the channel is what it attaches to.
    events: broadcast::Sender<ServerMessage>,
}

impl RestFrontend {
    /// A receiver for everything published from now on.
    ///
    /// History is not replayed: a socket that just opened is sent a job snapshot instead, which is
    /// the state a display actually needs. Scrollback from before it connected is not this side's
    /// to keep.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ServerMessage> {
        self.events.subscribe()
    }

    /// The handle for `id`, if this session still holds one: what input is written through.
    #[must_use]
    pub fn handle(&self, id: &ShellId) -> Option<Spawned> {
        self.binding.handle(id)
    }

    /// The bound mux, or `None` while unbound or after shutdown.
    #[must_use]
    pub fn mux(&self) -> Option<Arc<ShellMux>> {
        self.binding.mux()
    }

    /// Publishes one message, ignoring a send with no receivers.
    ///
    /// The error case is a session nobody is looking at, which is not a failure: jobs keep running
    /// with every browser closed, and the next socket to open is told the state rather than the
    /// history.
    fn publish(&self, message: ServerMessage) {
        let _ = self.events.send(message);
    }
}

impl MarshFrontend for RestFrontend {
    fn new(rows: u16, cols: u16) -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            binding: FrontendBinding::new(rows, cols),
            events,
        }
    }

    fn size(&self) -> (u16, u16) {
        self.binding.size()
    }

    fn bind(&mut self, mux: Weak<ShellMux>) {
        self.binding.bind(mux);
    }

    /// Every observation, published as one message.
    ///
    /// [`FrontendEvent::Opened`] publishes nothing of its own: `observe` has already installed the
    /// handle input is written through, and the [`FrontendEvent::Changed`] that accompanies an
    /// opened job is what tells clients the table grew. Sending both would make a tab appear twice.
    fn update(&mut self, event: FrontendEvent<'_>) {
        self.binding.observe(event);
        match event {
            FrontendEvent::Changed => {
                // A sanctioned synchronous read: the callback runs under no mux lock, and the
                // event carries no state precisely so that the answer is read here and now.
                if let Some(mux) = self.binding.mux() {
                    self.publish(ServerMessage::Jobs(snapshot(&mux)));
                }
            }
            FrontendEvent::Opened(_) => {}
            FrontendEvent::Terminal { shell, bytes } => {
                self.publish(ServerMessage::Terminal {
                    job: shell.id.clone(),
                    uid: shell.uid.clone(),
                    data: BASE64.encode(bytes),
                });
            }
            FrontendEvent::Instrumentation { shell, bytes } => {
                self.publish(ServerMessage::Instrumentation {
                    job: shell.id.clone(),
                    uid: shell.uid.clone(),
                    data: BASE64.encode(bytes),
                });
            }
            FrontendEvent::Finished {
                shell,
                exit_code,
                outcome,
            } => {
                self.publish(ServerMessage::Finished {
                    job: shell.id.clone(),
                    exit_code,
                    outcome: outcome_dto(outcome),
                });
            }
            FrontendEvent::Closed(shell) => {
                self.publish(ServerMessage::Closed {
                    job: shell.id.clone(),
                    uid: shell.uid.clone(),
                });
            }
            FrontendEvent::Resized { rows, cols } => {
                self.publish(ServerMessage::Resized { rows, cols });
            }
            FrontendEvent::IoError { shell, error } => {
                self.publish(ServerMessage::IoError {
                    job: shell.id.clone(),
                    message: error.to_string(),
                });
            }
        }
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use shellmux::{CmdOutcome, Sandbox};

    use super::*;

    /// A sandbox to attribute synthetic events to.
    fn sandbox(id: &str, uid: &str) -> Sandbox {
        Sandbox {
            id: ShellId::from(id),
            dir: String::new(),
            uid: uid.to_string(),
        }
    }

    /// A full-screen program's output is not text: it carries escape sequences and it may be cut
    /// mid-UTF-8 wherever the read ended. What arrives at a browser has to be the same bytes.
    #[test]
    fn terminal_bytes_survive_the_wire_exactly() {
        let mut frontend = RestFrontend::new(24, 80);
        let mut events = frontend.subscribe();
        let shell = sandbox("main", "ab12cd");
        // A cursor-position escape, then the leading two bytes of a three-byte character: the
        // chunk boundary a text encoding would destroy.
        let bytes = [0x1b, b'[', b'2', b'J', 0xe2, 0x82];

        frontend.update(FrontendEvent::Terminal {
            shell: &shell,
            bytes: &bytes,
        });

        match events.try_recv().unwrap() {
            ServerMessage::Terminal { job, uid, data } => {
                assert_eq!(job, ShellId::from("main"));
                assert_eq!(uid, "ab12cd");
                assert_eq!(BASE64.decode(data).unwrap(), bytes);
            }
            other => panic!("expected terminal bytes, got {other:?}"),
        }
    }

    /// A verdict reaches clients on the socket, because the request that started the command was
    /// answered long before the transaction concluded.
    #[test]
    fn a_concluded_transaction_publishes_its_verdict() {
        let mut frontend = RestFrontend::new(24, 80);
        let mut events = frontend.subscribe();
        let shell = sandbox("main", "ab12cd");
        let outcome = Arc::new(Ok(CmdOutcome::Committed {
            seq: 7,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            granted: Vec::new(),
            trace_log: std::path::PathBuf::from("/state/trace.log"),
        }));

        frontend.update(FrontendEvent::Finished {
            shell: &shell,
            exit_code: 0,
            outcome: &outcome,
        });

        match events.try_recv().unwrap() {
            ServerMessage::Finished {
                job,
                exit_code,
                outcome,
            } => {
                assert_eq!(job, ShellId::from("main"));
                assert_eq!(exit_code, 0);
                assert_eq!(
                    outcome,
                    OutcomeDto::Committed {
                        seq: 7,
                        exit_code: 0,
                        granted: 0
                    }
                );
            }
            other => panic!("expected a verdict, got {other:?}"),
        }
    }

    /// A stream failing is reported and nothing else: the job it belonged to is still open, so a
    /// client must not remove its tab.
    #[test]
    fn a_stream_failure_is_reported_without_closing_the_job() {
        let mut frontend = RestFrontend::new(24, 80);
        let mut events = frontend.subscribe();
        let shell = sandbox("build", "ff99ee");
        let error = std::io::Error::from(std::io::ErrorKind::BrokenPipe);

        frontend.update(FrontendEvent::IoError {
            shell: &shell,
            error: &error,
        });

        match events.try_recv().unwrap() {
            ServerMessage::IoError { job, message } => {
                assert_eq!(job, ShellId::from("build"));
                assert!(!message.is_empty());
            }
            other => panic!("expected a stream failure, got {other:?}"),
        }
        assert!(events.try_recv().is_err());
    }

    /// The frontend answers `size` from the binding, and a resize moves it: `ShellMux::new` reads
    /// that geometry to open every pseudoterminal, so a stale one renders every job wrongly.
    #[test]
    fn a_resize_moves_the_geometry_and_tells_every_client() {
        let mut frontend = RestFrontend::new(24, 80);
        let mut events = frontend.subscribe();

        assert_eq!(frontend.size(), (24, 80));
        frontend.update(FrontendEvent::Resized {
            rows: 50,
            cols: 120,
        });

        assert_eq!(frontend.size(), (50, 120));
        match events.try_recv().unwrap() {
            ServerMessage::Resized { rows, cols } => {
                assert_eq!((rows, cols), (50, 120));
            }
            other => panic!("expected a resize, got {other:?}"),
        }
    }

    /// A session with no browser attached keeps running: publishing into a channel nobody holds is
    /// not a failure, and the mux's pump must not be stalled by one.
    #[test]
    fn publishing_with_no_client_attached_is_not_a_failure() {
        let mut frontend = RestFrontend::new(24, 80);
        let shell = sandbox("main", "ab12cd");

        frontend.update(FrontendEvent::Terminal {
            shell: &shell,
            bytes: b"hello",
        });

        // And a client attaching afterwards still gets everything from that point on.
        let mut events = frontend.subscribe();
        frontend.update(FrontendEvent::Resized { rows: 10, cols: 20 });
        assert!(matches!(
            events.try_recv().unwrap(),
            ServerMessage::Resized { rows: 10, cols: 20 }
        ));
    }

    /// An unbound frontend has no job table to read, so a change it cannot answer publishes
    /// nothing rather than an empty table that would blank every client's tabs.
    #[test]
    fn a_change_with_no_mux_bound_publishes_nothing() {
        let mut frontend = RestFrontend::new(24, 80);
        let mut events = frontend.subscribe();

        frontend.update(FrontendEvent::Changed);

        assert!(events.try_recv().is_err());
    }

    /// Input is addressed by job name and carries bytes, not text.
    #[test]
    fn an_input_frame_parses_into_bytes() {
        let frame = r#"{"type":"input","job":"main","data":"aGVsbG8K"}"#;
        let ClientMessage::Input { job, data } = serde_json::from_str(frame).unwrap();
        assert_eq!(job, ShellId::from("main"));
        assert_eq!(BASE64.decode(data).unwrap(), b"hello\n");
    }
}
