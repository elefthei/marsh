//! The wire shapes: what a browser is told about jobs and transactions, and what it may ask for.
//!
//! Separate types rather than serde derives on the mux's own, because those are a public API this
//! crate does not own: a field renamed for a display would be a breaking change to every other
//! embedder. The translation is one way and lossy on purpose — a verdict's captured stdout and
//! stderr are not carried, because a job's bytes already reached the client as they were produced,
//! and a trace log's path names a file on the server's disk that no browser can open.

use serde::{Deserialize, Serialize};
use shellmux::{CapDenial, CmdOutcome, JobView, MuxError, ShellId, ShellMux, StalePath};

/// The directory a spawn request that named none is rooted at: the seed-relative directory the
/// session was opened in, which is what `.` means to a caller that has no other frame of reference.
fn default_dir() -> String {
    ".".to_string()
}

/// One open job, as a client displays it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobDto {
    /// The job's name, which is also the principal its commands request capabilities as.
    pub id: ShellId,
    /// Short id of its snapshot: the routing key for its bytes, since a reused name is a different
    /// job and must not inherit the first one's terminal.
    pub uid: String,
    /// Seed-relative directory its commands start in, `""` for the seed root.
    pub dir: String,
    /// The command in flight, or `null` when the job is idle.
    pub running: Option<RunningDto>,
    /// A command is being launched into it, so it is neither idle nor yet running.
    pub starting: bool,
    /// An accepted stop has closed it: it takes no new command.
    pub closing: bool,
    /// Its last transaction is still merging, so the seed has not caught up with it yet.
    pub merging: bool,
}

/// The command in flight in a job.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningDto {
    /// The command line as submitted.
    pub cmd: String,
    /// Process-group id of the traced command.
    ///
    /// Widened to `i64` because JSON has one number type and `libc::pid_t` is 32 bits on some
    /// targets and not others; a pid always fits.
    pub pid: i64,
}

/// The whole job table and the selection, which is what every client redraws from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobsSnapshot {
    /// Every open job, in the mux's own order.
    pub jobs: Vec<JobDto>,
    /// The selected job, or `null` when the last one closed.
    pub current: Option<ShellId>,
}

/// One capability the policy refused, with the reason and the way out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenialDto {
    /// The refused capability, rendered `principal action resource`.
    ///
    /// A string rather than a structure: [`shellmux::Event`] is the policy's own product type and
    /// its three components each render themselves, which is exactly what the console prints.
    pub event: String,
    /// The precondition it failed, naming the conflicting history.
    pub failed_precondition: String,
    /// State-changing actions that would make the request legal.
    pub allowed_fixes: Vec<String>,
}

/// A path whose contents moved on after the command took its snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaleDto {
    /// Seed-relative, `/`-joined path.
    pub path: String,
    /// Sequence number of the transaction that won the race for it.
    pub merged_seq: u64,
}

/// What became of one submitted command.
///
/// The `error` kind is the one that is not a [`CmdOutcome`]: the mux itself broke while concluding
/// the transaction. It rides here rather than as an HTTP status because the request that started
/// the command was answered long before the verdict existed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutcomeDto {
    /// Capabilities granted and changes merged into the seed.
    Committed {
        /// Sequence number the transaction occupies.
        seq: u64,
        /// Exit status of the command.
        exit_code: i32,
        /// How many capabilities were granted.
        granted: usize,
    },
    /// At least one capability was refused; nothing was committed.
    DeniedCaps {
        /// Exit status of the command, which ran before the merge was refused.
        exit_code: i32,
        /// Every refused capability, with its reason and its fixes.
        denials: Vec<DenialDto>,
    },
    /// Another principal merged one of this command's paths first; it must be rerun.
    StaleSnapshot {
        /// The paths that moved on, and who won them.
        stale: Vec<StaleDto>,
    },
    /// The command itself failed, so it was rolled back wholesale.
    ExecFailed {
        /// Non-zero exit status.
        exit_code: i32,
    },
    /// The command cannot be expressed as capabilities, so it cannot be authorized.
    Unsupported {
        /// What could not be translated.
        reason: String,
    },
    /// The command skipped the sandbox because a prior traced run showed it only reads.
    Bypassed {
        /// Exit status of the command.
        exit_code: i32,
        /// How many reads the policy granted.
        granted: usize,
    },
    /// A command vouched for as read-only did more than read; its effects never reached the seed.
    Escaped {
        /// Exit status of the command.
        exit_code: i32,
        /// Whether the trace showed a write inside the tree it read.
        wrote: bool,
    },
    /// The mux failed while concluding the transaction.
    Error {
        /// What it reported.
        message: String,
    },
}

/// A request to open a new job.
#[derive(Clone, Debug, Deserialize)]
pub struct SpawnRequest {
    /// The name to open it under. Refused when empty, and by the mux when a live job holds it.
    pub id: String,
    /// Where to root it, relative to the current job or absolute from the seed root.
    #[serde(default = "default_dir")]
    pub dir: String,
}

/// A request to run one command in a job.
#[derive(Clone, Debug, Deserialize)]
pub struct StartRequest {
    /// The command line, exactly as typed.
    pub cmd: String,
}

/// A request to change the geometry every job's terminal is at.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ResizeRequest {
    /// New height.
    pub rows: u16,
    /// New width.
    pub cols: u16,
}

/// Whether a stop kills the command in flight instead of waiting for it.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
pub struct ForceQuery {
    /// Kill the job's process group now.
    #[serde(default)]
    pub force: bool,
}

/// One job as a client sees it. `merging` is asked separately because the view does not carry it.
pub fn job_dto(view: &JobView, merging: bool) -> JobDto {
    JobDto {
        id: view.id.clone(),
        uid: view.sandbox.uid.clone(),
        dir: view.sandbox.dir.clone(),
        running: view.running.as_ref().map(|running| RunningDto {
            cmd: running.cmd.clone(),
            pid: i64::from(running.pid),
        }),
        starting: view.starting,
        closing: view.closing,
        merging,
    }
}

/// The whole job table and the selection, read from `mux` in one place so a client's redraw is
/// answered from one pass.
///
/// Not a consistent snapshot, and it does not need to be: the mux publishes
/// [`shellmux::FrontendEvent::Changed`] after every move, so a table read while one was landing is
/// followed by another read.
pub fn snapshot(mux: &ShellMux) -> JobsSnapshot {
    let jobs = mux
        .jobs()
        .iter()
        .map(|view| {
            let merging = mux.is_merging(&view.id);
            job_dto(view, merging)
        })
        .collect();
    JobsSnapshot {
        jobs,
        current: mux.current_job().map(|view| view.id),
    }
}

/// One refused capability, rendered the way the console renders it.
fn denial_dto(denial: &CapDenial) -> DenialDto {
    DenialDto {
        event: format!(
            "{} {} {}",
            denial.event.principal, denial.event.action, denial.event.resource
        ),
        failed_precondition: denial.failed_precondition.clone(),
        allowed_fixes: denial.allowed_fixes.clone(),
    }
}

/// A stale path and the transaction that won it.
fn stale_dto(stale: &StalePath) -> StaleDto {
    StaleDto {
        path: stale.path.clone(),
        merged_seq: stale.merged_seq,
    }
}

/// One transaction's verdict, as a client displays it.
///
/// Captured output is deliberately dropped: a job's stdout and stderr are its pseudoterminal's, and
/// every byte of them already reached the client as `terminal` messages while the command ran.
/// Repeating them under the verdict would print each line twice.
pub fn outcome_dto(outcome: &Result<CmdOutcome, MuxError>) -> OutcomeDto {
    match outcome {
        Ok(CmdOutcome::Committed {
            seq,
            exit_code,
            granted,
            ..
        }) => OutcomeDto::Committed {
            seq: *seq,
            exit_code: *exit_code,
            granted: granted.len(),
        },
        Ok(CmdOutcome::DeniedCaps {
            exit_code, denials, ..
        }) => OutcomeDto::DeniedCaps {
            exit_code: *exit_code,
            denials: denials.iter().map(denial_dto).collect(),
        },
        Ok(CmdOutcome::StaleSnapshot { stale, .. }) => OutcomeDto::StaleSnapshot {
            stale: stale.iter().map(stale_dto).collect(),
        },
        Ok(CmdOutcome::ExecFailed { exit_code, .. }) => OutcomeDto::ExecFailed {
            exit_code: *exit_code,
        },
        Ok(CmdOutcome::Unsupported { reason, .. }) => OutcomeDto::Unsupported {
            reason: reason.clone(),
        },
        Ok(CmdOutcome::Bypassed {
            exit_code, granted, ..
        }) => OutcomeDto::Bypassed {
            exit_code: *exit_code,
            granted: granted.len(),
        },
        Ok(CmdOutcome::Escaped {
            exit_code, wrote, ..
        }) => OutcomeDto::Escaped {
            exit_code: *exit_code,
            wrote: *wrote,
        },
        Err(error) => OutcomeDto::Error {
            message: error.to_string(),
        },
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use shellmux::{Action, Event, Resource, RunningView, Sandbox};

    use super::*;

    /// A job view with `running` set, and its sandbox.
    fn view(id: &str, running: Option<&str>) -> JobView {
        JobView {
            id: ShellId::from(id),
            sandbox: Sandbox {
                id: ShellId::from(id),
                dir: "src".to_string(),
                uid: "ab12cd".to_string(),
            },
            running: running.map(|cmd| RunningView {
                cmd: cmd.to_string(),
                pid: 4321,
            }),
            starting: false,
            closing: false,
        }
    }

    /// The uid is the routing key for a job's bytes, so it has to be on the wire beside the name:
    /// a client that keyed a terminal by name alone would feed a reused name's output into its
    /// predecessor's scrollback.
    #[test]
    fn a_job_carries_its_uid_and_its_running_command() {
        let dto = job_dto(&view("main", Some("sleep 5")), true);
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["id"], "main");
        assert_eq!(json["uid"], "ab12cd");
        assert_eq!(json["dir"], "src");
        assert_eq!(json["running"]["cmd"], "sleep 5");
        assert_eq!(json["running"]["pid"], 4321);
        assert_eq!(json["merging"], true);
    }

    /// An idle job's `running` is null rather than absent: a client distinguishes the two by
    /// reading one field, not by asking whether a key exists.
    #[test]
    fn an_idle_job_reports_a_null_command() {
        let json = serde_json::to_value(job_dto(&view("1", None), false)).unwrap();
        assert!(json["running"].is_null());
        assert_eq!(json["merging"], false);
    }

    /// A commit reports where it landed and how much it was granted — not the output it captured,
    /// which the client already has.
    #[test]
    fn a_commit_reports_its_sequence_and_grant_count() {
        let outcome = Ok(CmdOutcome::Committed {
            seq: 42,
            exit_code: 0,
            stdout: b"hello".to_vec(),
            stderr: Vec::new(),
            granted: vec![
                Event::new("main", Action::Edit, Resource::from(vec!["a.txt"])),
                Event::new("main", Action::Stage, Resource::from(vec!["a.txt"])),
            ],
            trace_log: PathBuf::from("/state/trace.log"),
        });
        let json = serde_json::to_value(outcome_dto(&outcome)).unwrap();
        assert_eq!(json["kind"], "committed");
        assert_eq!(json["seq"], 42);
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["granted"], 2);
        assert!(json.get("stdout").is_none());
        assert!(json.get("trace_log").is_none());
    }

    /// A denial is only actionable if it names the capability, the precondition and the way out.
    #[test]
    fn a_denial_renders_its_capability_precondition_and_fixes() {
        let outcome = Ok(CmdOutcome::DeniedCaps {
            exit_code: 1,
            stdout: Vec::new(),
            stderr: Vec::new(),
            requested: vec![Event::new(
                "main",
                Action::Stage,
                Resource::from(vec!["a.txt"]),
            )],
            denials: vec![CapDenial {
                event: Event::new("main", Action::Stage, Resource::from(vec!["a.txt"])),
                failed_precondition: "no edit precedes the stage".to_string(),
                allowed_fixes: vec!["edit a.txt".to_string()],
            }],
            trace_log: PathBuf::from("/state/trace.log"),
        });
        let json = serde_json::to_value(outcome_dto(&outcome)).unwrap();
        assert_eq!(json["kind"], "denied_caps");
        assert_eq!(json["exit_code"], 1);
        assert_eq!(json["denials"][0]["event"], "main stage a.txt");
        assert_eq!(
            json["denials"][0]["failed_precondition"],
            "no edit precedes the stage"
        );
        assert_eq!(json["denials"][0]["allowed_fixes"][0], "edit a.txt");
    }

    /// A stale snapshot names the paths that moved on and who won them, because that is what tells
    /// a reader whether rerunning is enough.
    #[test]
    fn a_stale_snapshot_names_the_paths_that_moved_on() {
        let outcome = Ok(CmdOutcome::StaleSnapshot {
            requested: Vec::new(),
            stale: vec![StalePath {
                path: "src/x".to_string(),
                merged_seq: 7,
            }],
            trace_log: PathBuf::from("/state/trace.log"),
        });
        let json = serde_json::to_value(outcome_dto(&outcome)).unwrap();
        assert_eq!(json["kind"], "stale_snapshot");
        assert_eq!(json["stale"][0]["path"], "src/x");
        assert_eq!(json["stale"][0]["merged_seq"], 7);
    }

    /// A mux failure is a verdict on the socket, not an HTTP status: the request that started the
    /// command was answered before the conclusion existed.
    #[test]
    fn a_conclusion_failure_becomes_an_error_verdict() {
        let outcome = Err(MuxError::Wal("log is truncated".to_string()));
        let json = serde_json::to_value(outcome_dto(&outcome)).unwrap();
        assert_eq!(json["kind"], "error");
        assert_eq!(json["message"], "write-ahead log failure: log is truncated");
    }

    /// A spawn with no directory is rooted where the session is, so the common request carries one
    /// field.
    #[test]
    fn a_spawn_request_defaults_its_directory() {
        let request: SpawnRequest = serde_json::from_str(r#"{"id":"1"}"#).unwrap();
        assert_eq!(request.id, "1");
        assert_eq!(request.dir, ".");
    }
}
