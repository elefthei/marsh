//! The capability history the policy decides from.
//!
//! This log is **not** provenance or debugging. `GitPolicy::decide(history, candidate)` takes the
//! accumulated history as its input, which is how "another principal already owns this path"
//! denials exist at all: drop the log and a restart forgets who owns what, so a command denied
//! before a restart is granted after it. One appended line per merge, one read at startup.

use std::collections::{HashMap, HashSet};

use rust_validator::{Action, Event, Resource};
use serde::{Deserialize, Serialize};

use crate::diff::CommitOp;
use crate::error::MuxError;
use crate::session::Session;
use crate::wal::JsonLog;

/// Log file name under the session's `meta/` directory.
const HISTORY_FILE: &str = "history.jsonl";

/// One committed transaction, as the authority remembers it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HistoryRecord {
    /// Merge sequence number.
    pub seq: u64,
    /// The principal it was granted to.
    pub principal: String,
    /// The command line.
    pub cmd: String,
    /// The capabilities granted.
    pub events: Vec<HistoryEvent>,
    /// Seed-relative paths this transaction wrote, which become staleness generations.
    pub paths: Vec<String>,
}

/// Serializable form of a capability event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HistoryEvent {
    /// Principal that requested the capability.
    principal: String,
    /// Requested action.
    action: HistoryAction,
    /// Resource path segments.
    resource: Vec<String>,
}

/// Serializable form of [`Action`]. The validator fork stays serde-free, so the mapping lives here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum HistoryAction {
    /// See [`Action::Read`].
    Read,
    /// See [`Action::Edit`].
    Edit,
    /// See [`Action::Stage`].
    Stage,
    /// See [`Action::Unstage`].
    Unstage,
    /// See [`Action::Commit`].
    Commit {
        /// Commit message, absent when the command supplied none.
        message: Option<String>,
    },
    /// See [`Action::Checkout`].
    Checkout,
    /// See [`Action::Stash`].
    Stash,
    /// See [`Action::Delete`].
    Delete,
    /// See [`Action::Clean`].
    Clean,
    /// See [`Action::Diff`].
    Diff,
    /// See [`Action::History`].
    History,
}

impl From<&Event> for HistoryEvent {
    fn from(event: &Event) -> Self {
        Self {
            principal: event.principal.to_string(),
            action: (&event.action).into(),
            resource: event.resource.segments().to_vec(),
        }
    }
}

impl From<&HistoryEvent> for Event {
    fn from(event: &HistoryEvent) -> Self {
        Self::new(
            event.principal.as_str(),
            (&event.action).into(),
            Resource::from(event.resource.clone()),
        )
    }
}

impl From<&Action> for HistoryAction {
    fn from(action: &Action) -> Self {
        match action {
            Action::Read => Self::Read,
            Action::Edit => Self::Edit,
            Action::Stage => Self::Stage,
            Action::Unstage => Self::Unstage,
            Action::Commit { message } => Self::Commit {
                message: message.clone(),
            },
            Action::Checkout => Self::Checkout,
            Action::Stash => Self::Stash,
            Action::Delete => Self::Delete,
            Action::Clean => Self::Clean,
            Action::Diff => Self::Diff,
            Action::History => Self::History,
        }
    }
}

impl From<&HistoryAction> for Action {
    fn from(action: &HistoryAction) -> Self {
        match action {
            HistoryAction::Read => Self::Read,
            HistoryAction::Edit => Self::Edit,
            HistoryAction::Stage => Self::Stage,
            HistoryAction::Unstage => Self::Unstage,
            HistoryAction::Commit { message } => Self::Commit {
                message: message.clone(),
            },
            HistoryAction::Checkout => Self::Checkout,
            HistoryAction::Stash => Self::Stash,
            HistoryAction::Delete => Self::Delete,
            HistoryAction::Clean => Self::Clean,
            HistoryAction::Diff => Self::Diff,
            HistoryAction::History => Self::History,
        }
    }
}

/// Append-only handle on the history, held by the authority.
///
/// Held rather than reopened per merge: the authority appends one line under its write lock, and
/// reopening a file to write a line the lock already serializes would buy nothing.
pub(crate) struct HistoryLog {
    /// The underlying JSON Lines log.
    log: JsonLog<HistoryRecord>,
}

impl HistoryLog {
    /// Appends one merge's record, fsynced before returning.
    pub(crate) fn append(
        &mut self,
        seq: u64,
        principal: &str,
        cmd: &str,
        events: &[Event],
        ops: &[CommitOp],
    ) -> Result<(), MuxError> {
        let record = HistoryRecord {
            seq,
            principal: principal.to_string(),
            cmd: cmd.to_string(),
            events: events.iter().map(HistoryEvent::from).collect(),
            paths: ops.iter().map(|op| op.path().to_string()).collect(),
        };
        self.log.append(std::slice::from_ref(&record))
    }
}

/// Appends one transaction's record without the authority's log handle.
///
/// Used only by [`crate::commit::recover`], which re-derives a history entry whose seed write
/// survived a crash that the entry did not — and which runs before the authority exists to hold a
/// handle.
pub(crate) fn append(
    session: &Session,
    seq: u64,
    principal: &str,
    cmd: &str,
    events: &[Event],
    ops: &[CommitOp],
) -> Result<(), MuxError> {
    HistoryLog {
        log: JsonLog::open(&session.meta().join(HISTORY_FILE))?,
    }
    .append(seq, principal, cmd, events, ops)
}

/// Sequence numbers the history already carries.
pub(crate) fn committed_sequences(session: &Session) -> Result<HashSet<u64>, MuxError> {
    let records = JsonLog::<HistoryRecord>::read(&session.meta().join(HISTORY_FILE))?;
    Ok(records.iter().map(|record| record.seq).collect())
}

/// Everything the authority rebuilds from the history at startup.
pub(crate) struct Loaded {
    /// Committed capability history, in merge order: the policy's input.
    pub history: Vec<Event>,
    /// Sequence number of the transaction that last wrote each seed-relative path.
    pub generations: HashMap<String, u64>,
    /// Highest committed sequence number.
    pub seq: u64,
    /// The open log, ready for the next merge.
    pub log: HistoryLog,
}

/// Rebuilds the authority's state from `meta/history.jsonl`.
///
/// A torn final line — the only corruption an append-and-fsync log can produce — is truncated away:
/// a record that was never fully written describes a merge whose history entry never landed, and
/// [`crate::merge::recover`] has already re-derived the seed content it described.
///
/// `generations` and `seq` do not have to survive a restart the way `history` does — every sandbox
/// is recreated from the current seed at startup, so no live snapshot can be stale against an older
/// sequence number — but both are in each record already, so rebuilding them costs nothing and
/// keeps `merged seq=` numbers from repeating.
pub(crate) fn load(session: &Session) -> Result<Loaded, MuxError> {
    let path = session.meta().join(HISTORY_FILE);
    let records = JsonLog::<HistoryRecord>::read(&path)?;

    let mut history = Vec::new();
    let mut generations = HashMap::new();
    let mut seq = 0;
    for record in &records {
        history.extend(record.events.iter().map(Event::from));
        for path in &record.paths {
            generations.insert(path.clone(), record.seq);
        }
        seq = seq.max(record.seq);
    }

    Ok(Loaded {
        history,
        generations,
        seq,
        log: HistoryLog {
            log: JsonLog::open(&path)?,
        },
    })
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::snapshot::tests::test_root;

    /// A session over a plain directory: this test exercises the log, which needs no btrfs.
    fn scratch_session(root: &Path) -> Session {
        let session = Session {
            seed: root.join("seed"),
            root: root.join("state"),
        };
        std::fs::create_dir_all(session.meta()).expect("meta");
        session
    }

    /// The history is the policy's input, so a restart that lost it would grant what the running
    /// session refused. Generations and the sequence number ride along in the same records.
    #[test]
    fn a_restart_reads_back_exactly_what_was_appended() {
        let root = test_root();
        let session = scratch_session(&root);
        let events = vec![
            Event::new("agent0", Action::Edit, Resource::from(vec!["src", "a.txt"])),
            Event::new(
                "agent0",
                Action::commit("m".to_string()),
                Resource::from(vec!["src", "a.txt"]),
            ),
        ];

        let mut loaded = load(&session).expect("load an absent history");
        assert!(loaded.history.is_empty());
        assert_eq!(loaded.seq, 0);
        loaded
            .log
            .append(
                1,
                "agent0",
                "printf x > src/a.txt",
                &events,
                &[CommitOp::Write("src/a.txt".to_string())],
            )
            .expect("append");
        loaded
            .log
            .append(
                2,
                "agent1",
                "rm -- src/b.txt",
                &[],
                &[CommitOp::Remove("src/b.txt".to_string())],
            )
            .expect("append");
        drop(loaded);

        let reloaded = load(&session).expect("load");
        assert_eq!(reloaded.history, events, "actions survive the round trip");
        assert_eq!(reloaded.seq, 2);
        assert_eq!(reloaded.generations.get("src/a.txt"), Some(&1));
        assert_eq!(reloaded.generations.get("src/b.txt"), Some(&2));
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}
