//! The write-ahead log: a job's snapshot into the seed.
//!
//! One append-only log, at `meta/wal.jsonl`, holds every transaction. The order is the protocol:
//! the whole transaction is logged and fsynced first, then each record is applied to the seed, then
//! `End`. A crash before `End` leaves a log a replay can finish; a crash after it leaves nothing to
//! do in the seed.
//!
//! The log also outlives its own stage. A transaction is followed by a history entry, and a crash
//! between the two is repaired from here — this is the only record that names, together, what
//! entered the seed and which capabilities earned it.

use std::path::Path;

use rust_validator::Event;
use serde::{Deserialize, Serialize};

use crate::diff::CommitOp;
use crate::error::MuxError;
use crate::history::{self, HistoryEvent};
use crate::ids;
use crate::session::Session;
use crate::wal::{self, JsonLog};

/// Log file name under the session's `meta/` directory.
const LOG_FILE: &str = "wal.jsonl";

/// One line of the log.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "UPPERCASE")]
pub(crate) enum WalRecord {
    /// Opens a transaction: everything the history needs, plus the snapshot its content comes from.
    Begin {
        /// Sequence number this transaction will occupy.
        seq: u64,
        /// The job whose snapshot holds the content, so a replay can find it.
        uid: String,
        /// The principal the capabilities were granted to.
        principal: String,
        /// The command line, for the audit trail.
        cmd: String,
        /// Capabilities the policy granted.
        events: Vec<HistoryEvent>,
    },
    /// Copy the snapshot's version of a path into the seed.
    Move {
        /// Source, relative to the job's snapshot root.
        from: String,
        /// Destination, relative to the seed.
        to: String,
        /// `sha1` of the content being moved, so a replay can tell an applied record from an
        /// interrupted one after the snapshot it came from was swept.
        sha1: String,
    },
    /// Delete a path from the seed.
    Delete {
        /// Seed-relative path.
        path: String,
    },
    /// Every preceding record of this transaction has been applied.
    End {
        /// The sequence number opened by `Begin`.
        seq: u64,
    },
}

impl WalRecord {
    /// The commit operation this record performs, or `None` for the framing records.
    fn operation(&self) -> Option<CommitOp> {
        match self {
            Self::Move { to, .. } => Some(CommitOp::Write(to.clone())),
            Self::Delete { path } => Some(CommitOp::Remove(path.clone())),
            Self::Begin { .. } | Self::End { .. } => None,
        }
    }
}

/// One logged transaction, as [`recover`] reads it back.
struct Transaction {
    /// Sequence number the transaction occupies.
    seq: u64,
    /// The job whose snapshot its content comes from.
    uid: String,
    /// The principal the capabilities were granted to.
    principal: String,
    /// The command line.
    cmd: String,
    /// Capabilities the policy granted.
    events: Vec<HistoryEvent>,
    /// Its `Move` and `Delete` records, in log order.
    records: Vec<WalRecord>,
    /// Whether the log carries this transaction's `End`.
    finished: bool,
}

/// Logs one transaction and applies it to the seed.
///
/// Order is the protocol: the whole batch first, fsynced, then the records, then `End`.
///
/// # Errors
///
/// Fails when the log cannot be written or a record cannot be applied to the seed.
pub(crate) fn apply(
    session: &Session,
    uid: &str,
    seq: u64,
    principal: &str,
    cmd: &str,
    events: &[Event],
    ops: &[CommitOp],
) -> Result<(), MuxError> {
    let work = session.work(uid);

    let mut records = Vec::with_capacity(ops.len() + 1);
    records.push(WalRecord::Begin {
        seq,
        uid: uid.to_string(),
        principal: principal.to_string(),
        cmd: cmd.to_string(),
        events: events.iter().map(HistoryEvent::from).collect(),
    });
    for op in ops {
        records.push(match op {
            CommitOp::Remove(path) => WalRecord::Delete { path: path.clone() },
            // `from` and `to` are equal in practice; both are logged so a record reads on its own.
            CommitOp::Write(path) => WalRecord::Move {
                from: path.clone(),
                to: path.clone(),
                sha1: content_hash(&work.join(path))?,
            },
        });
    }

    let mut log = JsonLog::open(&session.meta().join(LOG_FILE))?;
    log.append(&records)?;
    for record in &records {
        apply_record(session, &work, record)?;
    }
    log.append(&[WalRecord::End { seq }])
}

/// Finishes every unfinished transaction and re-derives the history entries any of them are
/// missing.
///
/// Called once, from [`crate::ShellMux::open`], before anything reads the seed and *before* the
/// snapshot sweep: an unfinished transaction's content lives in `snap/<uid>`. A finished
/// transaction is still consulted, because the protocol writes the seed and then the history, and a
/// crash between the two leaves this log as the only record of what was granted.
///
/// # Errors
///
/// Fails when the log is corrupt, when a record can neither be applied nor recognized as already
/// applied, or when the history cannot be appended to.
pub(crate) fn recover(session: &Session) -> Result<(), MuxError> {
    let path = session.meta().join(LOG_FILE);
    let records = JsonLog::<WalRecord>::read(&path)?;
    if records.is_empty() {
        return Ok(());
    }

    let mut transactions: Vec<Transaction> = Vec::new();
    for record in records {
        match record {
            WalRecord::Begin {
                seq,
                uid,
                principal,
                cmd,
                events,
            } => transactions.push(Transaction {
                seq,
                uid,
                principal,
                cmd,
                events,
                records: Vec::new(),
                finished: false,
            }),
            WalRecord::End { seq } => {
                if let Some(transaction) = transactions
                    .iter_mut()
                    .rev()
                    .find(|transaction| transaction.seq == seq)
                {
                    transaction.finished = true;
                }
            }
            // A record before any `Begin` belongs to no transaction and describes nothing.
            operation => {
                if let Some(transaction) = transactions.last_mut() {
                    transaction.records.push(operation);
                }
            }
        }
    }

    let remembered = history::committed_sequences(session)?;
    let mut log = JsonLog::open(&path)?;
    for transaction in &transactions {
        if !transaction.finished {
            let work = session.work(&transaction.uid);
            for record in &transaction.records {
                apply_record(session, &work, record)?;
            }
            log.append(&[WalRecord::End {
                seq: transaction.seq,
            }])?;
        }
        if !remembered.contains(&transaction.seq) {
            let granted: Vec<Event> = transaction.events.iter().map(Event::from).collect();
            let ops: Vec<CommitOp> = transaction
                .records
                .iter()
                .filter_map(WalRecord::operation)
                .collect();
            history::append(
                session,
                transaction.seq,
                &transaction.principal,
                &transaction.cmd,
                &granted,
                &ops,
            )?;
        }
    }
    Ok(())
}

/// Applies one record to the seed.
///
/// Idempotent, which is what lets a replay re-run a transaction that may have partly happened: a
/// write replaces whatever is there and a removal tolerates an absent path. A write whose source is
/// gone is not an error when the destination already carries the content the record named — that is
/// a transaction which completed and whose snapshot was swept.
fn apply_record(session: &Session, work: &Path, record: &WalRecord) -> Result<(), MuxError> {
    match record {
        WalRecord::Begin { .. } | WalRecord::End { .. } => Ok(()),
        WalRecord::Delete { path } => wal::apply_remove(&session.seed, &session.seed.join(path)),
        WalRecord::Move { from, to, sha1 } => write(&session.seed, work, from, to, sha1),
    }
}

/// Copies `from` (in the job's snapshot) onto `to` (in the seed).
fn write(seed: &Path, work: &Path, from: &str, to: &str, sha1: &str) -> Result<(), MuxError> {
    let source = work.join(from);
    let target = seed.join(to);
    if source.symlink_metadata().is_ok() {
        return wal::apply_write(&source, &target);
    }
    if target.symlink_metadata().is_ok() && content_hash(&target)? == sha1 {
        return Ok(());
    }
    Err(MuxError::Wal(format!(
        "source {} is gone and {} does not carry its content; the transaction can neither be \
         completed nor undone",
        source.display(),
        target.display()
    )))
}

/// The `sha1` a record carries for a path: the bytes of a file, or the target of a symlink.
///
/// Anything else — a fifo, a socket, a device node — has no content to read; its mode is the whole
/// entry, and the diff already compared that.
fn content_hash(path: &Path) -> Result<String, MuxError> {
    let metadata = path.symlink_metadata()?;
    if metadata.file_type().is_symlink() {
        Ok(ids::content_hash(
            std::fs::read_link(path)?.as_os_str().as_encoded_bytes(),
        ))
    } else if metadata.is_file() {
        Ok(ids::content_hash(&std::fs::read(path)?))
    } else {
        Ok(ids::content_hash(&[]))
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::snapshot::tests::test_root;

    /// A session over plain directories: these tests only copy files, so no subvolume is needed.
    fn scratch_session(root: &Path, uid: &str) -> Session {
        let session = Session {
            seed: root.join("seed"),
            root: root.join("state"),
        };
        std::fs::create_dir_all(&session.seed).expect("seed");
        std::fs::create_dir_all(session.meta()).expect("meta");
        std::fs::create_dir_all(session.work(uid)).expect("snapshot");
        session
    }

    /// Writes an unfinished transaction — logged, not yet applied — over one file.
    fn unfinished_log(session: &Session, uid: &str, path: &str, contents: &[u8]) {
        JsonLog::open(&session.meta().join(LOG_FILE))
            .expect("open log")
            .append(&[
                WalRecord::Begin {
                    seq: 1,
                    uid: uid.to_string(),
                    principal: "agent0".to_string(),
                    cmd: format!("printf … > {path}"),
                    events: Vec::new(),
                },
                WalRecord::Move {
                    from: path.to_string(),
                    to: path.to_string(),
                    sha1: ids::content_hash(contents),
                },
            ])
            .expect("append");
    }

    /// The log's whole reason to exist: the record is durable, the seed is not yet whole, and the
    /// next startup finishes it — including the history entry the crash cost.
    #[test]
    fn an_unfinished_transaction_is_replayed_on_recover() {
        let root = test_root().join("wal-interrupted");
        let session = scratch_session(&root, "job0");
        std::fs::write(session.work("job0").join("a.txt"), b"recovered\n").expect("snapshot file");
        unfinished_log(&session, "job0", "a.txt", b"recovered\n");

        recover(&session).expect("recover");
        assert_eq!(
            std::fs::read(session.seed.join("a.txt")).expect("read the seed"),
            b"recovered\n",
            "the interrupted move reached the seed"
        );
        let records: Vec<WalRecord> =
            JsonLog::<WalRecord>::read(&session.meta().join(LOG_FILE)).expect("read the log");
        assert!(
            matches!(records.last(), Some(WalRecord::End { seq: 1 })),
            "and the transaction is closed: {records:?}"
        );
        let history =
            std::fs::read_to_string(session.meta().join("history.jsonl")).expect("read history");
        assert!(
            history.contains("\"seq\":1"),
            "the history entry is re-derived from the same log: {history}"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The case the recorded `sha1` exists for: the transaction did reach the seed, the crash beat
    /// its `End`, and the snapshot it came from has since been swept. The content is proof enough.
    #[test]
    fn a_replayed_move_whose_snapshot_is_gone_is_a_no_op() {
        let root = test_root().join("wal-swept");
        let session = scratch_session(&root, "job0");
        unfinished_log(&session, "job0", "a.txt", b"recovered\n");
        std::fs::write(session.seed.join("a.txt"), b"recovered\n").expect("seed file");
        std::fs::remove_dir_all(session.work("job0")).expect("sweep the snapshot");

        recover(&session).expect("recover");
        assert_eq!(
            std::fs::read(session.seed.join("a.txt")).expect("read the seed"),
            b"recovered\n",
            "the seed already carried the record's content, so nothing was rewritten"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}
