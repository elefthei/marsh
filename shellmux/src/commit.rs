//! Publishing one job's snapshot into the seed, and what the mux remembers about it.
//!
//! The durable protocol — log the whole transaction, fsync, apply it to the seed, close it — lives
//! in [`brush_btrfs::commit`], which knows nothing about principals or capabilities. This module is
//! the marsh half: it names what a transaction *was* (who asked, for what command, with which
//! capabilities granted) as the metadata that crate records beside the operations, and it turns a
//! recovered transaction back into the history entry the authority decides from.
//!
//! The split matters at recovery. The seed write and the history entry are two steps, and a crash
//! between them leaves the log as the only record of what was granted. `brush_btrfs` finishes the
//! seed write and hands back every transaction it found whole; deciding which of those the history
//! is still missing is a question only marsh can answer.

use brush_btrfs::{CommitOp, PersistenceLayer};
use rust_validator::Event;
use serde::{Deserialize, Serialize};

use crate::error::MuxError;
use crate::history::{self, HistoryEvent};

/// What marsh records with every transaction, flattened into the log's `BEGIN` line.
///
/// The field names are the wire format: a `wal.jsonl` written before the durable protocol moved
/// into its own crate carries exactly these keys at the top level of its `BEGIN` records, and they
/// still read back.
#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    /// The principal the capabilities were granted to.
    principal: String,
    /// The command line, for the audit trail.
    cmd: String,
    /// Capabilities the policy granted.
    events: Vec<HistoryEvent>,
}

/// Logs one transaction and applies it to the seed.
///
/// # Errors
///
/// Fails when the log cannot be written or a record cannot be applied to the seed.
pub(crate) fn apply(
    persistence: &PersistenceLayer,
    uid: &str,
    seq: u64,
    principal: &str,
    cmd: &str,
    events: &[Event],
    ops: &[CommitOp],
) -> Result<(), MuxError> {
    let meta = Meta {
        principal: principal.to_string(),
        cmd: cmd.to_string(),
        events: events.iter().map(HistoryEvent::from).collect(),
    };
    Ok(brush_btrfs::commit::apply(
        persistence,
        uid,
        seq,
        &meta,
        ops,
    )?)
}

/// Finishes every unfinished transaction and re-derives the history entries any of them are
/// missing.
///
/// Called once, from [`crate::ShellMux::new`], before anything reads the seed and *before* the
/// snapshot sweep: an unfinished transaction's content lives in `snap/<uid>`. A finished
/// transaction is consulted too, because the protocol writes the seed and then the history, and a
/// crash between the two leaves the log as the only record of what was granted.
///
/// # Errors
///
/// Fails when the log is corrupt, when a record can neither be applied nor recognized as already
/// applied, or when the history cannot be appended to.
pub(crate) fn recover(persistence: &PersistenceLayer) -> Result<(), MuxError> {
    let recovered = brush_btrfs::commit::recover::<Meta>(persistence)?;
    if recovered.is_empty() {
        return Ok(());
    }
    let remembered = history::committed_sequences(persistence)?;
    for transaction in recovered
        .iter()
        .filter(|transaction| !remembered.contains(&transaction.seq))
    {
        let granted: Vec<Event> = transaction.meta.events.iter().map(Event::from).collect();
        history::append(
            persistence,
            transaction.seq,
            &transaction.meta.principal,
            &transaction.meta.cmd,
            &granted,
            &transaction.ops,
        )?;
    }
    Ok(())
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use std::path::{Path, PathBuf};

    use rust_validator::{Action, Resource};

    /// A persistence layer over plain directories: these tests only copy files, so no subvolume is
    /// needed.
    fn scratch_persistence(root: &Path, uid: &str) -> PersistenceLayer {
        let persistence = PersistenceLayer::new(root.join("seed"), root.join("state"));
        std::fs::create_dir_all(&persistence.seed).expect("seed");
        std::fs::create_dir_all(persistence.meta()).expect("meta");
        std::fs::create_dir_all(persistence.work(uid)).expect("snapshot");
        persistence
    }

    /// The history is the policy's memory, and a crash between the seed write and the history
    /// append would silently forget a grant. Recovery re-derives it from the same log.
    #[test]
    fn recovery_re_derives_a_missing_history_entry() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch_persistence(scratch.path(), "job0");
        std::fs::write(persistence.work("job0").join("a.txt"), b"x\n").expect("snapshot file");
        let events = vec![Event::new(
            "agent0",
            Action::Edit,
            Resource::from(vec!["a.txt"]),
        )];

        apply(
            &persistence,
            "job0",
            1,
            "agent0",
            "printf x > a.txt",
            &events,
            &[CommitOp::Write(PathBuf::from("a.txt"))],
        )
        .expect("apply");
        assert!(
            !persistence.meta().join("history.jsonl").exists(),
            "the transaction is durable; the history entry is the caller's separate step"
        );

        recover(&persistence).expect("recover");
        let loaded = history::load(&persistence).expect("load the history");
        assert_eq!(
            loaded.history, events,
            "the grant the crash cost is back, verbatim"
        );
        assert_eq!(loaded.seq, 1);
        assert_eq!(
            loaded.generations.get(Path::new("a.txt")),
            Some(&1),
            "and so is the generation the path earned"
        );
    }

    /// Recovery runs at every startup, and a transaction whose history entry already landed must
    /// not be appended a second time: a duplicated grant would be a duplicated claim.
    #[test]
    fn a_remembered_transaction_is_not_re_derived() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch_persistence(scratch.path(), "job0");
        std::fs::write(persistence.work("job0").join("a.txt"), b"x\n").expect("snapshot file");
        apply(
            &persistence,
            "job0",
            1,
            "agent0",
            "printf x > a.txt",
            &[],
            &[CommitOp::Write(PathBuf::from("a.txt"))],
        )
        .expect("apply");

        recover(&persistence).expect("first recovery");
        recover(&persistence).expect("second recovery");
        let text =
            std::fs::read_to_string(persistence.meta().join("history.jsonl")).expect("history");
        assert_eq!(
            text.lines().count(),
            1,
            "one transaction, one history entry: {text}"
        );
    }
}
