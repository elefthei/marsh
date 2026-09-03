//! Write-ahead log: what makes a merge atomic against a crash.
//!
//! A merge is two durable steps. First an `Intent` record — the events, the file operations, and the
//! work snapshot they come from — is appended and fsynced. Then the operations are applied to the
//! seed. Finally a `Commit` record is appended and fsynced, and only then may the work snapshot be
//! deleted.
//!
//! That ordering gives exactly three crash windows, and recovery handles each:
//!
//! * before the intent is durable — the seed is untouched and the command simply never happened;
//! * between intent and commit — the intent names a snapshot that still exists, so [`recover`]
//!   re-applies the operations (they are idempotent) and commits;
//! * after the commit — nothing to replay; the leftover snapshot is swept.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rust_validator::{Action, Event, Resource};
use serde::{Deserialize, Serialize};

use crate::diff::MergeOp;
use crate::error::MuxError;

/// Log file name under the mux's `.marsh/` directory.
const WAL_FILE: &str = "wal.log";

/// One durable log record.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WalRecord {
    /// A merge that is about to be applied.
    Intent {
        /// Sequence number this merge will occupy.
        seq: u64,
        /// Principal whose command produced it.
        principal: String,
        /// The command line, for the audit trail.
        cmd: String,
        /// Root-relative path of the work snapshot the writes come from.
        work_snapshot: String,
        /// Capabilities the policy granted for this merge.
        events: Vec<WalEvent>,
        /// File operations that constitute the merge.
        ops: Vec<WalOp>,
    },
    /// The merge with this sequence number is complete and durable.
    Commit {
        /// Sequence number of the completed merge.
        seq: u64,
    },
}

/// Serializable form of a capability event.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WalEvent {
    /// Principal that requested the capability.
    principal: String,
    /// Requested action.
    action: WalAction,
    /// Resource path segments.
    resource: Vec<String>,
}

/// Serializable form of [`Action`]. The validator fork stays serde-free, so the mapping lives here.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WalAction {
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

/// Serializable form of [`MergeOp`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum WalOp {
    /// Copy this seed-relative path from the work snapshot into the seed.
    Write {
        /// Seed-relative, `/`-joined path.
        path: String,
    },
    /// Delete this seed-relative path from the seed.
    Remove {
        /// Seed-relative, `/`-joined path.
        path: String,
    },
}

impl WalOp {
    /// The path this operation touches.
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::Write { path } | Self::Remove { path } => path,
        }
    }
}

impl From<&MergeOp> for WalOp {
    fn from(op: &MergeOp) -> Self {
        match op {
            MergeOp::Write(path) => Self::Write { path: path.clone() },
            MergeOp::Remove(path) => Self::Remove { path: path.clone() },
        }
    }
}

impl From<&Event> for WalEvent {
    fn from(event: &Event) -> Self {
        Self {
            principal: event.principal.to_string(),
            action: (&event.action).into(),
            resource: event.resource.segments().to_vec(),
        }
    }
}

impl From<&WalEvent> for Event {
    fn from(event: &WalEvent) -> Self {
        Self::new(
            event.principal.as_str(),
            (&event.action).into(),
            Resource::from(event.resource.clone()),
        )
    }
}

impl From<&Action> for WalAction {
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

impl From<&WalAction> for Action {
    fn from(action: &WalAction) -> Self {
        match action {
            WalAction::Read => Self::Read,
            WalAction::Edit => Self::Edit,
            WalAction::Stage => Self::Stage,
            WalAction::Unstage => Self::Unstage,
            WalAction::Commit { message } => Self::Commit {
                message: message.clone(),
            },
            WalAction::Checkout => Self::Checkout,
            WalAction::Stash => Self::Stash,
            WalAction::Delete => Self::Delete,
            WalAction::Clean => Self::Clean,
            WalAction::Diff => Self::Diff,
            WalAction::History => Self::History,
        }
    }
}

/// Append-only handle on the log.
pub(crate) struct WalWriter {
    file: File,
}

impl WalWriter {
    /// Opens (creating if absent) the log under `root/.marsh/`.
    pub(crate) fn open(root: &Path) -> Result<Self, MuxError> {
        let path = wal_path(root);
        std::fs::create_dir_all(path.parent().expect("wal path has a parent"))?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { file })
    }

    /// Appends one record and forces it to disk before returning.
    pub(crate) fn append(&mut self, record: &WalRecord) -> Result<(), MuxError> {
        let mut line = serde_json::to_vec(record)
            .map_err(|error| MuxError::Wal(format!("serialize record: {error}")))?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        Ok(())
    }
}

/// State the authority rebuilds from the log at startup.
#[derive(Debug)]
pub(crate) struct WalState {
    /// Committed capability history, in merge order.
    pub history: Vec<Event>,
    /// Last merge sequence number that wrote each seed-relative path, `.git/` included.
    pub generations: HashMap<String, u64>,
    /// Highest committed sequence number; the next intent takes `seq + 1`.
    pub seq: u64,
}

/// Path of the log file for a mux root.
fn wal_path(root: &Path) -> PathBuf {
    root.join(".marsh").join(WAL_FILE)
}

/// Applies merge operations to `seed`, taking file contents from `work`.
///
/// Idempotent by construction — a `Remove` tolerates an already-absent path and a `Write` replaces
/// whatever is there — which is what lets recovery re-run a merge that may have partly happened.
/// Each write lands through a temporary file and a rename, so a crash can never expose a
/// half-copied file at its real path.
pub(crate) fn apply_ops(seed: &Path, work: &Path, ops: &[WalOp]) -> Result<(), MuxError> {
    for op in ops {
        match op {
            WalOp::Remove { path } => {
                let target = seed.join(path);
                let removal = match target.symlink_metadata() {
                    Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&target),
                    Ok(_) => std::fs::remove_file(&target),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                };
                if let Err(error) = removal
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    return Err(MuxError::Io(error));
                }
                prune_empty_parents(seed, &target);
            }
            WalOp::Write { path } => {
                let source = work.join(path);
                let target = seed.join(path);
                let parent = target
                    .parent()
                    .ok_or_else(|| MuxError::Wal(format!("write path {path} has no parent")))?;
                std::fs::create_dir_all(parent)?;
                let temporary = parent.join(format!(
                    "{}.tmp-wal",
                    target
                        .file_name()
                        .ok_or_else(|| MuxError::Wal(format!("write path {path} has no name")))?
                        .to_string_lossy()
                ));
                let metadata = source.symlink_metadata().map_err(|error| {
                    MuxError::Wal(format!(
                        "missing merge source {}: {error}",
                        source.display()
                    ))
                })?;
                let _ = std::fs::remove_file(&temporary);
                if metadata.file_type().is_symlink() {
                    std::os::unix::fs::symlink(std::fs::read_link(&source)?, &temporary)?;
                } else {
                    // `fs::copy` carries the permission bits over, which the diff treats as part of
                    // the entry.
                    std::fs::copy(&source, &temporary)?;
                    File::open(&temporary)?.sync_data()?;
                }
                // Replacing a directory with a file needs the directory gone first.
                if target.symlink_metadata().is_ok_and(|meta| meta.is_dir()) {
                    std::fs::remove_dir_all(&target)?;
                }
                std::fs::rename(&temporary, &target)?;
                File::open(parent)?.sync_all()?;
            }
        }
    }
    Ok(())
}

/// Removes directories left empty by a deletion, stopping at the seed root.
fn prune_empty_parents(seed: &Path, target: &Path) {
    let mut current = target.parent().map(Path::to_path_buf);
    while let Some(directory) = current {
        if directory == seed || !directory.starts_with(seed) {
            return;
        }
        let empty = std::fs::read_dir(&directory).is_ok_and(|mut entries| entries.next().is_none());
        if !empty {
            return;
        }
        if std::fs::remove_dir(&directory).is_err() {
            return;
        }
        current = directory.parent().map(Path::to_path_buf);
    }
}

/// Rebuilds authority state from the log, finishing any merge that a crash interrupted.
///
/// A torn final line — the only corruption an append-and-fsync log can produce — is truncated away:
/// a record that was never fully written describes a merge that never started.
pub(crate) fn recover(root: &Path, seed: &Path) -> Result<WalState, MuxError> {
    let path = wal_path(root);
    let mut state = WalState {
        history: Vec::new(),
        generations: HashMap::new(),
        seq: 0,
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(state),
        Err(error) => return Err(MuxError::Io(error)),
    };

    let mut records: Vec<WalRecord> = Vec::new();
    let mut durable_len = 0usize;
    let mut lines = text.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        let is_last = lines.peek().is_none();
        let trimmed = line.trim_end_matches('\n');
        if trimmed.is_empty() {
            durable_len += line.len();
            continue;
        }
        match serde_json::from_str::<WalRecord>(trimmed) {
            Ok(record) => {
                records.push(record);
                durable_len += line.len();
            }
            Err(error) => {
                if is_last {
                    // Torn tail: discard it so the next append starts from a clean record boundary.
                    let file = OpenOptions::new().write(true).open(&path)?;
                    file.set_len(durable_len as u64)?;
                    file.sync_all()?;
                    break;
                }
                return Err(MuxError::Wal(format!(
                    "corrupt record {trimmed:?}: {error}"
                )));
            }
        }
    }

    let committed: Vec<u64> = records
        .iter()
        .filter_map(|record| match record {
            WalRecord::Commit { seq } => Some(*seq),
            WalRecord::Intent { .. } => None,
        })
        .collect();

    let mut pending: Option<(u64, String, Vec<Event>, Vec<WalOp>)> = None;
    for record in &records {
        let WalRecord::Intent {
            seq,
            work_snapshot,
            events,
            ops,
            ..
        } = record
        else {
            continue;
        };
        let events: Vec<Event> = events.iter().map(Event::from).collect();
        if committed.contains(seq) {
            state.history.extend(events);
            for op in ops {
                state.generations.insert(op.path().to_string(), *seq);
            }
            state.seq = state.seq.max(*seq);
        } else {
            pending = Some((*seq, work_snapshot.clone(), events, ops.clone()));
        }
    }

    if let Some((seq, work_snapshot, events, ops)) = pending {
        let work = root.join(&work_snapshot);
        if !work.exists() {
            return Err(MuxError::Wal(format!(
                "intent {seq} names work snapshot {work_snapshot} which no longer exists; \
                 the merge cannot be completed or undone"
            )));
        }
        apply_ops(seed, &work, &ops)?;
        let mut writer = WalWriter::open(root)?;
        writer.append(&WalRecord::Commit { seq })?;
        state.history.extend(events);
        for op in &ops {
            state.generations.insert(op.path().to_string(), seq);
        }
        state.seq = state.seq.max(seq);
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::snapshot::tests::test_root;

    fn seed_and_work(root: &Path) -> (PathBuf, PathBuf) {
        let seed = root.join("seed");
        let work = root.join(".marsh/snaps/work-0");
        std::fs::create_dir_all(seed.join("src")).expect("seed dirs");
        std::fs::create_dir_all(work.join("src")).expect("work dirs");
        std::fs::write(seed.join("src/a.txt"), b"seed\n").expect("seed file");
        std::fs::write(work.join("src/a.txt"), b"work\n").expect("work file");
        (seed, work)
    }

    fn intent(seq: u64, ops: Vec<WalOp>) -> WalRecord {
        WalRecord::Intent {
            seq,
            principal: "agent0".to_string(),
            cmd: "printf work > src/a.txt".to_string(),
            work_snapshot: ".marsh/snaps/work-0".to_string(),
            events: vec![WalEvent::from(&Event::new(
                "agent0",
                Action::Edit,
                Resource::from(vec!["src", "a.txt"]),
            ))],
            ops,
        }
    }

    #[test]
    fn round_trips_records_and_rebuilds_state() {
        let root = test_root();
        let (seed, _) = seed_and_work(&root);
        let ops = vec![WalOp::Write {
            path: "src/a.txt".to_string(),
        }];
        let mut writer = WalWriter::open(&root).expect("open wal");
        writer.append(&intent(1, ops)).expect("append intent");
        writer
            .append(&WalRecord::Commit { seq: 1 })
            .expect("append commit");

        let state = recover(&root, &seed).expect("recover");
        assert_eq!(state.seq, 1);
        assert_eq!(
            state.history,
            vec![Event::new(
                "agent0",
                Action::Edit,
                Resource::from(vec!["src", "a.txt"])
            )]
        );
        assert_eq!(state.generations.get("src/a.txt"), Some(&1));
        assert_eq!(
            std::fs::read(seed.join("src/a.txt")).expect("read seed"),
            b"seed\n",
            "a committed merge is never re-applied"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn recovery_completes_an_intent_without_commit() {
        let root = test_root();
        let (seed, _) = seed_and_work(&root);
        std::fs::write(seed.join("src/gone.txt"), b"doomed\n").expect("write victim");
        let ops = vec![
            WalOp::Remove {
                path: "src/gone.txt".to_string(),
            },
            WalOp::Write {
                path: "src/a.txt".to_string(),
            },
        ];
        let mut writer = WalWriter::open(&root).expect("open wal");
        writer.append(&intent(1, ops)).expect("append intent");
        drop(writer);

        let state = recover(&root, &seed).expect("recover");
        assert_eq!(state.seq, 1, "the interrupted merge is now committed");
        assert_eq!(
            std::fs::read(seed.join("src/a.txt")).expect("read seed"),
            b"work\n",
            "the interrupted write was replayed from the surviving snapshot"
        );
        assert!(!seed.join("src/gone.txt").exists(), "the removal replayed");
        assert_eq!(state.generations.get("src/gone.txt"), Some(&1));

        // Recovering again must be a no-op: the Commit record recovery appended is durable.
        std::fs::write(seed.join("src/a.txt"), b"later\n").expect("post-merge edit");
        let again = recover(&root, &seed).expect("recover again");
        assert_eq!(again.seq, 1);
        assert_eq!(again.history.len(), 1, "history is not duplicated");
        assert_eq!(
            std::fs::read(seed.join("src/a.txt")).expect("read seed"),
            b"later\n",
            "a committed merge is never replayed a second time"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn recovery_rejects_an_intent_whose_snapshot_is_gone() {
        let root = test_root();
        let (seed, work) = seed_and_work(&root);
        std::fs::remove_dir_all(&work).expect("drop the snapshot");
        let mut writer = WalWriter::open(&root).expect("open wal");
        writer
            .append(&intent(
                1,
                vec![WalOp::Write {
                    path: "src/a.txt".to_string(),
                }],
            ))
            .expect("append intent");
        drop(writer);

        let error = recover(&root, &seed).expect_err("must not silently drop the merge");
        assert!(
            matches!(&error, MuxError::Wal(message) if message.contains("no longer exists")),
            "got {error:?}"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn a_torn_final_record_is_truncated_away() {
        let root = test_root();
        let (seed, _) = seed_and_work(&root);
        let mut writer = WalWriter::open(&root).expect("open wal");
        writer
            .append(&intent(
                1,
                vec![WalOp::Write {
                    path: "src/a.txt".to_string(),
                }],
            ))
            .expect("append intent");
        writer
            .append(&WalRecord::Commit { seq: 1 })
            .expect("append commit");
        drop(writer);
        let path = wal_path(&root);
        let mut raw = std::fs::read(&path).expect("read wal");
        let complete_len = raw.len();
        raw.extend_from_slice(br#"{"kind":"intent","seq":2,"princ"#);
        std::fs::write(&path, &raw).expect("simulate a torn append");

        let state = recover(&root, &seed).expect("recover past the torn tail");
        assert_eq!(state.seq, 1);
        assert_eq!(
            std::fs::metadata(&path).expect("stat wal").len() as usize,
            complete_len,
            "the log is truncated to its last complete record"
        );

        // The truncated log must still accept appends and read back cleanly.
        let mut writer = WalWriter::open(&root).expect("reopen wal");
        writer
            .append(&WalRecord::Commit { seq: 2 })
            .expect("append after truncation");
        drop(writer);
        assert_eq!(recover(&root, &seed).expect("recover again").seq, 1);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn generations_record_the_last_writer_of_each_path() {
        let root = test_root();
        let (seed, _) = seed_and_work(&root);
        let mut writer = WalWriter::open(&root).expect("open wal");
        for seq in 1..=3 {
            let path = if seq == 2 { "src/b.txt" } else { "src/a.txt" };
            writer
                .append(&intent(
                    seq,
                    vec![WalOp::Write {
                        path: path.to_string(),
                    }],
                ))
                .expect("append intent");
            writer
                .append(&WalRecord::Commit { seq })
                .expect("append commit");
        }
        drop(writer);

        let state = recover(&root, &seed).expect("recover");
        assert_eq!(state.seq, 3);
        assert_eq!(state.history.len(), 3);
        assert_eq!(state.generations.get("src/a.txt"), Some(&3));
        assert_eq!(state.generations.get("src/b.txt"), Some(&2));
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn removals_prune_directories_they_empty() {
        let root = test_root();
        let (seed, work) = seed_and_work(&root);
        std::fs::create_dir_all(seed.join("deep/nest")).expect("nested dirs");
        std::fs::write(seed.join("deep/nest/leaf.txt"), b"x\n").expect("leaf");
        apply_ops(
            &seed,
            &work,
            &[WalOp::Remove {
                path: "deep/nest/leaf.txt".to_string(),
            }],
        )
        .expect("apply removal");
        assert!(!seed.join("deep").exists(), "emptied parents are pruned");
        assert!(seed.join("src").exists(), "unrelated directories survive");
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}
