//! Durable-log primitives: an append-only JSON Lines log, and the file moves it replays.
//!
//! A transaction moves a job's snapshot content into the seed. It cannot use `rename(2)` between
//! the two — a rename cannot cross a subvolume boundary, and the snapshot is one — so every move is
//! a copy into a temporary *beside the destination*, an fsync, and a rename within the
//! destination's own directory. That is what makes a crash unable to expose a half-copied file at a
//! real path.
//!
//! Every operation is idempotent: a write replaces whatever is there, a removal tolerates an
//! absent path. Replaying a log that may have partly run is therefore safe, which is the whole
//! recovery contract.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::MuxError;

/// Suffix of the temporaries a write lands through, swept at startup.
pub(crate) const TEMPORARY_SUFFIX: &str = ".tmp-wal";

/// Append-only handle on a JSON Lines log of `R`.
///
/// The record type is on the handle, not on `append`, because a log file is one format: a
/// `HistoryRecord` written into `meta/wal.jsonl` would be a line recovery cannot parse, and there
/// is no caller for which that is a legal thing to do.
///
/// `PhantomData<fn(R)>` rather than `PhantomData<R>`: the handle owns no `R`, and this form is
/// `Send + Sync` whatever `R` is — which [`crate::LearnedPurity`] needs, since it holds one behind a
/// `Mutex` inside an `Arc<dyn PuritySource>`.
pub(crate) struct JsonLog<R> {
    /// The log file, opened for appending.
    file: File,
    /// The record type this log holds.
    _record: PhantomData<fn(R)>,
}

impl<R> JsonLog<R> {
    /// Opens (creating if absent) the log at `path`, making its directory if needed.
    pub(crate) fn open(path: &Path) -> Result<Self, MuxError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file,
            _record: PhantomData,
        })
    }

    /// Appends `records` as one write and forces them to disk before returning.
    ///
    /// One write and one fsync for the whole batch: a log is durable as a unit, and paying an
    /// fsync per line would make a transaction's cost proportional to the files it touched.
    pub(crate) fn append(&mut self, records: &[R]) -> Result<(), MuxError>
    where
        R: Serialize,
    {
        if records.is_empty() {
            return Ok(());
        }
        let mut bytes = Vec::new();
        for record in records {
            serde_json::to_writer(&mut bytes, record)
                .map_err(|error| MuxError::Wal(format!("serialize record: {error}")))?;
            bytes.push(b'\n');
        }
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Every complete record of the log at `path`; an absent log reads as empty.
    ///
    /// A torn final line — the only corruption an append-and-fsync log can produce — is truncated
    /// away so the next append starts from a clean record boundary. A torn line anywhere else is a
    /// corrupt log and is reported as one.
    pub(crate) fn read(path: &Path) -> Result<Vec<R>, MuxError>
    where
        R: DeserializeOwned,
    {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(MuxError::Io(error)),
        };

        let mut records: Vec<R> = Vec::new();
        let mut durable_len = 0usize;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if !line.ends_with(b"\n") {
                let file = OpenOptions::new().write(true).open(path)?;
                file.set_len(durable_len as u64)?;
                file.sync_all()?;
                break;
            }
            let record = &line[..line.len() - 1];
            if record.is_empty() {
                durable_len += line.len();
                continue;
            }
            let parsed = serde_json::from_slice::<R>(record).map_err(|error| {
                MuxError::Wal(format!(
                    "corrupt record {:?}: {error}",
                    String::from_utf8_lossy(record)
                ))
            })?;
            records.push(parsed);
            durable_len += line.len();
        }
        Ok(records)
    }
}

/// Copies `source` onto `target`, atomically at `target`.
///
/// The copy carries the permission bits over, which the diff treats as part of the entry, and a
/// symlink is recreated rather than dereferenced.
pub(crate) fn apply_write(source: &Path, target: &Path) -> Result<(), MuxError> {
    let parent = target
        .parent()
        .ok_or_else(|| MuxError::Wal(format!("write target {} has no parent", target.display())))?;
    std::fs::create_dir_all(parent)?;
    let name = target
        .file_name()
        .ok_or_else(|| MuxError::Wal(format!("write target {} has no name", target.display())))?
        .to_string_lossy()
        .into_owned();
    let temporary = parent.join(format!("{name}{TEMPORARY_SUFFIX}"));

    let metadata = source
        .symlink_metadata()
        .map_err(|error| MuxError::Wal(format!("missing source {}: {error}", source.display())))?;
    let _ = std::fs::remove_file(&temporary);
    if metadata.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(source)?, &temporary)?;
    } else {
        std::fs::copy(source, &temporary)?;
        File::open(&temporary)?.sync_data()?;
    }
    // Replacing a directory with a file needs the directory gone first.
    if target.symlink_metadata().is_ok_and(|meta| meta.is_dir()) {
        std::fs::remove_dir_all(target)?;
    }
    std::fs::rename(&temporary, target)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Deletes `target` and prunes the directories the deletion empties, stopping at `root`.
pub(crate) fn apply_remove(root: &Path, target: &Path) -> Result<(), MuxError> {
    let removal = match target.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(target),
        Ok(_) => std::fs::remove_file(target),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = removal
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(MuxError::Io(error));
    }
    prune_empty_parents(root, target);
    Ok(())
}

/// Removes directories left empty by a deletion, stopping at `root`.
fn prune_empty_parents(root: &Path, target: &Path) {
    let mut current = target.parent().map(Path::to_path_buf);
    while let Some(directory) = current {
        if directory == root || !directory.starts_with(root) {
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

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal record type: the log primitives are generic, so the shape under test only has to
    /// round-trip.
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Line {
        /// Sequence number, so a torn tail is identifiable by what survives.
        seq: u64,
    }

    /// A crash can only ever tear the *last* line, and the log has to keep accepting appends
    /// afterwards — otherwise one interrupted write would end the session.
    #[test]
    fn a_torn_final_record_is_truncated_away() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let root = scratch.path();
        let path = root.join("log.jsonl");
        let mut log = JsonLog::open(&path).expect("open log");
        log.append(&[Line { seq: 1 }, Line { seq: 2 }])
            .expect("append");
        drop(log);
        let complete_len = std::fs::metadata(&path).expect("stat log").len();

        let mut raw = std::fs::read(&path).expect("read log");
        raw.extend_from_slice(br#"{"seq":3"#);
        std::fs::write(&path, &raw).expect("simulate a torn append");

        let records: Vec<Line> = JsonLog::<Line>::read(&path).expect("read past the torn tail");
        assert_eq!(records, vec![Line { seq: 1 }, Line { seq: 2 }]);
        assert_eq!(
            std::fs::metadata(&path).expect("stat log").len(),
            complete_len,
            "the log is truncated to its last complete record"
        );

        let mut log = JsonLog::open(&path).expect("reopen log");
        log.append(&[Line { seq: 3 }])
            .expect("append after truncation");
        drop(log);
        let records: Vec<Line> = JsonLog::<Line>::read(&path).expect("read again");
        assert_eq!(records.len(), 3);
    }

    /// A removal that empties its directory must take the directory with it: the seed and the
    /// source directory are compared against a plain re-execution, which leaves no empty husks.
    #[test]
    fn removals_prune_directories_they_empty() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let root = scratch.path();
        let tree = root.join("tree");
        std::fs::create_dir_all(tree.join("deep/nest")).expect("nested dirs");
        std::fs::create_dir_all(tree.join("src")).expect("sibling dir");
        std::fs::write(tree.join("deep/nest/leaf.txt"), b"x\n").expect("leaf");

        apply_remove(&tree, &tree.join("deep/nest/leaf.txt")).expect("apply removal");
        assert!(!tree.join("deep").exists(), "emptied parents are pruned");
        assert!(tree.join("src").exists(), "unrelated directories survive");
        apply_remove(&tree, &tree.join("deep/nest/leaf.txt")).expect("removal is idempotent");
    }

    /// A syntactically complete suffix is not durable without its terminating newline.
    #[test]
    fn complete_json_without_a_newline_is_truncated() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let root = scratch.path();
        let path = root.join("log.jsonl");
        let mut log = JsonLog::open(&path).expect("open log");
        log.append(&[Line { seq: 1 }]).expect("append");
        drop(log);

        let mut raw = std::fs::read(&path).expect("read log");
        raw.extend_from_slice(br#"{"seq":2}"#);
        std::fs::write(&path, raw).expect("write unterminated JSON");
        assert_eq!(
            JsonLog::<Line>::read(&path).expect("repair log"),
            vec![Line { seq: 1 }]
        );

        let mut log = JsonLog::open(&path).expect("reopen log");
        log.append(&[Line { seq: 2 }]).expect("append after repair");
        drop(log);
        assert_eq!(
            JsonLog::<Line>::read(&path).expect("read repaired log"),
            vec![Line { seq: 1 }, Line { seq: 2 }]
        );
    }

    /// Byte-oriented repair can discard a tail ending midway through a UTF-8 code point.
    #[test]
    fn truncated_utf8_tail_is_repaired() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let root = scratch.path();
        let path = root.join("log.jsonl");
        let mut log = JsonLog::open(&path).expect("open log");
        log.append(&[Line { seq: 1 }]).expect("append");
        drop(log);

        let mut raw = std::fs::read(&path).expect("read log");
        raw.extend_from_slice(b"{\"seq\":2,\"text\":\"\xf0\x9f");
        std::fs::write(&path, raw).expect("write truncated UTF-8");
        assert_eq!(
            JsonLog::<Line>::read(&path).expect("repair log"),
            vec![Line { seq: 1 }]
        );

        let mut log = JsonLog::open(&path).expect("reopen log");
        log.append(&[Line { seq: 2 }]).expect("append after repair");
        drop(log);
        assert_eq!(
            JsonLog::<Line>::read(&path).expect("read repaired log"),
            vec![Line { seq: 1 }, Line { seq: 2 }]
        );
    }

    /// Newline termination makes malformed JSON durable corruption, not a repairable suffix.
    #[test]
    fn malformed_newline_terminated_record_is_an_error() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let root = scratch.path();
        let path = root.join("log.jsonl");
        std::fs::write(&path, b"{not-json}\n").expect("write corrupt log");
        let before = std::fs::read(&path).expect("read corrupt log");

        assert!(matches!(
            JsonLog::<Line>::read(&path),
            Err(MuxError::Wal(_))
        ));
        assert_eq!(
            std::fs::read(&path).expect("reread corrupt log"),
            before,
            "durable corruption must not be discarded"
        );
    }

    /// A write lands atomically and carries the mode, and it replaces whatever was there.
    #[test]
    fn a_write_replaces_its_target_through_a_temporary() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = tempfile::tempdir().expect("scratch directory");
        let root = scratch.path();
        let source = root.join("source.txt");
        let target = root.join("nested/target.txt");
        std::fs::write(&source, b"new\n").expect("source");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
            .expect("mark executable");

        apply_write(&source, &target).expect("apply write");
        assert_eq!(std::fs::read(&target).expect("read target"), b"new\n");
        assert_eq!(
            std::fs::metadata(&target)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the mode is part of the entry the diff compared"
        );
        assert!(
            !target
                .with_file_name(format!("target.txt{TEMPORARY_SUFFIX}"))
                .exists(),
            "the temporary is renamed away, never left behind"
        );
    }
}
