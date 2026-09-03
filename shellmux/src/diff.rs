//! What a command changed, recovered by comparing its work snapshot against the base snapshot.
//!
//! The base snapshot is taken from the same quiescent seed as the work snapshot, so any difference
//! between them was produced by the command — including differences under `.git/`, which must merge
//! for a committed history to survive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::MuxError;

/// One filesystem change to apply to the seed. Paths are seed-relative and `/`-joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MergeOp {
    /// Copy the work snapshot's version of this path over the seed's.
    Write(String),
    /// Delete this path from the seed.
    Remove(String),
}

/// A non-directory tree entry, at the granularity differences are detected.
#[derive(PartialEq, Eq)]
enum Entry {
    /// Regular file: length and permission bits (contents compared separately).
    File(u64, u32),
    /// Symlink and its target.
    Symlink(PathBuf),
    /// Anything else (fifo, socket, device): compared by mode only.
    Other(u32),
}

/// Computes the changes that turn `base` into `work`.
///
/// Directories are implicit: a [`MergeOp::Write`] creates the parents it needs, and directories left
/// empty by a [`MergeOp::Remove`] are pruned. A command that creates an *empty* directory and
/// nothing else therefore merges as a no-op — the one tree shape this representation cannot carry.
///
/// Ordering is total and deterministic: removals first, deepest paths first (so a directory is
/// emptied before it is pruned), then writes shallowest first (so parents exist before children).
pub(crate) fn diff_trees(base: &Path, work: &Path) -> Result<Vec<MergeOp>, MuxError> {
    let base_entries = collect(base)?;
    let work_entries = collect(work)?;

    let mut removes: Vec<String> = Vec::new();
    let mut writes: Vec<String> = Vec::new();

    for (path, base_entry) in &base_entries {
        match work_entries.get(path) {
            None => removes.push(path.clone()),
            Some(work_entry) => {
                if base_entry != work_entry
                    || contents_differ(base_entry, &base.join(path), &work.join(path))?
                {
                    writes.push(path.clone());
                }
            }
        }
    }
    for path in work_entries.keys() {
        if !base_entries.contains_key(path) {
            writes.push(path.clone());
        }
    }

    removes.sort_by(|left, right| depth_key(right).cmp(&depth_key(left)));
    writes.sort_by(|left, right| depth_key(left).cmp(&depth_key(right)));

    let mut ops = Vec::with_capacity(removes.len() + writes.len());
    ops.extend(removes.into_iter().map(MergeOp::Remove));
    ops.extend(writes.into_iter().map(MergeOp::Write));
    Ok(ops)
}

/// Sort key placing shallower paths first, ties broken lexicographically.
fn depth_key(path: &str) -> (usize, &str) {
    (path.split('/').count(), path)
}

/// Indexes every non-directory entry of `root` by its `/`-joined relative path.
fn collect(root: &Path) -> Result<BTreeMap<String, Entry>, MuxError> {
    let mut entries = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = entry.path().symlink_metadata()?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                stack.push((entry.path(), relative));
            } else if file_type.is_symlink() {
                entries.insert(relative, Entry::Symlink(std::fs::read_link(entry.path())?));
            } else if file_type.is_file() {
                entries.insert(relative, Entry::File(metadata.len(), mode(&metadata)));
            } else {
                entries.insert(relative, Entry::Other(mode(&metadata)));
            }
        }
    }
    Ok(entries)
}

/// Permission bits of an entry.
fn mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o7777
}

/// Compares regular-file contents; other entry kinds are already fully compared by their metadata.
fn contents_differ(entry: &Entry, base: &Path, work: &Path) -> Result<bool, MuxError> {
    match entry {
        Entry::File(..) => Ok(std::fs::read(base)? != std::fs::read(work)?),
        Entry::Symlink(_) | Entry::Other(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::snapshot::tests::test_root;

    fn write(root: &Path, path: &str, contents: &str) {
        let target = root.join(path);
        std::fs::create_dir_all(target.parent().expect("has a parent")).expect("create parents");
        std::fs::write(target, contents).expect("write file");
    }

    #[test]
    fn detects_creations_modifications_and_deletions() {
        let root = test_root();
        let base = root.join("base");
        let work = root.join("work");
        write(&base, "src/keep.txt", "same");
        write(&base, "src/change.txt", "old");
        write(&base, "src/gone.txt", "bye");
        write(&base, ".git/index", "old-index");
        write(&work, "src/keep.txt", "same");
        write(&work, "src/change.txt", "new-longer");
        write(&work, "src/new/deep.txt", "fresh");
        write(&work, ".git/index", "new-index");

        let ops = diff_trees(&base, &work).expect("diff");
        assert_eq!(
            ops,
            vec![
                MergeOp::Remove("src/gone.txt".to_string()),
                MergeOp::Write(".git/index".to_string()),
                MergeOp::Write("src/change.txt".to_string()),
                MergeOp::Write("src/new/deep.txt".to_string()),
            ],
            "git metadata merges like any other path; unchanged paths are absent"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn detects_same_length_content_changes_and_mode_changes() {
        let root = test_root();
        let base = root.join("base");
        let work = root.join("work");
        write(&base, "a.txt", "aaa");
        write(&work, "a.txt", "bbb");
        write(&base, "b.sh", "x");
        write(&work, "b.sh", "x");
        std::fs::set_permissions(
            work.join("b.sh"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("chmod");

        let ops = diff_trees(&base, &work).expect("diff");
        assert_eq!(
            ops,
            vec![
                MergeOp::Write("a.txt".to_string()),
                MergeOp::Write("b.sh".to_string()),
            ],
            "equal length is not equal content, and mode is part of the entry"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn orders_deep_removals_before_shallow_ones_and_parents_before_children() {
        let root = test_root();
        let base = root.join("base");
        let work = root.join("work");
        write(&base, "d/x/deep.txt", "gone");
        write(&base, "d/mid.txt", "gone");
        write(&base, "top.txt", "gone");
        write(&work, "n/n2/leaf.txt", "new");
        write(&work, "n/one.txt", "new");
        write(&work, "root.txt", "new");

        let ops = diff_trees(&base, &work).expect("diff");
        assert_eq!(
            ops,
            vec![
                MergeOp::Remove("d/x/deep.txt".to_string()),
                MergeOp::Remove("d/mid.txt".to_string()),
                MergeOp::Remove("top.txt".to_string()),
                MergeOp::Write("root.txt".to_string()),
                MergeOp::Write("n/one.txt".to_string()),
                MergeOp::Write("n/n2/leaf.txt".to_string()),
            ]
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn detects_symlink_target_changes_and_type_changes() {
        let root = test_root();
        let base = root.join("base");
        let work = root.join("work");
        write(&base, "target1", "one");
        write(&work, "target1", "one");
        std::fs::create_dir_all(&base).expect("base dir");
        std::os::unix::fs::symlink("target1", base.join("link")).expect("base symlink");
        std::os::unix::fs::symlink("target2", work.join("link")).expect("work symlink");
        // A directory in the base becomes a plain file in the work snapshot.
        write(&base, "swap/inner.txt", "dir-side");
        write(&work, "swap", "file-side");

        let ops = diff_trees(&base, &work).expect("diff");
        assert_eq!(
            ops,
            vec![
                MergeOp::Remove("swap/inner.txt".to_string()),
                MergeOp::Write("link".to_string()),
                MergeOp::Write("swap".to_string()),
            ],
            "a retargeted symlink is a write; a directory replaced by a file empties then writes"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn identical_trees_produce_no_operations() {
        let root = test_root();
        let base = root.join("base");
        let work = root.join("work");
        write(&base, "src/a.txt", "same");
        write(&work, "src/a.txt", "same");
        assert!(diff_trees(&base, &work).expect("diff").is_empty());
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}
