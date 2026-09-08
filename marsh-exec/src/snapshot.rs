//! btrfs subvolume and snapshot primitives.
//!
//! The seed is the user's own subvolume; marsh creates only snapshots of it. Every command runs in
//! a *writable* copy-on-write snapshot, so the seed is never touched by a command that has not
//! committed.

use std::path::Path;

use btrfsutil::qgroup::QgroupInherit;
use btrfsutil::subvolume::{DeleteFlags, SnapshotFlags, Subvolume};
use proc_mounts::{MountInfo, MountIter};

use crate::error::ExecError;

/// `statfs.f_type` for btrfs (`BTRFS_SUPER_MAGIC`).
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;

/// Fails unless `path` lives on a btrfs filesystem.
pub(crate) fn assert_btrfs(path: &Path) -> Result<(), ExecError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ExecError::NotBtrfs(path.to_path_buf()))?;
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated string and `buf` is a valid, writable `statfs`
    // allocation that `statfs(2)` fills in on success.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(ExecError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `statfs(2)` returned success, so it initialized every field of `buf`.
    let fs_type = unsafe { buf.assume_init() }.f_type;
    if fs_type == BTRFS_SUPER_MAGIC {
        Ok(())
    } else {
        Err(ExecError::NotBtrfs(path.to_path_buf()))
    }
}

/// The mount that contains `path`, chosen by the longest matching mount point.
///
/// The match is component-wise (`Path::starts_with` compares whole components), so `/homer` is
/// never treated as living under `/home`. On a tie the later line wins: a mount stacked on an
/// existing mount point shadows the one below it.
fn containing_mount(mounts: impl Iterator<Item = MountInfo>, path: &Path) -> Option<MountInfo> {
    let mut best: Option<(usize, MountInfo)> = None;
    for mount in mounts {
        if !path.starts_with(&mount.dest) {
            continue;
        }
        let depth = mount.dest.components().count();
        if best
            .as_ref()
            .is_none_or(|(best_depth, _)| depth >= *best_depth)
        {
            best = Some((depth, mount));
        }
    }
    best.map(|(_, mount)| mount)
}

/// Every mount `/proc/mounts` describes, skipping lines that cannot be parsed.
///
/// `/proc/mounts` rather than `/proc/self/mountinfo` because its single options field merges the
/// per-mount and super options that mountinfo splits apart, and `user_subvol_rm_allowed` lives only
/// in the super half. Unparsable lines are skipped rather than fatal: one exotic mount elsewhere on
/// the machine must not stop marsh from starting.
fn mounts() -> Result<impl Iterator<Item = MountInfo>, ExecError> {
    Ok(MountIter::new()
        .map_err(ExecError::Io)?
        .filter_map(Result::ok))
}

/// Fails unless `path`'s mount carries `user_subvol_rm_allowed`.
///
/// Snapshot deletion goes through the unprivileged ioctl, which returns `EPERM` without this
/// option; checking it once at startup turns a mid-session failure into a startup message.
pub(crate) fn assert_user_subvol_rm_allowed(path: &Path) -> Result<(), ExecError> {
    let allowed = containing_mount(mounts()?, path).is_some_and(|mount| {
        // Whole entries, not substrings: a hypothetical `nouser_subvol_rm_allowed` must not pass.
        mount
            .options
            .iter()
            .any(|option| option == "user_subvol_rm_allowed")
    });
    if allowed {
        Ok(())
    } else {
        Err(ExecError::NotUserSubvolRmAllowed(path.to_path_buf()))
    }
}

/// Whether `path` is the root of a btrfs subvolume.
///
/// `btrfs_util_is_subvolume` is a `stat`/`statfs` check and needs no privilege, which is what lets
/// the seed walk run as the user. Anything that is not a subvolume root — a plain directory, a
/// missing path, a path on another filesystem — answers `false`.
pub(crate) fn is_subvolume(path: &Path) -> bool {
    Subvolume::is_subvolume(path).is_ok()
}

/// Whether `path` is the root of the mount that contains it.
///
/// A seed that is its own mount root has no usable parent directory: marsh's state would land on
/// whatever filesystem the mount point sits in, outside the seed's own subvolume tree.
pub(crate) fn is_mount_root(path: &Path) -> Result<bool, ExecError> {
    Ok(containing_mount(mounts()?, path).is_some_and(|mount| mount.dest == path))
}

/// Snapshots the subvolume rooted at `src` to `dest`.
///
/// Snapshots are deliberately **writable**: a command runs inside its own snapshot and writes into
/// it, which a read-only snapshot would refuse.
///
/// # Errors
///
/// Fails with [`ExecError::Snapshot`] when `src` cannot be opened as a subvolume or the snapshot
/// ioctl is refused.
pub fn snapshot(src: &Path, dest: &Path) -> Result<(), ExecError> {
    let subvol = Subvolume::get(src)
        .map_err(|error| ExecError::Snapshot(format!("open {}: {error}", src.display())))?;
    subvol
        .snapshot(dest, None::<SnapshotFlags>, None::<QgroupInherit>)
        .map(|_| ())
        .map_err(|error| {
            ExecError::Snapshot(format!(
                "snapshot {} -> {}: {error}",
                src.display(),
                dest.display()
            ))
        })
}

/// Deletes the subvolume at `path`, falling back through progressively more privileged mechanisms.
///
/// The unprivileged delete ioctl is the normal path; the fallbacks cover a mount whose options
/// changed under a running session. The chain is: delete ioctl, then `remove_dir_all` (kernels ≥
/// 4.18 let the owner rmdir an *empty* subvolume, and removing the contents empties it), then
/// `sudo -n btrfs subvolume delete`. If every branch fails the snapshot is leaked with a warning:
/// a leaked snapshot costs disk space, never correctness, so it must not fail a merge that already
/// committed.
pub fn delete_subvolume(path: &Path) {
    if !path.exists() {
        return;
    }
    let ioctl_error =
        match Subvolume::get(path).and_then(|subvol| subvol.delete(None::<DeleteFlags>)) {
            Ok(()) => return,
            Err(error) => error.to_string(),
        };
    let rmdir_error = match std::fs::remove_dir_all(path) {
        Ok(()) => return,
        Err(error) => error.to_string(),
    };
    let sudo_error = match std::process::Command::new("sudo")
        .args(["-n", "btrfs", "subvolume", "delete"])
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => return,
        Ok(status) => format!("exit {status}"),
        Err(error) => error.to_string(),
    };
    eprintln!(
        "marsh-exec: leaking snapshot {} (ioctl: {ioctl_error}; rmdir: {rmdir_error}; sudo: {sudo_error})",
        path.display()
    );
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique scratch directory under the workspace's `target/tmp`.
    ///
    /// `/tmp` is not btrfs on a typical machine, so `tempfile`'s default root cannot be used for
    /// anything involving subvolumes. `target/tmp` is where cargo points `CARGO_TARGET_TMPDIR` for
    /// the integration tests, and therefore where CI mounts its loopback btrfs — a unit test has no
    /// `CARGO_TARGET_TMPDIR`, so it reconstructs the same directory rather than picking its own.
    pub(crate) fn test_root() -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/tmp/marsh-exec-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).expect("create test root");
        root
    }

    /// Retires both environment risks in one test: btrfs snapshots work unprivileged here, and
    /// `strace` can trace a child. Also pins which branch of the deletion chain this machine takes.
    #[test]
    fn smoke_btrfs_and_strace() {
        let root = test_root();
        assert_btrfs(&root).expect("the workspace target/tmp is on btrfs");

        let subvol = root.join("seed");
        Subvolume::create(&*subvol, None::<QgroupInherit>).expect("create subvolume");
        assert!(is_subvolume(&subvol), "created path is a subvolume");
        std::fs::write(subvol.join("a.txt"), b"seed\n").expect("write seed file");

        let snap = root.join("work");
        snapshot(&subvol, &snap).expect("snapshot subvolume");
        assert!(is_subvolume(&snap), "snapshot is a subvolume");
        assert_eq!(
            std::fs::read(snap.join("a.txt")).expect("read snapshot file"),
            b"seed\n",
            "snapshot sees the seed's content"
        );
        std::fs::write(snap.join("a.txt"), b"work\n").expect("snapshot is writable");
        assert_eq!(
            std::fs::read(subvol.join("a.txt")).expect("read seed file"),
            b"seed\n",
            "writing the snapshot does not touch the seed"
        );

        delete_subvolume(&snap);
        delete_subvolume(&subvol);
        assert!(!snap.exists(), "snapshot removed");
        assert!(!subvol.exists(), "seed removed");

        let trace = root.join("trace.log");
        let status = std::process::Command::new("strace")
            .args(["-f", "-e", "trace=%file", "-o"])
            .arg(&trace)
            .args(["--", "/bin/true"])
            .status()
            .expect("spawn strace");
        assert!(status.success(), "strace ran /bin/true: {status}");
        let text = std::fs::read_to_string(&trace).expect("read trace");
        assert!(!text.is_empty(), "strace recorded syscalls");

        std::fs::remove_dir_all(&root).expect("clean test root");
    }

    /// A subvolume is not a mount point, so the containing mount has to be found by longest
    /// prefix; an exact-match lookup would find nothing for a seed inside `/home`.
    #[test]
    fn the_containing_mount_is_the_longest_matching_one() {
        let fixture = concat!(
            "/dev/sda1 / ext4 rw,relatime 0 0\n",
            "/dev/loop3 /home btrfs rw,noatime,user_subvol_rm_allowed,subvol=/@home 0 0\n",
        );
        let mounts = |text: &'static str| {
            proc_mounts::MountIter::new_from_reader(std::io::BufReader::new(text.as_bytes()))
                .filter_map(Result::ok)
        };

        let found = containing_mount(mounts(fixture), Path::new("/home/someone/work"))
            .expect("a seed inside /home is covered by the /home mount");
        assert_eq!(found.dest, Path::new("/home"));
        assert!(
            found
                .options
                .iter()
                .any(|option| option == "user_subvol_rm_allowed")
        );

        let sibling = containing_mount(mounts(fixture), Path::new("/homer"))
            .expect("falls back to the root mount");
        assert_eq!(
            sibling.dest,
            Path::new("/"),
            "a string prefix would have picked /home"
        );
    }
}
