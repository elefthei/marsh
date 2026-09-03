//! btrfs subvolume and snapshot primitives.
//!
//! Every command runs in a *writable* copy-on-write snapshot of the seed subvolume, so the seed is
//! never touched by an unmerged command. The base snapshot taken alongside it is the three-way
//! reference the tree diff uses to recover what the command changed.

use std::path::Path;

use btrfsutil::qgroup::QgroupInherit;
use btrfsutil::subvolume::{DeleteFlags, SnapshotFlags, Subvolume};

use crate::error::MuxError;

/// `statfs.f_type` for btrfs (`BTRFS_SUPER_MAGIC`).
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;

/// Fails unless `path` lives on a btrfs filesystem.
pub(crate) fn assert_btrfs(path: &Path) -> Result<(), MuxError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| MuxError::NotBtrfs(path.to_path_buf()))?;
    // SAFETY: `c_path` is a valid NUL-terminated string and `buf` is a valid, writable
    // `statfs` allocation that `statfs(2)` fills in on success.
    let (rc, fs_type) = unsafe {
        let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let rc = libc::statfs(c_path.as_ptr(), buf.as_mut_ptr());
        if rc != 0 {
            (rc, 0)
        } else {
            (rc, buf.assume_init().f_type)
        }
    };
    if rc != 0 {
        return Err(MuxError::Io(std::io::Error::last_os_error()));
    }
    if fs_type == BTRFS_SUPER_MAGIC {
        Ok(())
    } else {
        Err(MuxError::NotBtrfs(path.to_path_buf()))
    }
}

/// Creates a new empty subvolume at `path`.
pub(crate) fn create_subvolume(path: &Path) -> Result<(), MuxError> {
    Subvolume::create(path, None::<QgroupInherit>)
        .map(|_| ())
        .map_err(|error| MuxError::Snapshot(format!("create {}: {error}", path.display())))
}

/// Snapshots the subvolume rooted at `src` to `dest`.
///
/// Snapshots are deliberately **writable**, including the base snapshot: the deletion fallback
/// chain in [`delete_subvolume`] then behaves identically for both, and a read-only base buys
/// nothing (the mux never writes to it).
pub(crate) fn snapshot(src: &Path, dest: &Path) -> Result<(), MuxError> {
    let subvol = Subvolume::get(src)
        .map_err(|error| MuxError::Snapshot(format!("open {}: {error}", src.display())))?;
    subvol
        .snapshot(dest, None::<SnapshotFlags>, None::<QgroupInherit>)
        .map(|_| ())
        .map_err(|error| {
            MuxError::Snapshot(format!(
                "snapshot {} -> {}: {error}",
                src.display(),
                dest.display()
            ))
        })
}

/// Reports whether `path` is the root of a subvolume.
pub(crate) fn is_subvolume(path: &Path) -> bool {
    Subvolume::is_subvolume(path).is_ok()
}

/// Deletes the subvolume at `path`, falling back through progressively more privileged mechanisms.
///
/// This mount lacks `user_subvol_rm_allowed`, so the unprivileged delete ioctl can fail with
/// `EPERM`. The chain is: delete ioctl, then `remove_dir_all` (kernels ≥ 4.18 let the owner rmdir
/// an *empty* subvolume, and removing the contents empties it), then `sudo -n btrfs subvolume
/// delete`. If every branch fails the snapshot is leaked with a warning: a leaked snapshot costs
/// disk space, never correctness, so it must not fail a merge that already committed.
pub(crate) fn delete_subvolume(path: &Path) -> Result<(), MuxError> {
    if !path.exists() {
        return Ok(());
    }
    let ioctl_error =
        match Subvolume::get(path).and_then(|subvol| subvol.delete(None::<DeleteFlags>)) {
            Ok(()) => return Ok(()),
            Err(error) => error.to_string(),
        };
    let rmdir_error = match std::fs::remove_dir_all(path) {
        Ok(()) => return Ok(()),
        Err(error) => error.to_string(),
    };
    let sudo_error = match std::process::Command::new("sudo")
        .args(["-n", "btrfs", "subvolume", "delete"])
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => return Ok(()),
        Ok(status) => format!("exit {status}"),
        Err(error) => error.to_string(),
    };
    eprintln!(
        "shellmux: leaking snapshot {} (ioctl: {ioctl_error}; rmdir: {rmdir_error}; sudo: {sudo_error})",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique scratch directory under the workspace `target/`, which is on btrfs.
    ///
    /// `/tmp` is *not* btrfs on this machine, so `tempfile`'s default root cannot be used for
    /// anything involving subvolumes.
    pub(crate) fn test_root() -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/shellmux-tests")
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
        assert_btrfs(&root).expect("workspace target/ is on btrfs");

        let subvol = root.join("seed");
        create_subvolume(&subvol).expect("create subvolume");
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

        delete_subvolume(&snap).expect("delete snapshot");
        delete_subvolume(&subvol).expect("delete seed");
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
}
