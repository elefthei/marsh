//! Terminal-attached transactions: the split [`ShellMux::start_cmd`]/[`ShellMux::conclude_cmd`]
//! path a job-control front-end drives, and the fd-3 instrumentation stream every traced command
//! now has.
//!
//! The claim under test is that splitting the wait out of the transaction changes nothing about the
//! transaction: the same snapshot, translate, authorize, merge pipeline runs, with the same
//! verdicts — including losing a race — while the caller owns the `waitpid`. The fd-3 tests pin the
//! other half of the contract: instrumentation is a *stream*, present for builtins and external
//! processes alike, and never merely absent.

mod common;

use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;

use common::{mux_root, remove_root, seed_init};
use shellmux::{Action, CmdOutcome, Event, MuxOptions, Principal, Resource, ShellMux};

/// Mux options pointing at the executor this test binary was built alongside.
fn options() -> MuxOptions {
    MuxOptions {
        executor: Some(PathBuf::from(env!("CARGO_BIN_EXE_marsh-exec"))),
        ..MuxOptions::default()
    }
}

/// Blocks until `pid` exits and returns its raw wait status.
fn wait_for(pid: i32) -> i32 {
    let mut status: libc::c_int = 0;
    // SAFETY: `waitpid` writes the status through the pointer we pass and has no other
    // requirements.
    let result = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert!(result == pid, "waitpid({pid}) failed: {result}");
    status
}

/// Moves `fd` above the instrumentation descriptor and closes the original.
///
/// The kernel hands out the lowest free descriptor, so a freshly created pipe usually *is* fd 3 and
/// fd 4. Installing such a write end as a child's instrumentation stream would `dup2` over the read
/// end and the test would then read from its own pipe's write end.
fn relocate_above_fd3(fd: RawFd) -> RawFd {
    // SAFETY: duplicating a descriptor we own to the lowest free number above fd 3.
    let moved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 4) };
    assert!(moved > 3, "relocating fd {fd} failed: {moved}");
    // SAFETY: closing the original descriptor, which nothing else refers to.
    unsafe { libc::close(fd) };
    moved
}

/// A pipe for a child's instrumentation stream: `(read end, write end)`, both above fd 3.
fn instrumentation_pipe() -> (std::fs::File, std::fs::File) {
    let mut ends: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `pipe2` writes exactly two descriptors through the pointer we pass.
    assert_eq!(
        unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "pipe2 failed"
    );
    let read_end = relocate_above_fd3(ends[0]);
    let write_end = relocate_above_fd3(ends[1]);
    // SAFETY: both descriptors are open, owned here, and never touched again by number.
    unsafe {
        (
            std::fs::File::from_raw_fd(read_end),
            std::fs::File::from_raw_fd(write_end),
        )
    }
}

/// The split path is the same transaction: a command that edits a path merges with exactly the
/// capability it requested, and the seed carries its bytes.
#[test]
fn start_conclude_merges_like_run_cmd() {
    let root = mux_root("jobs-merge");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");
    let principal = Principal::from("1");

    let started = mux
        .start_cmd(&principal, "printf 'one\n' > src/file0.txt", None)
        .expect("start command");
    let status = wait_for(started.pid());
    let outcome = mux.conclude_cmd(started, status).expect("conclude command");

    let CmdOutcome::Merged { granted, .. } = &outcome else {
        panic!("expected a merge, got {outcome:?}");
    };
    assert_eq!(
        granted,
        &vec![Event::new(
            principal,
            Action::Edit,
            Resource::from(vec!["src", "file0.txt"])
        )]
    );
    assert_eq!(
        std::fs::read_to_string(root.join("seed/src/file0.txt")).expect("read merged file"),
        "one\n"
    );

    remove_root(&root);
}

/// Ctrl-C on a foreground job: the group dies of the signal, and a command that did not finish is
/// rolled back wholesale — including the snapshots, which `conclude_cmd` owns on every path.
#[test]
fn a_signal_killed_job_rolls_back() {
    let root = mux_root("jobs-signal");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");

    let started = mux
        .start_cmd(&Principal::from("1"), "sleep 300", None)
        .expect("start command");
    let pid = started.pid();
    // The traced child is its own process group, which is what makes a terminal signal reach the
    // tracer and everything it traces at once.
    // SAFETY: `kill` with a negated pid signals that process group.
    assert_eq!(unsafe { libc::kill(-pid, libc::SIGINT) }, 0, "kill failed");
    let status = wait_for(pid);
    let outcome = mux.conclude_cmd(started, status).expect("conclude command");

    let CmdOutcome::ExecFailed { exit_code, .. } = &outcome else {
        panic!("expected a failed execution, got {outcome:?}");
    };
    assert_eq!(*exit_code, 130, "128 + SIGINT");

    let snapshots: Vec<_> = std::fs::read_dir(root.join(".marsh/snaps"))
        .expect("read snapshot directory")
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        snapshots.is_empty(),
        "concluding a killed job must still reclaim its snapshots, found {snapshots:?}"
    );

    remove_root(&root);
}

/// fd 3 is a stream, not a special case: a brush *builtin* redirecting to it resolves through the
/// patched file table, and an *external* child inherits the very same descriptor.
#[test]
fn fd3_is_a_standard_stream() {
    let root = mux_root("jobs-fd3");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");
    let (mut read_end, write_end) = instrumentation_pipe();

    let started = mux
        .start_cmd(
            &Principal::from("1"),
            "echo builtin >&3 && sh -c 'echo external >&3'",
            Some(std::os::fd::AsRawFd::as_raw_fd(&write_end)),
        )
        .expect("start command");
    let status = wait_for(started.pid());
    let outcome = mux.conclude_cmd(started, status).expect("conclude command");

    let CmdOutcome::Merged { granted, .. } = &outcome else {
        panic!("expected a merge, got {outcome:?}");
    };
    assert!(
        granted.is_empty(),
        "writing instrumentation touches no seed path, got {granted:?}"
    );

    // Dropping the only remaining write end is what ends the read; the child's copies died with it.
    drop(write_end);
    let mut instrumentation = String::new();
    read_end
        .read_to_string(&mut instrumentation)
        .expect("read instrumentation");
    assert_eq!(
        instrumentation, "builtin\nexternal\n",
        "the builtin reached fd 3 through the file table, the external child by inheritance"
    );

    remove_root(&root);
}

/// Two open transactions over one path behave exactly as two console jobs do: the first to conclude
/// merges, the second is told its snapshot went stale and which path lost the race.
#[test]
fn concurrent_started_cmds_race_like_tabs() {
    let root = mux_root("jobs-race");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");

    // Both snapshot before either merges, so both carry the same base sequence number.
    let first = mux
        .start_cmd(
            &Principal::from("1"),
            "printf 'first\n' > src/file1.txt",
            None,
        )
        .expect("start first command");
    let second = mux
        .start_cmd(
            &Principal::from("2"),
            "printf 'second\n' > src/file1.txt",
            None,
        )
        .expect("start second command");
    let first_status = wait_for(first.pid());
    let second_status = wait_for(second.pid());

    let first_outcome = mux
        .conclude_cmd(first, first_status)
        .expect("conclude first");
    assert!(
        matches!(first_outcome, CmdOutcome::Merged { .. }),
        "the first to conclude wins, got {first_outcome:?}"
    );

    let second_outcome = mux
        .conclude_cmd(second, second_status)
        .expect("conclude second");
    let CmdOutcome::StaleSnapshot { stale, .. } = &second_outcome else {
        panic!("expected a stale snapshot, got {second_outcome:?}");
    };
    assert!(
        stale.iter().any(|path| path.path == "src/file1.txt"),
        "the conflict must name the path that moved on, got {stale:?}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("seed/src/file1.txt")).expect("read merged file"),
        "first\n"
    );

    remove_root(&root);
}

/// The library and batch path gets fd 3 too, wired to `/dev/null`: instrumentation writes vanish
/// rather than failing, so a command's behavior never depends on whether a console is listening.
#[test]
fn piped_jobs_get_dev_null_instrumentation() {
    let root = mux_root("jobs-devnull");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");

    let outcome = mux
        .run_cmd(&Principal::from("1"), "echo x >&3")
        .expect("run command");

    let CmdOutcome::Merged {
        exit_code, stdout, ..
    } = &outcome
    else {
        panic!("expected a merge, got {outcome:?}");
    };
    assert_eq!(*exit_code, 0, "no BadFileDescriptor: fd 3 exists");
    assert!(
        stdout.is_empty(),
        "instrumentation must not leak into stdout, got {:?}",
        String::from_utf8_lossy(stdout)
    );

    remove_root(&root);
}
