//! Terminal-attached transactions: the split [`ShellMux::start_cmd`]/[`ShellMux::conclude_cmd`]
//! path a job-control front-end drives, and the fd-3 instrumentation stream every traced command
//! now has.
//!
//! The claim under test is that splitting the wait out of the transaction changes nothing about the
//! transaction: the same snapshot, translate, authorize, commit pipeline runs, with the same
//! verdicts — including losing a race — while the caller owns the `waitpid`. The fd-3 tests pin the
//! other half of the contract: instrumentation is a *stream*, present for builtins and external
//! processes alike, and never merely absent.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};

use common::Fixture;
use shellmux::{Action, CmdOutcome, Event, Reaped, Resource};

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
    let rc = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2 failed");
    let read_end = relocate_above_fd3(ends[0]);
    let write_end = relocate_above_fd3(ends[1]);
    // SAFETY: `read_end` is open, owned here, and never touched again by number.
    let reader = unsafe { std::fs::File::from_raw_fd(read_end) };
    // SAFETY: `write_end` is open, owned here, and never touched again by number.
    let writer = unsafe { std::fs::File::from_raw_fd(write_end) };
    (reader, writer)
}

/// The split path is the same transaction: a command that edits a path commits with exactly the
/// capability it requested, and the seed carries its bytes.
#[test]
fn start_conclude_commits_like_run_cmd() {
    let fixture = Fixture::new("jobs-commit");
    let mux = fixture.mux();
    let sandbox = common::sandbox(&fixture, "1", "");

    let started = mux
        .start_cmd(&sandbox, "printf 'one\n' > src/file0.txt", None)
        .expect("start command");
    let status = wait_for(started.pid());
    let outcome = mux.conclude_cmd(started, status).expect("conclude command");

    let CmdOutcome::Committed { granted, .. } = &outcome else {
        panic!("expected a commit, got {outcome:?}");
    };
    assert_eq!(
        granted,
        &vec![Event::new(
            "1",
            Action::Edit,
            Resource::from(vec!["src", "file0.txt"])
        )]
    );
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the committed file"),
        "one\n"
    );
}

/// Ctrl-C on a foreground job: the group dies of the signal, and a command that did not finish is
/// rolled back wholesale. The sandbox's snapshot is *not* reclaimed — it belongs to the job, not to
/// the command — and closing the sandbox is what returns it.
#[test]
fn a_signal_killed_job_rolls_back() {
    let fixture = Fixture::new("jobs-signal");
    let mux = fixture.mux();
    let session = fixture.session();
    let sandbox = common::sandbox(&fixture, "1", "");

    let started = mux
        .start_cmd(&sandbox, "sleep 300", None)
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
    let live: Vec<_> = std::fs::read_dir(session.snap())
        .expect("read snapshot directory")
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        session.work(&sandbox.uid).is_dir(),
        "the sandbox keeps its snapshot across a command"
    );
    assert_eq!(
        live,
        vec![std::ffi::OsString::from(&sandbox.uid)],
        "a sandbox has exactly one snapshot, and nothing beside it"
    );

    mux.close_sandbox(&sandbox);
    let snapshots: Vec<_> = std::fs::read_dir(session.snap())
        .expect("read snapshot directory")
        .flatten()
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        snapshots.is_empty(),
        "closing a sandbox reclaims its snapshot, found {snapshots:?}"
    );
}

/// fd 3 is a stream, not a special case: a brush *builtin* redirecting to it resolves through the
/// patched file table, and an *external* child inherits the very same descriptor.
#[test]
fn fd3_is_a_standard_stream() {
    let fixture = Fixture::new("jobs-fd3");
    let mux = fixture.mux();
    let sandbox = common::sandbox(&fixture, "1", "");
    let (mut read_end, write_end) = instrumentation_pipe();

    let started = mux
        .start_cmd(
            &sandbox,
            "echo builtin >&3 && sh -c 'echo external >&3'",
            Some(std::os::fd::AsRawFd::as_raw_fd(&write_end)),
        )
        .expect("start command");
    let status = wait_for(started.pid());
    let outcome = mux.conclude_cmd(started, status).expect("conclude command");

    let CmdOutcome::Committed { granted, .. } = &outcome else {
        panic!("expected a commit, got {outcome:?}");
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
}

/// Two open transactions over one path behave exactly as two console jobs do: the first to conclude
/// commits, the second is told its snapshot went stale and which path lost the race.
#[test]
fn concurrent_started_cmds_race_like_tabs() {
    let fixture = Fixture::new("jobs-race");
    let mux = fixture.mux();
    let one = common::sandbox(&fixture, "1", "");
    let two = common::sandbox(&fixture, "2", "");

    // Both snapshot before either commits, so both carry the same base sequence number.
    let first = mux
        .start_cmd(&one, "printf 'first\n' > src/file1.txt", None)
        .expect("start first command");
    let second = mux
        .start_cmd(&two, "printf 'second\n' > src/file1.txt", None)
        .expect("start second command");
    let first_status = wait_for(first.pid());
    let second_status = wait_for(second.pid());

    let first_outcome = mux
        .conclude_cmd(first, first_status)
        .expect("conclude first");
    assert!(
        matches!(first_outcome, CmdOutcome::Committed { .. }),
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
        std::fs::read_to_string(fixture.seed("src/file1.txt")).expect("read the committed file"),
        "first\n"
    );
}

/// Disjoint paths conflict now: the reference is the seed itself, so a transaction that landed after this
/// command snapshotted appears in its write set as a change it never made — here as a *removal* of
/// the winner's new file, since the loser's snapshot predates it. The staleness check is what stops
/// that write set from reverting the winner.
#[test]
fn a_commit_invalidates_every_older_snapshot() {
    let fixture = Fixture::new("jobs-disjoint");
    let mux = fixture.mux();
    let one = common::sandbox(&fixture, "1", "");
    let two = common::sandbox(&fixture, "2", "");

    let first = mux
        .start_cmd(&one, "printf 'a\n' > src/a.txt", None)
        .expect("start first command");
    let second = mux
        .start_cmd(&two, "printf 'b\n' > src/b.txt", None)
        .expect("start second command");
    let first_status = wait_for(first.pid());
    let second_status = wait_for(second.pid());

    let first_outcome = mux
        .conclude_cmd(first, first_status)
        .expect("conclude first");
    assert!(
        matches!(first_outcome, CmdOutcome::Committed { .. }),
        "the first to conclude wins, got {first_outcome:?}"
    );

    let second_outcome = mux
        .conclude_cmd(second, second_status)
        .expect("conclude second");
    let CmdOutcome::StaleSnapshot { stale, .. } = &second_outcome else {
        panic!("expected a stale snapshot, got {second_outcome:?}");
    };
    assert!(
        stale.iter().any(|path| path.path == "src/a.txt"),
        "the winner's path is what invalidated it, got {stale:?}"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/a.txt")).expect("read the winner's file"),
        "a\n"
    );
    assert!(
        !fixture.seed("src/b.txt").exists(),
        "the loser committed nothing"
    );
}

/// The library and batch path gets fd 3 too, wired to `/dev/null`: instrumentation writes vanish
/// rather than failing, so a command's behavior never depends on whether a console is listening.
#[test]
fn piped_jobs_get_dev_null_instrumentation() {
    let fixture = Fixture::new("jobs-devnull");
    let mux = fixture.mux();
    let sandbox = common::sandbox(&fixture, "1", "");

    let outcome = mux.run_cmd(&sandbox, "echo x >&3").expect("run command");

    let CmdOutcome::Committed {
        exit_code, stdout, ..
    } = &outcome
    else {
        panic!("expected a commit, got {outcome:?}");
    };
    assert_eq!(*exit_code, 0, "no BadFileDescriptor: fd 3 exists");
    assert!(
        stdout.is_empty(),
        "instrumentation must not leak into stdout, got {:?}",
        String::from_utf8_lossy(stdout)
    );
}

/// The two halves of a job's start are separate so a console can answer its line between them: the
/// row is in the table with its name taken and `starting` set, and no tracer exists until
/// `launch_into` runs — which then makes it an ordinary transaction.
#[test]
fn a_job_opened_for_a_command_is_in_the_table_before_it_starts() {
    let fixture = Fixture::new("jobs-reserve");
    let mux = fixture.mux();
    let cmd = "printf 'one\n' > src/file0.txt";

    mux.spawn("", Some("bg".to_string()), Some(cmd))
        .expect("open a job for a command");
    let opened = mux.job("bg").expect("the job is in the table");
    assert!(
        opened.starting,
        "opened for a command, so it reports starting"
    );
    assert!(opened.running.is_none(), "no tracer exists yet");
    assert!(
        mux.spawn("", Some("bg".to_string()), None).is_err(),
        "the name is taken from the moment the job is opened"
    );

    mux.launch_into("bg", cmd, None)
        .expect("launch into the job");
    let Some(Reaped::Ended {
        started, status, ..
    }) = mux.wait_for_job("bg")
    else {
        panic!("the launched command should end");
    };
    let outcome = mux.conclude_cmd(*started, status).expect("conclude");
    assert!(
        matches!(outcome, CmdOutcome::Committed { .. }),
        "the launched command is an ordinary transaction, got {outcome:?}"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed"),
        "one\n"
    );
}
