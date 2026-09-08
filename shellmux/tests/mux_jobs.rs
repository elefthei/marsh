//! Jobs as a front-end drives them: `spawn`, `start_in`, `stop` and `wait_for_job`, over the
//! pseudoterminal and the instrumentation stream every job owns.
//!
//! The claim under test is that owning the wait changes nothing about the transaction: the same
//! snapshot, translate, authorize, commit pipeline runs, with the same verdicts — including losing a
//! race — while the caller only ever observes. The terminal tests pin the other half of the
//! contract: one geometry for the whole mux, output that survives byte for byte, and
//! instrumentation that is a *stream*, present for builtins and external processes alike and never
//! mixed into the output a reader is looking at.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{COLS, Fixture, ROWS};
use shellmux::{
    Action, CmdOutcome, Event, MuxError, PurityCheckerBuilder, Reaped, Resource, ShellId, ShellMux,
    Spawned,
};

/// How long a job test waits for something it requires before declaring the claim unmet.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A command that holds its job open long enough for another job to snapshot beside it.
///
/// Long enough that the *other* command runs, ends and merges first: which of two open transactions
/// concludes first is what decides the race, so it has to be decided by the test rather than by
/// scheduling.
const HOLD: &str = "sleep 5";

/// The process group of the command running in job `id`.
fn running_pid(mux: &ShellMux, id: &ShellId) -> libc::pid_t {
    mux.job(id)
        .and_then(|view| view.running)
        .unwrap_or_else(|| panic!("{id} is running a command"))
        .pid
}

/// One completion: the exit status a waiter observed, and the transaction that produced it.
///
/// Shared rather than owned, because a completion is announced to every handle of the job at once
/// and a committed outcome carries the command's whole captured output.
type Completion = (i32, Arc<Result<CmdOutcome, MuxError>>);

/// Waits for `job`'s command to end, and reports what it ended as.
async fn concluded(mux: &Arc<ShellMux>, job: &mut Spawned) -> Completion {
    let Some(Reaped {
        exit_code, outcome, ..
    }) = mux.wait_for_job(job).await
    else {
        panic!("{} produced no completion", job.id);
    };
    (exit_code, outcome)
}

/// The transaction a completion carries, failing the test when the conclusion itself broke.
fn transaction(result: &Arc<Result<CmdOutcome, MuxError>>) -> &CmdOutcome {
    result
        .as_ref()
        .as_ref()
        .unwrap_or_else(|error| panic!("the conclusion failed: {error}"))
}

/// Drains `job`'s terminal until `done` accepts everything read so far, and returns it.
async fn drain_output(
    mux: &Arc<ShellMux>,
    job: &Spawned,
    label: &str,
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut seen: Vec<u8> = Vec::new();
    while !done(&seen) {
        let mut buffer = [0_u8; 4096];
        let read = tokio::time::timeout_at(deadline, mux.read_output(job, &mut buffer))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{label}: timed out with {:?}",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read the job's terminal");
        assert!(
            read > 0,
            "{label}: end of terminal after {:?}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&buffer[..read]);
    }
    seen
}

/// Drains `job`'s instrumentation stream until it holds at least `wanted` bytes.
async fn drain_instrumentation(mux: &Arc<ShellMux>, job: &Spawned, wanted: usize) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut seen: Vec<u8> = Vec::new();
    while seen.len() < wanted {
        let mut buffer = [0_u8; 4096];
        let read = tokio::time::timeout_at(deadline, mux.read_instrumentation(job, &mut buffer))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "instrumentation timed out with {:?}",
                    String::from_utf8_lossy(&seen)
                )
            })
            .expect("read the job's instrumentation");
        assert!(
            read > 0,
            "instrumentation ended after {:?}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&buffer[..read]);
    }
    seen
}

/// Runs `cmd` in job `id` and returns the first line its terminal produced.
async fn run_line(mux: &Arc<ShellMux>, id: &ShellId, job: &mut Spawned, cmd: &str) -> String {
    mux.start_in(id, cmd)
        .await
        .unwrap_or_else(|error| panic!("start {cmd:?} in {id}: {error}"));
    let seen = drain_output(mux, job, cmd, |bytes| bytes.contains(&b'\n')).await;
    let (_, result) = concluded(mux, job).await;
    let outcome = transaction(&result);
    assert!(
        !matches!(outcome, CmdOutcome::ExecFailed { .. }),
        "{cmd:?} in {id} failed: {outcome:?}"
    );
    let text = String::from_utf8_lossy(&seen).into_owned();
    text.lines().next().unwrap_or_default().trim().to_string()
}

/// The terminal geometry job `id` reports, as `"<rows> <cols>"`.
async fn size_of_job(mux: &Arc<ShellMux>, id: &ShellId, job: &mut Spawned) -> String {
    run_line(mux, id, job, "stty size").await
}

/// Waits until `predicate` holds.
///
/// What a test uses for work the mux finishes *after* it has published a result: a completion is
/// announced as soon as the transaction is concluded, and the storage it held is reclaimed next.
async fn eventually(label: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !predicate() {
        assert!(tokio::time::Instant::now() < deadline, "{label}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The job path is the same transaction: a command that edits a path commits with exactly the
/// capability it requested, and the seed carries its bytes.
#[test]
fn a_job_command_commits_like_run_cmd() {
    mux_test!(fixture = Fixture::new("jobs-commit"), {
        let mux = fixture.mux();
        let id = ShellId::from("1");
        let mut job = mux
            .spawn("", Some(id.clone()), Some("printf 'one\n' > src/file0.txt"))
            .await
            .expect("open a job for a command");

        let (_, result) = concluded(mux, &mut job).await;
        let outcome = transaction(&result);
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
            std::fs::read_to_string(fixture.seed("src/file0.txt"))
                .expect("read the committed file"),
            "one\n"
        );
    });
}

/// Ctrl-C on a foreground job: the group dies of the signal, and a command that did not finish is
/// rolled back wholesale. The sandbox's snapshot is *not* reclaimed — it belongs to the job, not to
/// the command — and stopping the job is what returns it.
#[test]
fn a_signal_killed_job_rolls_back() {
    mux_test!(fixture = Fixture::new("jobs-signal"), {
        let mux = fixture.mux();
        let persistence = fixture.persistence();
        let id = ShellId::from("1");
        let mut job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open the job");
        mux.start_in(&id, "sleep 300")
            .await
            .expect("start the command");

        // The traced child is its own process group, which is what makes a terminal signal reach
        // the tracer and everything it traces at once.
        let pid = running_pid(mux, &id);
        // SAFETY: `kill` with a negated pid signals that process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGINT) }, 0, "kill failed");

        let (observed, result) = concluded(mux, &mut job).await;
        let outcome = transaction(&result);
        let CmdOutcome::ExecFailed { exit_code, .. } = &outcome else {
            panic!("expected a failed execution, got {outcome:?}");
        };
        assert_eq!(*exit_code, 130, "128 + SIGINT");
        assert_eq!(observed, 130, "and that is what the waiter observed");

        let live: Vec<_> = std::fs::read_dir(persistence.snap())
            .expect("read snapshot directory")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            persistence.work(&job.sandbox.uid).is_dir(),
            "the sandbox keeps its snapshot across a command"
        );
        assert_eq!(
            live,
            vec![std::ffi::OsString::from(&job.sandbox.uid)],
            "a sandbox has exactly one snapshot, and nothing beside it"
        );

        mux.stop(&id, false).await.expect("stop the idle job");
        let snapshots: Vec<_> = std::fs::read_dir(persistence.snap())
            .expect("read snapshot directory")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            snapshots.is_empty(),
            "closing a job reclaims its snapshot, found {snapshots:?}"
        );
    });
}

/// fd 3 is a stream, not a special case: a brush *builtin* redirecting to it resolves through the
/// patched file table, an *external* child inherits the very same descriptor, and neither byte
/// reaches the terminal a reader is watching.
#[test]
fn fd3_is_a_standard_stream_beside_the_terminal() {
    mux_test!(fixture = Fixture::new("jobs-fd3"), {
        /// A builtin write, an external write, and a final payload with no newline to end it.
        const CMD: &str =
            "echo builtin >&3; sh -c 'printf external >&3'; printf out; printf err >&2";
        /// Exactly what fd 3 must carry: the newline is the builtin's, and nothing follows.
        const INSTRUMENTATION: &[u8] = b"builtin\nexternal";

        let mux = fixture.mux();
        let id = ShellId::from("1");
        let mut job = mux
            .spawn("", Some(id.clone()), Some(CMD))
            .await
            .expect("open a job for a command");

        let instrumentation = drain_instrumentation(mux, &job, INSTRUMENTATION.len()).await;
        assert_eq!(
            instrumentation, INSTRUMENTATION,
            "the builtin reached fd 3 through the file table, the external child by inheritance"
        );

        let output = drain_output(mux, &job, CMD, |bytes| {
            let text = String::from_utf8_lossy(bytes);
            text.contains("out") && text.contains("err")
        })
        .await;
        let output = String::from_utf8_lossy(&output).into_owned();
        assert!(
            !output.contains("builtin") && !output.contains("external"),
            "instrumentation must not reach the terminal, got {output:?}"
        );

        let (_, result) = concluded(mux, &mut job).await;
        let outcome = transaction(&result);
        let CmdOutcome::Committed { granted, .. } = &outcome else {
            panic!("expected a commit, got {outcome:?}");
        };
        assert!(
            granted.is_empty(),
            "writing instrumentation touches no seed path, got {granted:?}"
        );
    });
}

/// A terminal carries bytes, not text: a full-screen program's escape sequences and a byte that is
/// not UTF-8 at all come back exactly as they were written.
#[test]
fn terminal_output_is_preserved_byte_for_byte() {
    mux_test!(fixture = Fixture::new("jobs-bytes"), {
        /// Alternate screen on, clear, cursor to 10;20, a non-UTF-8 byte, alternate screen off.
        const PAYLOAD: &[u8] = b"\x1b[?1049h\x1b[2J\x1b[10;20Hmarker\xff\x1b[?1049l";

        let mux = fixture.mux();
        let id = ShellId::from("1");
        let mut job = mux
            .spawn(
                "",
                Some(id.clone()),
                Some(r"printf '\033[?1049h\033[2J\033[10;20Hmarker\377\033[?1049l'"),
            )
            .await
            .expect("open a job for a command");

        let output = drain_output(mux, &job, "escape sequences", |bytes| {
            bytes.windows(PAYLOAD.len()).any(|window| window == PAYLOAD)
        })
        .await;
        assert!(
            output.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
            "the terminal rewrote the byte stream: {output:?}"
        );

        let (exit_code, _) = concluded(mux, &mut job).await;
        assert_eq!(exit_code, 0);
    });
}

/// Two open transactions over one path behave exactly as two console jobs do: the first to conclude
/// commits, the second is told its snapshot went stale and which path lost the race.
#[test]
fn concurrent_job_commands_race_like_tabs() {
    mux_test!(fixture = Fixture::new("jobs-race"), {
        let mux = fixture.mux();
        let slow = ShellId::from("slow");
        let quick = ShellId::from("quick");
        let mut slow_job = mux
            .spawn("", Some(slow.clone()), None)
            .await
            .expect("open the slow job");
        let mut quick_job = mux
            .spawn("", Some(quick.clone()), None)
            .await
            .expect("open the quick job");

        // Both snapshot before either concludes: `start_in` returns once the command is running, and
        // the slow one is still running when the quick one takes its own snapshot.
        mux.start_in(&slow, &format!("printf 'slow\n' > src/file1.txt; {HOLD}"))
            .await
            .expect("start the slow command");
        mux.start_in(&quick, "printf 'quick\n' > src/file1.txt")
            .await
            .expect("start the quick command");

        let (_, quick_result) = concluded(mux, &mut quick_job).await;
        let quick_outcome = transaction(&quick_result);
        assert!(
            matches!(quick_outcome, CmdOutcome::Committed { .. }),
            "the first to conclude wins, got {quick_outcome:?}"
        );

        let (_, slow_result) = concluded(mux, &mut slow_job).await;
        let slow_outcome = transaction(&slow_result);
        let CmdOutcome::StaleSnapshot { stale, .. } = &slow_outcome else {
            panic!("expected a stale snapshot, got {slow_outcome:?}");
        };
        assert!(
            stale.iter().any(|path| path.path == "src/file1.txt"),
            "the conflict must name the path that moved on, got {stale:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file1.txt"))
                .expect("read the committed file"),
            "quick\n"
        );
    });
}

/// Disjoint paths conflict now: the reference is the seed itself, so a transaction that landed after
/// this command snapshotted appears in its write set as a change it never made — here as a *removal*
/// of the winner's new file, since the loser's snapshot predates it. The staleness check is what
/// stops that write set from reverting the winner.
#[test]
fn a_commit_invalidates_every_older_snapshot() {
    mux_test!(fixture = Fixture::new("jobs-disjoint"), {
        let mux = fixture.mux();
        let slow = ShellId::from("slow");
        let quick = ShellId::from("quick");
        let mut slow_job = mux
            .spawn("", Some(slow.clone()), None)
            .await
            .expect("open the slow job");
        let mut quick_job = mux
            .spawn("", Some(quick.clone()), None)
            .await
            .expect("open the quick job");

        mux.start_in(&slow, &format!("printf 'b\n' > src/b.txt; {HOLD}"))
            .await
            .expect("start the slow command");
        mux.start_in(&quick, "printf 'a\n' > src/a.txt")
            .await
            .expect("start the quick command");

        let (_, quick_result) = concluded(mux, &mut quick_job).await;
        let quick_outcome = transaction(&quick_result);
        assert!(
            matches!(quick_outcome, CmdOutcome::Committed { .. }),
            "the first to conclude wins, got {quick_outcome:?}"
        );

        let (_, slow_result) = concluded(mux, &mut slow_job).await;
        let slow_outcome = transaction(&slow_result);
        let CmdOutcome::StaleSnapshot { stale, .. } = &slow_outcome else {
            panic!("expected a stale snapshot, got {slow_outcome:?}");
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
    });
}

/// The library and batch path gets fd 3 too, wired to `/dev/null`: instrumentation writes vanish
/// rather than failing, so a command's behavior never depends on whether a console is listening.
#[test]
fn piped_jobs_get_dev_null_instrumentation() {
    mux_test!(fixture = Fixture::new("jobs-devnull"), {
        let mux = fixture.mux();
        let sandbox = common::sandbox(&fixture, "1", "").await;

        let outcome = mux
            .run_cmd(&sandbox, "echo x >&3")
            .await
            .expect("run command");

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
    });
}

/// One geometry belongs to the mux, not to a job: every job opens at it, `resize` applies it to
/// every job including the ones nobody is looking at, a job opened afterwards inherits it, and a
/// geometry no job could use changes nothing.
///
/// Working directories stay each job's own throughout: one shared size is not one shared job.
#[test]
fn one_terminal_size_governs_every_job() {
    mux_test!(fixture = Fixture::new("jobs-size"), {
        let mux = fixture.mux();
        let root = ShellId::from("root");
        let nested = ShellId::from("nested");
        let mut root_job = mux
            .spawn("", Some(root.clone()), None)
            .await
            .expect("open the root job");
        let mut nested_job = mux
            .spawn("src", Some(nested.clone()), None)
            .await
            .expect("open the nested job");

        let opened = format!("{ROWS} {COLS}");
        assert_eq!(size_of_job(mux, &root, &mut root_job).await, opened);
        assert_eq!(size_of_job(mux, &nested, &mut nested_job).await, opened);

        let root_dir = run_line(mux, &root, &mut root_job, "pwd").await;
        let nested_dir = run_line(mux, &nested, &mut nested_job, "pwd").await;
        assert!(
            nested_dir.ends_with("/src"),
            "the nested job works in its own directory: {nested_dir:?}"
        );
        assert!(
            !root_dir.ends_with("/src") && nested_dir.starts_with(&root_dir),
            "and the other one in the directory above it: {root_dir:?} vs {nested_dir:?}"
        );

        mux.resize(30, 100).await.expect("resize the mux");
        assert_eq!(size_of_job(mux, &root, &mut root_job).await, "30 100");
        assert_eq!(
            size_of_job(mux, &nested, &mut nested_job).await,
            "30 100",
            "including the job nobody selected"
        );

        let third = ShellId::from("third");
        let mut third_job = mux
            .spawn("", Some(third.clone()), None)
            .await
            .expect("open the third job");
        assert_eq!(
            size_of_job(mux, &third, &mut third_job).await,
            "30 100",
            "a job opened afterwards inherits the configured size"
        );

        // Overlapping: whichever of the two lands first, the job being built ends at the size the
        // resize configured rather than at the one it was allocated with.
        let overlapped = ShellId::from("overlapped");
        let spawning = tokio::spawn({
            let mux = Arc::clone(mux);
            let id = overlapped.clone();
            async move { mux.spawn("", Some(id), None).await }
        });
        let resizing = tokio::spawn({
            let mux = Arc::clone(mux);
            async move { mux.resize(40, 120).await }
        });
        let mut overlapped_job = spawning
            .await
            .expect("spawn task")
            .expect("open the overlapped job");
        resizing
            .await
            .expect("resize task")
            .expect("resize while a job was being built");
        for (id, job) in [
            (&root, &mut root_job),
            (&nested, &mut nested_job),
            (&third, &mut third_job),
            (&overlapped, &mut overlapped_job),
        ] {
            assert_eq!(
                size_of_job(mux, id, job).await,
                "40 120",
                "{id} must end at the size both calls agreed on"
            );
        }

        let error = mux
            .resize(0, 100)
            .await
            .expect_err("a zero dimension is refused");
        assert!(
            matches!(error, MuxError::InvalidTerminalSize { rows: 0, cols: 100 }),
            "got {error}"
        );
        assert_eq!(
            size_of_job(mux, &root, &mut root_job).await,
            "40 120",
            "a refused resize leaves every terminal exactly as it was"
        );
    });
}

/// A geometry no job could be given is refused before any mux-specific state is built, and the
/// collaborators the refused construction consumed are released with it.
#[test]
fn a_zero_dimension_is_refused_before_the_mux_is_built() {
    let fixture = Fixture::cold("jobs-zero-size");
    let seed = fixture.seed_root().to_path_buf();
    let root = fixture.persistence().root;

    let refused = ShellMux::new(
        common::acquire_executor(&seed, &root),
        PurityCheckerBuilder::new().static_checks().build(),
        brush_core::env::ShellEnvironment::new(),
        0,
        COLS,
    );
    let Err(error) = refused else {
        panic!("a geometry with a zero dimension must be refused");
    };
    assert!(
        matches!(
            error,
            MuxError::InvalidTerminalSize {
                rows: 0,
                cols: COLS
            }
        ),
        "got {error}"
    );
    drop(error);

    // The executor the refused construction consumed went down with it, and the session lease with
    // the executor: taking it again is what proves nothing was left holding it.
    drop(common::acquire_executor(&seed, &root));
}

/// The two halves of a job's start are separate so a front-end can answer its line between them: the
/// row is in the table with its name taken and `starting` set, and no tracer exists until the launch
/// this mux owns runs — which then makes it an ordinary transaction.
///
/// Single-threaded on purpose: the launch task cannot run before this test yields, so `starting` is
/// a fact rather than a window.
#[test]
fn a_job_opened_for_a_command_is_in_the_table_before_it_starts() {
    mux_test!(local fixture = Fixture::new("jobs-reserve"), {
        let mux = fixture.mux();
        let id = ShellId::from("bg");
        let mut job = mux
            .spawn("", Some(id.clone()), Some("printf 'one\n' > src/file0.txt"))
            .await
            .expect("open a job for a command");

        let opened = mux.job(&id).expect("the job is in the table");
        assert!(
            opened.starting,
            "opened for a command, so it reports starting"
        );
        assert!(opened.running.is_none(), "no tracer exists yet");
        assert!(
            mux.spawn("", Some(id.clone()), None).await.is_err(),
            "the name is taken from the moment the job is opened"
        );

        let (_, result) = concluded(mux, &mut job).await;
        let outcome = transaction(&result);
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "the launched command is an ordinary transaction, got {outcome:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed"),
            "one\n"
        );
    });
}

/// A stop accepted while a reserved launch is still in flight has to survive that launch: the
/// command runs to completion and merges, no new command may be submitted, and `keep` — which does
/// cancel the series' own automatic closure — must not cancel a reader's.
#[test]
fn graceful_stop_requested_while_starting_finishes_and_closes() {
    mux_test!(local fixture = Fixture::new("jobs-graceful-start"), {
        let mux = fixture.mux();
        let persistence = fixture.persistence();
        let id = ShellId::from("graceful");
        let mut job = mux
            .spawn(
                "",
                Some(id.clone()),
                Some("printf 'done\n' > src/file0.txt"),
            )
            .await
            .expect("open a job for a command");

        mux.stop(&id, false)
            .await
            .expect("accept the stop while it is starting");
        mux.keep(&id);
        assert!(
            mux.job(&id).is_some_and(|view| view.closing),
            "an explicit stop is not a mark `keep` may clear"
        );
        assert!(
            matches!(
                mux.start_in(&id, "true").await,
                Err(MuxError::JobClosing(_))
            ),
            "a closing job takes no new command"
        );

        let (_, result) = concluded(mux, &mut job).await;
        let outcome = transaction(&result);
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "a graceful stop lets the command it found finish: {outcome:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed"),
            "done\n"
        );

        // The producer descriptors go with the row, so the stream ending is how a holder of the
        // handle learns the job is over.
        assert!(
            mux.wait_for_job(&mut job).await.is_none(),
            "the job closed itself once nothing was in flight"
        );
        assert!(mux.job(&id).is_none(), "the row is gone");
        eventually("and so is its work snapshot", || {
            !persistence.work(&job.sandbox.uid).exists()
        })
        .await;
        assert!(
            matches!(mux.stop(&id, false).await, Err(MuxError::NoSuchJob(_))),
            "a job closes once"
        );
    });
}

/// Force accepted before the tracer exists is carried out when it does: the job disappears from
/// public view at once, its command is killed rather than waited out, and nothing it wrote merges.
#[test]
fn force_stop_requested_while_starting_kills_the_launched_command() {
    mux_test!(local fixture = Fixture::new("jobs-force-start"), {
        let mux = fixture.mux();
        let persistence = fixture.persistence();
        let id = ShellId::from("forced");
        let before = std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed");
        let mut job = mux
            .spawn(
                "",
                Some(id.clone()),
                Some("printf 'partial\n' > src/file0.txt; sleep 60"),
            )
            .await
            .expect("open a job for a command");

        mux.stop(&id, true)
            .await
            .expect("accept the force while it is starting");
        assert!(
            mux.job(&id).is_none(),
            "a forced job leaves public view at once"
        );
        assert!(
            !mux.jobs().iter().any(|view| view.id == id),
            "including the listing"
        );
        assert!(
            matches!(
                mux.spawn("", Some(id.clone()), None).await,
                Err(MuxError::JobExists(_))
            ),
            "its name stays reserved while its row still owns a tracer"
        );

        let launched = std::time::Instant::now();
        let (exit_code, result) = concluded(mux, &mut job).await;
        let outcome = transaction(&result);
        assert!(
            launched.elapsed() < Duration::from_secs(30),
            "the kill landed rather than the command being waited out"
        );
        let CmdOutcome::ExecFailed {
            exit_code: reported,
            ..
        } = &outcome
        else {
            panic!("a forced command fails: {outcome:?}");
        };
        assert_eq!(*reported, 137, "128 + SIGKILL");
        assert_eq!(exit_code, 137, "and that is what the waiter observed");
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("reread seed"),
            before,
            "nothing a forcibly aborted transaction wrote reaches the seed"
        );

        assert!(
            mux.wait_for_job(&mut job).await.is_none(),
            "the forced row is claimed once its lifecycle is over"
        );
        eventually("its work path is gone", || {
            !persistence.work(&job.sandbox.uid).exists()
        })
        .await;
        mux.spawn("", Some(id), None)
            .await
            .expect("the name is reusable once teardown claimed the old row");
    });
}

/// Every job operation is an owned, `Send` future: a front-end may drive them from tasks it spawns,
/// and one job parked on a command that is waiting for input blocks neither the other jobs nor the
/// mux's own cheap snapshots.
#[test]
fn owned_job_futures_progress_while_another_job_is_blocked() {
    mux_test!(fixture = Fixture::new("jobs-concurrent"), {
        let mux = fixture.mux();
        let blocked_id = ShellId::from("blocked");
        let worker_id = ShellId::from("worker");
        let mut blocked = mux
            .spawn("", Some(blocked_id.clone()), None)
            .await
            .expect("open the blocked job");
        let mut worker = mux
            .spawn("", Some(worker_id.clone()), None)
            .await
            .expect("open the worker job");

        // A real command that cannot end until this test feeds its terminal.
        tokio::spawn({
            let mux = Arc::clone(mux);
            let id = blocked_id.clone();
            async move { mux.start_in(&id, "cat").await }
        })
        .await
        .expect("start task")
        .expect("start the blocking command");

        let view = tokio::spawn({
            let mux = Arc::clone(mux);
            let id = worker_id.clone();
            async move { mux.switch(&id).await }
        })
        .await
        .expect("switch task")
        .expect("switch to the worker job");
        assert_eq!(view.id, worker_id);
        assert_eq!(
            mux.current_job().map(|view| view.id),
            Some(worker_id.clone())
        );
        assert_eq!(
            mux.jobs().len(),
            2,
            "the table answers while a command is blocked"
        );
        assert!(mux.history().is_empty(), "and so does the history");

        tokio::spawn({
            let mux = Arc::clone(mux);
            async move { mux.resize(28, 96).await }
        })
        .await
        .expect("resize task")
        .expect("resize while a job is blocked");

        tokio::spawn({
            let mux = Arc::clone(mux);
            let id = worker_id.clone();
            async move { mux.start_in(&id, "printf 'x\n' > src/file0.txt").await }
        })
        .await
        .expect("start task")
        .expect("start the worker command");
        let (_, result) = concluded(mux, &mut worker).await;
        let outcome = transaction(&result);
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "the other job ran a whole transaction meanwhile: {outcome:?}"
        );
        assert_eq!(
            mux.history().len(),
            1,
            "the blocked job never held the authority"
        );

        // It really was waiting for input: ending its input ends it.
        mux.write_input(&blocked, b"\x04")
            .await
            .expect("end the blocked command's input");
        let (exit_code, _) = concluded(mux, &mut blocked).await;
        assert_eq!(exit_code, 0, "the blocked command ended when its input did");

        tokio::spawn({
            let mux = Arc::clone(mux);
            let id = blocked_id.clone();
            async move { mux.stop(&id, false).await }
        })
        .await
        .expect("stop task")
        .expect("stop the blocked job");
        assert!(
            mux.wait_for_job(&mut blocked).await.is_none(),
            "the stopped job's row and terminal are gone"
        );

        tokio::spawn({
            let mux = Arc::clone(mux);
            async move { mux.shutdown().await }
        })
        .await
        .expect("shutdown task")
        .expect("shut the mux down from a task that owns its handle");
    });
}
