//! Jobs as a front-end drives them: `spawn`, `start_in`, `stop` and `on_finish`, over the
//! pseudoterminal and the instrumentation stream every job owns, with the frontend the mux
//! delivers all of it to.
//!
//! The claim under test is that owning the wait changes nothing about the transaction: the same
//! snapshot, translate, authorize, commit pipeline runs, with the same verdicts — including losing a
//! race — while the caller only ever observes. The terminal tests pin the other half of the
//! contract: one geometry for the whole mux, output that survives byte for byte, instrumentation
//! that is a *stream* present for builtins and external processes alike and never mixed into the
//! output a reader is looking at, and delivery that keeps running for a job nobody is draining.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use common::{
    COLS, Fixture, FrontendAction, ROWS, RecordingFrontend, TIMEOUT, concluded, wait_for_on,
    wait_until, wait_until_on,
};
use shellmux::{
    Action, CmdOutcome, Event, MarshFrontend, MuxError, PurityCheckerBuilder, Resource, ShellId,
    ShellMux, Spawned,
};

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

/// The transaction a completion carries, failing the test when the conclusion itself broke.
fn transaction(result: &Arc<Result<CmdOutcome, MuxError>>) -> &CmdOutcome {
    result
        .as_ref()
        .as_ref()
        .unwrap_or_else(|error| panic!("the conclusion failed: {error}"))
}

/// Drains `job`'s recorded terminal bytes until `done` accepts everything seen so far.
async fn drain_output(
    fixture: &Fixture,
    job: &Spawned,
    label: &str,
    done: impl Fn(&[u8]) -> bool + Send + Sync,
) -> Vec<u8> {
    drain_stream(
        fixture.frontend(),
        &job.sandbox.uid,
        label,
        RecordingFrontend::take_terminal,
        done,
    )
    .await
}

/// Drains `job`'s recorded instrumentation stream until it holds at least `wanted` bytes.
async fn drain_instrumentation(fixture: &Fixture, job: &Spawned, wanted: usize) -> Vec<u8> {
    drain_stream(
        fixture.frontend(),
        &job.sandbox.uid,
        "instrumentation",
        RecordingFrontend::take_instrumentation,
        |seen| seen.len() >= wanted,
    )
    .await
}

/// Drains one of `uid`'s streams as `frontend` receives it, until `done` accepts everything seen.
///
/// `take` is the recorder's own taker for that stream. The mux delivers on its own, so this
/// consumes what the recorder already holds rather than reading a descriptor: a test that stops
/// asking is not a test that stops the job. A stream that ends — end of file or a read error —
/// before `done` is satisfied fails the test, as does [`TIMEOUT`] passing.
async fn drain_stream(
    frontend: &Arc<Mutex<RecordingFrontend>>,
    uid: &str,
    label: &str,
    take: fn(&mut RecordingFrontend, &str) -> Vec<u8>,
    done: impl Fn(&[u8]) -> bool + Send + Sync,
) -> Vec<u8> {
    let mut seen: Vec<u8> = Vec::new();
    let outcome = wait_for_on(frontend, |recorder| {
        seen.extend_from_slice(&take(recorder, uid));
        if done(&seen) {
            Some(true)
        } else if recorder.is_closed(uid) || recorder.error(uid).is_some() {
            Some(false)
        } else {
            None
        }
    })
    .await;
    match outcome {
        Some(true) => seen,
        Some(false) => panic!(
            "{label}: the stream ended after {:?}",
            String::from_utf8_lossy(&seen)
        ),
        None => panic!(
            "{label}: timed out with {:?}",
            String::from_utf8_lossy(&seen)
        ),
    }
}

/// Runs `cmd` in job `id` and returns the first line its terminal produced.
async fn run_line(fixture: &Fixture, id: &ShellId, job: &Spawned, cmd: &str) -> String {
    let mux = fixture.mux();
    mux.start_in(id, cmd, None)
        .await
        .unwrap_or_else(|error| panic!("start {cmd:?} in {id}: {error}"));
    let seen = drain_output(fixture, job, cmd, |bytes| bytes.contains(&b'\n')).await;
    let (_, result) = concluded(fixture, &job.sandbox.uid).await;
    let outcome = transaction(&result);
    assert!(
        !matches!(outcome, CmdOutcome::ExecFailed { .. }),
        "{cmd:?} in {id} failed: {outcome:?}"
    );
    let text = String::from_utf8_lossy(&seen).into_owned();
    text.lines().next().unwrap_or_default().trim().to_string()
}

/// The terminal geometry job `id` reports, as `"<rows> <cols>"`.
async fn size_of_job(fixture: &Fixture, id: &ShellId, job: &Spawned) -> String {
    run_line(fixture, id, job, "stty size").await
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

/// Waits for the frontend's end of stream for the sandbox `uid`.
///
/// The mux emits it only once both of that job's readers are done *and* the row's release token
/// is gone, which is after its storage was reclaimed — so this is also what a test waits on
/// before reading a job's complete tail.
async fn wait_for_close(fixture: &Fixture, uid: &str) {
    assert!(
        wait_until(fixture, |recorder| recorder.is_closed(uid)).await,
        "{uid}: the frontend's end of stream never arrived"
    );
}

/// Asserts what the frontend's own callback read back for the idle job `spawn` just returned.
///
/// The recorder's view, not a fresh `mux.jobs()` call: a display is refreshed when the mux says it
/// is out of date, so a job that became ready without saying so is a job a frontend keeps drawing
/// as still opening.
fn observed_ready(fixture: &Fixture, opened: &Spawned) {
    let recorder = fixture.recorder();
    let observed = recorder
        .observed_jobs()
        .last()
        .unwrap_or_else(|| panic!("{} left the callback nothing to read back", opened.id));
    assert_eq!(
        observed.id, opened.id,
        "the newest row the frontend read is the job that was opened"
    );
    assert_eq!(
        observed.sandbox.uid, opened.sandbox.uid,
        "and the sandbox the caller was handed"
    );
    assert!(
        !observed.starting,
        "an idle job whose spawn has returned has its terminal and shell, so it is not starting"
    );
    assert!(
        observed.running.is_none(),
        "it was opened for no command, so nothing is running in it"
    );
    assert!(
        !recorder.observed_merging(&opened.id),
        "and it has no conclusion in flight"
    );
    drop(recorder);
}

/// Asserts that the closed sandbox `uid` still answers for exactly what it observed.
///
/// Its completions stay readable once its job is gone, and its byte buffer stays empty: a later
/// job under the same name writes into its own, never back into this one's.
fn history_intact(fixture: &Fixture, uid: &str, exits: &[i32]) {
    assert_eq!(
        fixture.recorder().exit_codes(uid),
        exits,
        "{uid} answers with the results it observed"
    );
    assert!(
        fixture.recorder().take_terminal(uid).is_empty(),
        "and with nothing left in its buffer"
    );
}

/// Appends whatever the recorder still holds for `uid` to the bytes a test already drained.
///
/// What the job's streams carried *in full*: a live drain takes a prefix, the tail arrives between
/// that drain and the end of stream, and only the two together can be compared for equality rather
/// than for containment.
fn complete_tails(
    fixture: &Fixture,
    uid: &str,
    terminal: &mut Vec<u8>,
    instrumentation: &mut Vec<u8>,
) {
    let mut recorder = fixture.recorder();
    terminal.extend_from_slice(&recorder.take_terminal(uid));
    instrumentation.extend_from_slice(&recorder.take_instrumentation(uid));
    assert_eq!(
        recorder.error(uid),
        None,
        "neither of {uid}'s readers reported a failure"
    );
    drop(recorder);
}

/// Runs `cmd` in job `id`, waits for `marker` on its terminal, and reports how it ended.
///
/// What [`run_line`] cannot do: that one rejects an `ExecFailed` outcome and hands back a trimmed
/// line, while these callers need raw bytes and a command that ends non-zero on purpose. Reaching
/// the marker *is* the output assertion — [`drain_output`] returns only once it has arrived, and
/// fails the test otherwise.
async fn run_to_marker(
    fixture: &Fixture,
    id: &ShellId,
    job: &Spawned,
    cmd: &str,
    marker: &[u8],
) -> i32 {
    let mux = fixture.mux();
    mux.start_in(id, cmd, None)
        .await
        .unwrap_or_else(|error| panic!("start {cmd:?} in {id}: {error}"));
    drain_output(fixture, job, cmd, |bytes| {
        bytes.windows(marker.len()).any(|window| window == marker)
    })
    .await;
    let (exit_code, _) = concluded(fixture, &job.sandbox.uid).await;
    exit_code
}

/// The job path is the same transaction: a command that edits a path commits with exactly the
/// capability it requested, and the seed carries its bytes.
#[test]
fn a_job_command_commits_like_run_cmd() {
    mux_test!(fixture = Fixture::new("jobs-commit"), {
        let mux = fixture.mux();
        let id = ShellId::from("1");
        let job = mux
            .spawn("", Some(id.clone()), Some("printf 'one\n' > src/file0.txt"))
            .await
            .expect("open a job for a command");

        let (_, result) = concluded(&fixture, &job.sandbox.uid).await;
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
        let job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open the job");
        mux.start_in(&id, "sleep 300", None)
            .await
            .expect("start the command");

        // The traced child is its own process group, which is what makes a terminal signal reach
        // the tracer and everything it traces at once.
        let pid = running_pid(mux, &id);
        // SAFETY: `kill` with a negated pid signals that process group.
        assert_eq!(unsafe { libc::kill(-pid, libc::SIGINT) }, 0, "kill failed");

        let (observed, result) = concluded(&fixture, &job.sandbox.uid).await;
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
        /// And exactly what the terminal must carry: the command's own two writes, in order.
        const TERMINAL: &[u8] = b"outerr";

        let mux = fixture.mux();
        let id = ShellId::from("1");
        let job = mux
            .spawn("", Some(id.clone()), Some(CMD))
            .await
            .expect("open a job for a command");

        // A second handle on the same job: the frontend is the one consumer of a job's bytes, so
        // cloning the caller's handle must neither split the stream nor deliver it twice.
        let clone = job.clone();
        assert_eq!(clone.sandbox.uid, job.sandbox.uid);

        let mut instrumentation =
            drain_instrumentation(&fixture, &job, INSTRUMENTATION.len()).await;
        let mut output = drain_output(&fixture, &clone, CMD, |bytes| {
            let text = String::from_utf8_lossy(bytes);
            text.contains("out") && text.contains("err")
        })
        .await;

        let (_, result) = concluded(&fixture, &job.sandbox.uid).await;
        let outcome = transaction(&result);
        let CmdOutcome::Committed { granted, .. } = &outcome else {
            panic!("expected a commit, got {outcome:?}");
        };
        assert!(
            granted.is_empty(),
            "writing instrumentation touches no seed path, got {granted:?}"
        );

        // The whole of both streams, not a prefix: a byte delivered to the wrong one arrives late
        // as easily as early, and only the end of stream says there is no more of either.
        mux.stop(&id, false).await.expect("stop the job");
        wait_for_close(&fixture, &job.sandbox.uid).await;
        complete_tails(
            &fixture,
            &job.sandbox.uid,
            &mut output,
            &mut instrumentation,
        );
        assert_eq!(
            instrumentation, INSTRUMENTATION,
            "the builtin reached fd 3 through the file table, the external child by inheritance"
        );
        assert_eq!(
            output, TERMINAL,
            "and the terminal carried the command's own output alone"
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
        let job = mux
            .spawn(
                "",
                Some(id.clone()),
                Some(r"printf '\033[?1049h\033[2J\033[10;20Hmarker\377\033[?1049l'"),
            )
            .await
            .expect("open a job for a command");

        let mut output = drain_output(&fixture, &job, "escape sequences", |bytes| {
            bytes.windows(PAYLOAD.len()).any(|window| window == PAYLOAD)
        })
        .await;

        let (exit_code, _) = concluded(&fixture, &job.sandbox.uid).await;
        assert_eq!(exit_code, 0);

        // Equality over the complete stream: a terminal that appended or rewrote a byte after the
        // payload is a terminal that did not preserve it.
        mux.stop(&id, false).await.expect("stop the job");
        wait_for_close(&fixture, &job.sandbox.uid).await;
        let mut instrumentation = Vec::new();
        complete_tails(
            &fixture,
            &job.sandbox.uid,
            &mut output,
            &mut instrumentation,
        );
        assert_eq!(output, PAYLOAD, "the terminal rewrote the byte stream");
        assert!(
            instrumentation.is_empty(),
            "and a command that never wrote fd 3 produced no instrumentation"
        );
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
        let slow_job = mux
            .spawn("", Some(slow.clone()), None)
            .await
            .expect("open the slow job");
        let quick_job = mux
            .spawn("", Some(quick.clone()), None)
            .await
            .expect("open the quick job");

        // Both snapshot before either concludes: `start_in` returns once the command is running, and
        // the slow one is still running when the quick one takes its own snapshot.
        mux.start_in(
            &slow,
            &format!("printf 'slow\n' > src/file1.txt; {HOLD}"),
            None,
        )
        .await
        .expect("start the slow command");
        mux.start_in(&quick, "printf 'quick\n' > src/file1.txt", None)
            .await
            .expect("start the quick command");

        let (_, quick_result) = concluded(&fixture, &quick_job.sandbox.uid).await;
        let quick_outcome = transaction(&quick_result);
        assert!(
            matches!(quick_outcome, CmdOutcome::Committed { .. }),
            "the first to conclude wins, got {quick_outcome:?}"
        );

        let (_, slow_result) = concluded(&fixture, &slow_job.sandbox.uid).await;
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
        let slow_job = mux
            .spawn("", Some(slow.clone()), None)
            .await
            .expect("open the slow job");
        let quick_job = mux
            .spawn("", Some(quick.clone()), None)
            .await
            .expect("open the quick job");

        mux.start_in(&slow, &format!("printf 'b\n' > src/b.txt; {HOLD}"), None)
            .await
            .expect("start the slow command");
        mux.start_in(&quick, "printf 'a\n' > src/a.txt", None)
            .await
            .expect("start the quick command");

        let (_, quick_result) = concluded(&fixture, &quick_job.sandbox.uid).await;
        let quick_outcome = transaction(&quick_result);
        assert!(
            matches!(quick_outcome, CmdOutcome::Committed { .. }),
            "the first to conclude wins, got {quick_outcome:?}"
        );

        let (_, slow_result) = concluded(&fixture, &slow_job.sandbox.uid).await;
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
        assert_eq!(size_of_job(&fixture, &root, &root_job).await, opened);
        assert_eq!(size_of_job(&fixture, &nested, &nested_job).await, opened);
        assert_eq!(fixture.recorder().dimensions(), (ROWS, COLS));

        let root_dir = run_line(&fixture, &root, &root_job, "pwd").await;
        let nested_dir = run_line(&fixture, &nested, &nested_job, "pwd").await;
        assert!(
            nested_dir.ends_with("/src"),
            "the nested job works in its own directory: {nested_dir:?}"
        );
        assert!(
            !root_dir.ends_with("/src") && nested_dir.starts_with(&root_dir),
            "and the other one in the directory above it: {root_dir:?} vs {nested_dir:?}"
        );

        mux.resize(30, 100).await.expect("resize the mux");
        assert_eq!(
            fixture.recorder().dimensions(),
            (30, 100),
            "the frontend is told the geometry it will be rendering into"
        );
        assert_eq!(size_of_job(&fixture, &root, &root_job).await, "30 100");
        assert_eq!(
            size_of_job(&fixture, &nested, &nested_job).await,
            "30 100",
            "including the job nobody selected"
        );

        let third = ShellId::from("third");
        let mut third_job = mux
            .spawn("", Some(third.clone()), None)
            .await
            .expect("open the third job");
        assert_eq!(
            size_of_job(&fixture, &third, &third_job).await,
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
                size_of_job(&fixture, id, job).await,
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
            size_of_job(&fixture, &root, &root_job).await,
            "40 120",
            "a refused resize leaves every terminal exactly as it was"
        );
        assert_eq!(
            fixture.recorder().dimensions(),
            (40, 120),
            "and tells the frontend nothing at all"
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
        Arc::new(std::sync::Mutex::new(RecordingFrontend::new(0, COLS))),
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
        let job = mux
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

        let (_, result) = concluded(&fixture, &job.sandbox.uid).await;
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
        let job = mux
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
                mux.start_in(&id, "true", None).await,
                Err(MuxError::JobClosing(_))
            ),
            "a closing job takes no new command"
        );

        let (_, result) = concluded(&fixture, &job.sandbox.uid).await;
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
        wait_for_close(&fixture, &job.sandbox.uid).await;
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
        let job = mux
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
        let (exit_code, result) = concluded(&fixture, &job.sandbox.uid).await;
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

        wait_for_close(&fixture, &job.sandbox.uid).await;
        eventually("its work path is gone", || {
            !persistence.work(&job.sandbox.uid).exists()
        })
        .await;
        mux.spawn("", Some(id), None)
            .await
            .expect("the name is reusable once teardown claimed the old row");
    });
}

/// A caller that asks to be told gets exactly one status per command, and gets it for the command
/// it registered against rather than for whatever the job runs next.
///
/// The callback is the only way a foreground line learns its own exit status, so a status
/// delivered late, twice, or for the wrong command is a console that reports the wrong `$?`.
#[test]
fn a_finish_callback_reports_each_command_once() {
    mux_test!(fixture = Fixture::new("jobs-finish"), {
        let mux = fixture.mux();
        let id = ShellId::from("waiter");
        let job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open a job");

        let (first, first_done) = tokio::sync::oneshot::channel();
        mux.start_in(
            &id,
            "exit 3",
            Some(Box::new(move |code| {
                let _ = first.send(code);
            })),
        )
        .await
        .expect("start the first command");
        assert_eq!(
            tokio::time::timeout(TIMEOUT, first_done)
                .await
                .expect("the first command ended"),
            Ok(3),
            "the status the command exited with"
        );

        let (second, second_done) = tokio::sync::oneshot::channel();
        mux.start_in(
            &id,
            HOLD,
            Some(Box::new(move |code| {
                let _ = second.send(code);
            })),
        )
        .await
        .expect("start the second command");
        assert!(
            !mux.on_finish(&id, Box::new(|_| ())),
            "a second waiter on one command is refused rather than silently dropped"
        );
        mux.stop(&id, true).await.expect("force the second command");
        assert_eq!(
            tokio::time::timeout(TIMEOUT, second_done)
                .await
                .expect("the forced command ended"),
            Ok(137),
            "128 + SIGKILL reaches the caller that registered for this command"
        );

        assert_eq!(
            fixture.recorder().exit_codes(&job.sandbox.uid),
            vec![3, 137],
            "and the frontend saw each command exactly once"
        );
    });
}

/// A callback that cannot be registered is dropped on the spot, so the caller it would have
/// released is released at once rather than left waiting for a status that cannot come.
///
/// Three refusals, one contract: an idle job and an unknown job have no command to report, and a
/// `start_in` refused as busy never started the command it was given the callback for — while the
/// callback the running command *was* registered with still fires.
#[test]
fn a_callback_nobody_can_register_is_dropped_at_once() {
    mux_test!(fixture = Fixture::new("jobs-finish-refused"), {
        let mux = fixture.mux();
        let id = ShellId::from("idle");
        let job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open a job");

        let (idle, mut idle_done) = tokio::sync::oneshot::channel::<i32>();
        assert!(
            !mux.on_finish(
                &id,
                Box::new(move |code| {
                    let _ = idle.send(code);
                })
            ),
            "nothing is running, so there is nothing to be told about"
        );
        assert!(
            matches!(
                idle_done.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
            ),
            "the refused callback was dropped, not kept"
        );

        let (unknown, mut unknown_done) = tokio::sync::oneshot::channel::<i32>();
        assert!(
            !mux.on_finish(
                &ShellId::from("nobody"),
                Box::new(move |code| {
                    let _ = unknown.send(code);
                })
            ),
            "an unknown job registers nothing"
        );
        assert!(matches!(
            unknown_done.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));

        let (first, first_done) = tokio::sync::oneshot::channel::<i32>();
        mux.start_in(
            &id,
            HOLD,
            Some(Box::new(move |code| {
                let _ = first.send(code);
            })),
        )
        .await
        .expect("start the held command");
        let (second, mut second_done) = tokio::sync::oneshot::channel::<i32>();
        let refused = mux
            .start_in(
                &id,
                "true",
                Some(Box::new(move |code| {
                    let _ = second.send(code);
                })),
            )
            .await;
        assert!(
            matches!(refused, Err(MuxError::JobBusy(_))),
            "a second command is refused while the first runs: {refused:?}"
        );
        assert!(
            matches!(
                second_done.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
            ),
            "a refused start drops its callback rather than holding it against the running command"
        );
        mux.stop(&id, true).await.expect("force the held command");
        assert_eq!(
            tokio::time::timeout(TIMEOUT, first_done)
                .await
                .expect("the held command ended"),
            Ok(137),
            "the callback registered with the command that ran still fires"
        );
        assert_eq!(
            fixture.recorder().exit_codes(&job.sandbox.uid),
            vec![137],
            "and the frontend saw exactly the one command that ran"
        );
    });
}

/// Shutting the session down releases a caller blocked on a command: its conclusion is cancelled,
/// so no status can come, and the callback is dropped rather than left in the row until the mux
/// itself is dropped.
#[test]
fn shutdown_drops_a_callback_still_waiting() {
    mux_test!(fixture = Fixture::new("jobs-finish-shutdown"), {
        let mux = fixture.mux();
        let id = ShellId::from("held");
        let _job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open a job");
        let (done, mut released) = tokio::sync::oneshot::channel::<i32>();
        mux.start_in(
            &id,
            HOLD,
            Some(Box::new(move |code| {
                let _ = done.send(code);
            })),
        )
        .await
        .expect("start the held command");

        mux.shutdown().await.expect("shut the session down");
        assert!(
            matches!(
                released.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
            ),
            "shutdown released the caller: its callback is gone and no status will follow"
        );
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
        let blocked = mux
            .spawn("", Some(blocked_id.clone()), None)
            .await
            .expect("open the blocked job");
        let worker = mux
            .spawn("", Some(worker_id.clone()), None)
            .await
            .expect("open the worker job");

        // A real command that cannot end until this test feeds its terminal.
        tokio::spawn({
            let mux = Arc::clone(mux);
            let id = blocked_id.clone();
            async move { mux.start_in(&id, "cat", None).await }
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
            async move {
                mux.start_in(&id, "printf 'x\n' > src/file0.txt", None)
                    .await
            }
        })
        .await
        .expect("start task")
        .expect("start the worker command");
        let (_, result) = concluded(&fixture, &worker.sandbox.uid).await;
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
        let (exit_code, _) = concluded(&fixture, &blocked.sandbox.uid).await;
        assert_eq!(exit_code, 0, "the blocked command ended when its input did");

        tokio::spawn({
            let mux = Arc::clone(mux);
            let id = blocked_id.clone();
            async move { mux.stop(&id, false).await }
        })
        .await
        .expect("stop task")
        .expect("stop the blocked job");
        wait_for_close(&fixture, &blocked.sandbox.uid).await;

        tokio::spawn({
            let mux = Arc::clone(mux);
            async move { mux.shutdown().await }
        })
        .await
        .expect("shutdown task")
        .expect("shut the mux down from a task that owns its handle");
    });
}

/// A job nobody is draining still runs: the mux pumps every job's streams into the frontend, so a
/// megabyte of output on an unselected tab neither stalls the command on a full pseudoterminal
/// buffer nor waits for a reader to ask for it.
#[test]
fn an_unselected_job_needs_no_reader() {
    mux_test!(fixture = Fixture::new("jobs-pump"), {
        /// Sixteen 64 KiB writes, then an instrumentation payload with no newline to end it.
        const CMD: &str = "dd if=/dev/zero bs=65536 count=16 2>/dev/null; printf fd3-tail >&3";
        /// What `dd` wrote: 16 × 65536 bytes, none of which a pseudoterminal may rewrite.
        const ZEROS: usize = 1_048_576;

        let mux = fixture.mux();
        let watched = ShellId::from("watched");
        let bulk = ShellId::from("bulk");
        mux.spawn("", Some(watched.clone()), None)
            .await
            .expect("open the selected job");
        mux.switch(&watched).await.expect("select the other job");
        let job = mux
            .spawn("", Some(bulk.clone()), Some(CMD))
            .await
            .expect("open a job for a command");
        assert_ne!(
            mux.current_job().map(|view| view.id),
            Some(bulk.clone()),
            "the job producing the bytes is not the selected one"
        );

        // No drain of any kind before this: the command has to finish on the mux's own pumping.
        let (exit_code, result) = concluded(&fixture, &job.sandbox.uid).await;
        assert_eq!(exit_code, 0, "a megabyte reached the frontend, {result:?}");

        mux.stop(&bulk, false).await.expect("stop the bulk job");
        wait_for_close(&fixture, &job.sandbox.uid).await;

        let (terminal, instrumentation) = {
            let mut recorder = fixture.recorder();
            let terminal = recorder.take_terminal(&job.sandbox.uid);
            let instrumentation = recorder.take_instrumentation(&job.sandbox.uid);
            drop(recorder);
            (terminal, instrumentation)
        };
        assert_eq!(terminal.len(), ZEROS, "every byte, exactly once");
        assert!(
            terminal.iter().all(|byte| *byte == 0),
            "and none of them rewritten"
        );
        assert_eq!(
            instrumentation, b"fd3-tail",
            "the final fd-3 payload arrives without a newline to flush it"
        );
        assert!(
            !fixture.recorder().closed_with_storage(&job.sandbox.uid),
            "and its snapshot was already reclaimed when its streams were reported over"
        );
    });
}

/// A frontend drives the mux through the reference it was bound to, and reads the table back
/// through the queries `Changed` invalidates: readiness, creation order, selection, and a force
/// that retires a row at once.
///
/// Every table assertion is the recorder's callback-observed copy rather than a fresh query, so a
/// state the mux reached without announcing it fails here instead of passing on a poll a real
/// frontend would never make.
#[test]
fn a_bound_frontend_drives_the_table_it_observes() {
    mux_test!(fixture = Fixture::new("jobs-controls"), {
        let mux = fixture
            .recorder()
            .mux()
            .expect("the frontend is bound to the mux that built it");

        let alpha = ShellId::from("alpha");
        let beta = ShellId::from("beta");
        let opened_alpha = mux
            .spawn("", Some(alpha.clone()), None)
            .await
            .expect("open alpha");
        observed_ready(&fixture, &opened_alpha);
        let opened_beta = mux
            .spawn("src", Some(beta.clone()), None)
            .await
            .expect("open beta");
        observed_ready(&fixture, &opened_beta);
        assert_eq!(
            fixture
                .recorder()
                .observed_jobs()
                .iter()
                .map(|view| view.id.clone())
                .collect::<Vec<_>>(),
            vec![alpha.clone(), beta.clone()],
            "the table the frontend read back answers in creation order"
        );

        mux.switch(&beta).await.expect("select beta");
        assert_eq!(
            fixture.recorder().observed_current(),
            Some(&beta),
            "a switch invalidates the display, and the selection is what it reads back"
        );

        let escape = ShellId::from("escape");
        assert!(
            matches!(
                mux.spawn("", Some(alpha.clone()), None).await,
                Err(MuxError::JobExists(_))
            ),
            "a live name is refused"
        );
        assert!(
            matches!(
                mux.spawn("../outside", Some(escape.clone()), None).await,
                Err(MuxError::SandboxDir { .. })
            ),
            "and a directory that escapes the seed is too"
        );
        {
            let recorder = fixture.recorder();
            assert!(
                recorder.handle(&escape).is_none(),
                "a refused spawn publishes no handle"
            );
            assert_eq!(
                recorder.handle(&alpha).map(|held| held.sandbox.uid),
                Some(opened_alpha.sandbox.uid.clone()),
                "and the job that kept the name is still the one opened under it"
            );
            drop(recorder);
        }

        mux.stop(&beta, true).await.expect("force beta");
        let recorder = fixture.recorder();
        assert_eq!(
            recorder
                .observed_jobs()
                .iter()
                .map(|view| view.id.clone())
                .collect::<Vec<_>>(),
            vec![alpha],
            "force retires the row at once, in the listing the frontend reads back"
        );
        assert!(
            recorder.observed_current().is_none(),
            "and the selection it held goes with it"
        );
        drop(recorder);
    });
}

/// Input reaches a job's terminal, its command's end is one result delivered once, and the job
/// outlives it. A name handed out again is a different sandbox throughout: separate buffers,
/// separate closure, and the handle the frontend holds is the live one.
#[test]
fn input_reaches_a_job_and_every_result_is_delivered_once() {
    mux_test!(fixture = Fixture::new("jobs-input"), {
        let mux = fixture.mux();
        let id = ShellId::from("io");
        let job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open the job");
        mux.start_in(&id, "stty -echo; printf READY; cat", None)
            .await
            .expect("start a command that waits for input");

        drain_output(&fixture, &job, "READY", |bytes| {
            bytes.windows(5).any(|window| window == b"READY")
        })
        .await;
        mux.write_input(&job, b"roundtrip\n")
            .await
            .expect("type into the job's terminal");
        // The drain returns only once the line came back, so reaching here is the round trip.
        drain_output(&fixture, &job, "roundtrip", |bytes| {
            bytes.windows(11).any(|window| window == b"roundtrip\r\n")
        })
        .await;

        // End of input, not end of job: the tab stays open for the next command.
        mux.write_input(&job, b"\x04")
            .await
            .expect("end the command's input");
        let (exit_code, _) = concluded(&fixture, &job.sandbox.uid).await;
        assert_eq!(exit_code, 0);
        let first = job.sandbox.uid.clone();
        assert!(mux.job(&id).is_some(), "a command ending is not a closure");
        assert!(!fixture.recorder().is_closed(&first));
        // No further await: the frontend is told a command ended before the handle waiting on it
        // is, so a waiter that returned has already seen the delivery.
        assert_eq!(
            fixture.recorder().exit_codes(&first),
            vec![0],
            "the completion reached the frontend before it reached the waiter"
        );

        // `run_line` refuses an `ExecFailed` outcome, and this second command ends non-zero on
        // purpose: two results are only distinguishable from one delivered twice by their codes.
        let exit_code = run_to_marker(
            &fixture,
            &id,
            &job,
            "printf 'second\\n'; sh -c 'exit 7'",
            b"second\r\n",
        )
        .await;
        assert_eq!(exit_code, 7, "the status the command itself ended with");
        assert_eq!(
            fixture.recorder().exit_codes(&first),
            vec![0, 7],
            "one result per command, delivered once each and in order"
        );

        mux.stop(&id, false).await.expect("stop the job");
        wait_for_close(&fixture, &first).await;
        history_intact(&fixture, &first, &[0, 7]);
        assert!(
            fixture.recorder().handle(&id).is_none(),
            "and the handle the frontend held for it went with the closure"
        );

        let reused = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("the name is free once the job closed");
        assert_ne!(reused.sandbox.uid, first, "a reused name is a new sandbox");
        let exit_code =
            run_to_marker(&fixture, &id, &reused, "printf 'again\\n'", b"again\r\n").await;
        assert_eq!(exit_code, 0, "the new job ran its own command");
        assert_eq!(
            fixture.recorder().exit_codes(&reused.sandbox.uid),
            vec![0],
            "the new sandbox has its own single result"
        );
        history_intact(&fixture, &first, &[0, 7]);
        assert!(
            !fixture.recorder().is_closed(&reused.sandbox.uid),
            "the live job's streams are open, whatever the old ones did"
        );
        assert_eq!(
            fixture
                .recorder()
                .handle(&id)
                .map(|handle| handle.sandbox.uid),
            Some(reused.sandbox.uid.clone()),
            "and the handle under that name is the live one"
        );
    });
}

/// Closing a sandbox by hand reclaims its storage before its streams end: the row leaves the table
/// at once, but its producers stay open until the tree it named is off disk, which is the ordering
/// [`shellmux::FrontendEvent::Closed`] promises a frontend.
#[test]
fn direct_close_reclaims_storage_before_closed() {
    mux_test!(fixture = Fixture::new("jobs-direct-close"), {
        let mux = fixture.mux();
        let persistence = fixture.persistence();
        let id = ShellId::from("direct");
        let job = mux
            .spawn("", Some(id.clone()), None)
            .await
            .expect("open the job");
        mux.start_in(&id, "printf 'written\n' > src/file0.txt", None)
            .await
            .expect("start a command that writes into the seed");
        let (exit_code, result) = concluded(&fixture, &job.sandbox.uid).await;
        assert_eq!(
            exit_code,
            0,
            "the command committed: {:?}",
            transaction(&result)
        );

        let uid = job.sandbox.uid.clone();
        assert!(
            persistence.work(&uid).exists(),
            "an open job keeps the tree its next command would run in"
        );

        // On a blocking thread, because the public entry point deletes a subvolume synchronously.
        let sandbox = job.sandbox.clone();
        let closer = Arc::clone(mux);
        tokio::task::spawn_blocking(move || closer.close_sandbox(&sandbox))
            .await
            .expect("close the sandbox by hand");
        wait_for_close(&fixture, &uid).await;

        assert!(
            !persistence.work(&uid).exists(),
            "the tree the job named is reclaimed"
        );
        let recorder = fixture.recorder();
        assert!(
            !recorder.closed_with_storage(&uid),
            "and it was already gone when the frontend was told the streams were over"
        );
        assert!(
            recorder.handle(&id).is_none(),
            "the handle under that name went with the row"
        );
        assert_eq!(
            recorder.results(&uid).len(),
            1,
            "while the completion it delivered stays readable under its uid"
        );
        drop(recorder);
    });
}

/// Shutdown ends the session and detaches the frontend: the recorder outlives the mux, keeps what
/// it observed, and holds nothing that would keep the session's lease alive — the same paths open
/// again straight afterwards.
#[test]
fn shutdown_detaches_frontend_without_retaining_session() {
    mux_test!(fixture = Fixture::new("jobs-detach"), {
        // The frontend a real host keeps: it was built before the mux and outlives it.
        let frontend = Arc::clone(fixture.frontend());
        let idle = ShellId::from("idle");
        let worked = ShellId::from("worked");
        fixture
            .mux()
            .spawn("", Some(idle.clone()), None)
            .await
            .expect("open the idle tab");
        let job = fixture
            .mux()
            .spawn("", Some(worked.clone()), None)
            .await
            .expect("open the working tab");
        fixture
            .mux()
            .start_in(&worked, "printf 'done\\n'", None)
            .await
            .expect("start a command in it");
        let (exit_code, _) = concluded(&fixture, &job.sandbox.uid).await;
        assert_eq!(exit_code, 0);
        let uid = job.sandbox.uid.clone();

        // Nothing of this test's holds a strong reference to the mux, so this is the last one.
        tokio::time::timeout(TIMEOUT, fixture.finish_mux())
            .await
            .expect("the session shut down");

        {
            let recorder = frontend.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(
                recorder.mux().is_none(),
                "the binding a detached frontend holds no longer names a session"
            );
            assert!(
                recorder.handle(&idle).is_none() && recorder.handle(&worked).is_none(),
                "and it released the terminals its live handles held"
            );
            assert_eq!(
                recorder.exit_codes(&uid),
                vec![0],
                "while what it observed is still what a host asks it about"
            );
            drop(recorder);
        }

        // The lease went with the session: the same paths open again without waiting for anything.
        let reopened = common::reopen(&fixture.persistence()).await;
        common::close_mux(reopened).await;
    });
}

/// Two frontends over one mux: both are bound to the same session, either one drives it, and every
/// job's bytes, results and closure reach both.
///
/// The geometry is the one both displays fit, so a job opened by a mux whose left side is 24×80 and
/// whose right side is 40×60 reports 24×60 to the program running in it.
#[test]
fn joined_frontends_share_one_mux() {
    mux_test!(fixture = Fixture::joined("jobs-join", (40, 60)), {
        // Both sides outlive the mux, as a real host's frontends do.
        let left = Arc::clone(fixture.frontend());
        let right = Arc::clone(fixture.twin());

        let bound_left = fixture.recorder().mux().expect("the left side is bound");
        let bound_right = fixture
            .twin_recorder()
            .mux()
            .expect("the right side is bound");
        assert!(
            Arc::ptr_eq(&bound_left, fixture.mux()) && Arc::ptr_eq(&bound_right, fixture.mux()),
            "both sides were bound to the one mux this fixture owns"
        );
        drop(bound_left);
        drop(bound_right);

        // Opened from the right side; observed by both.
        let id = ShellId::from("shared");
        RecordingFrontend::dispatch(fixture.twin(), FrontendAction::Spawn { id: &id })
            .await
            .expect("the right side opens a job");
        let job = fixture
            .recorder()
            .handle(&id)
            .expect("the left side was handed the handle for a job the right side opened");
        let twin_handle = fixture
            .twin_recorder()
            .handle(&id)
            .expect("and so was the right side");
        assert_eq!(
            job.sandbox.uid, twin_handle.sandbox.uid,
            "one job, published to both sides"
        );
        drop(twin_handle);
        observed_ready(&fixture, &job);
        let uid = job.sandbox.uid.clone();

        // The geometry both displays fit: the smaller of each dimension, not either side's own.
        assert_eq!(
            size_of_job(&fixture, &id, &job).await,
            format!("{ROWS} 60"),
            "the job is opened at the geometry both sides can render"
        );
        drain_stream(
            &right,
            &uid,
            "right: stty size",
            RecordingFrontend::take_terminal,
            |seen| seen.windows(5).any(|window| window == b"24 60"),
        )
        .await;

        // Started from the left; its output reaches the right.
        assert_eq!(
            run_line(&fixture, &id, &job, "printf 'both\\n'").await,
            "both"
        );
        drain_stream(
            &right,
            &uid,
            "right: printf",
            RecordingFrontend::take_terminal,
            |seen| seen.windows(4).any(|window| window == b"both"),
        )
        .await;

        // Both conclusions reached both sides, exactly once each.
        assert_eq!(fixture.recorder().exit_codes(&uid), vec![0, 0]);
        assert_eq!(
            fixture.twin_recorder().exit_codes(&uid),
            vec![0, 0],
            "the right side observed the same two completions"
        );

        fixture.mux().stop(&id, false).await.expect("close the job");
        wait_for_close(&fixture, &uid).await;
        assert!(
            wait_until_on(fixture.twin(), |recorder| recorder.is_closed(&uid)).await,
            "the right side saw the closure"
        );

        // Nothing of this test's holds a strong reference to the mux, so this is the last one.
        drop(job);
        tokio::time::timeout(TIMEOUT, fixture.finish_mux())
            .await
            .expect("the session shut down");

        for (side, frontend) in [("left", &left), ("right", &right)] {
            let recorder = frontend.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(
                recorder.mux().is_none(),
                "the {side} side's binding no longer names a session"
            );
            assert!(
                recorder.handle(&id).is_none(),
                "and the {side} side released the terminal its handle held"
            );
            drop(recorder);
        }
    });
}

/// What `caps` is allowed to show: the claims the authority still holds, and nothing a rolled-back
/// command provisionally asked for.
///
/// A denial is atomic over the whole command, so the *first* event of a two-file command — which
/// the policy granted before the second was refused — must not survive as a claim; and a claim is
/// held by a principal, not by a tab, so closing the job that took it leaves it standing.
#[test]
fn active_capabilities_exclude_partial_denials_and_outlive_jobs() {
    mux_test!(fixture = Fixture::new("jobs-active-caps"), {
        let mux = fixture.mux();
        let owner = ShellId::from("owner");
        let other = ShellId::from("other");
        mux.spawn("", Some(owner.clone()), None)
            .await
            .expect("open the owning job");
        let other_job = mux
            .spawn("", Some(other.clone()), None)
            .await
            .expect("open the other job");

        mux.start_in(&owner, "printf 'owned\n' > src/file1.txt", None)
            .await
            .expect("start the owning command");
        let (_, owned) = concluded(
            &fixture,
            &mux.job(&owner).expect("the owning job").sandbox.uid,
        )
        .await;
        assert!(
            matches!(transaction(&owned), CmdOutcome::Committed { .. }),
            "the first edit of a clean resource is granted, got {:?}",
            transaction(&owned)
        );

        // The first redirection is to a resource nobody holds; the second contends with `owner`.
        mux.start_in(
            &other,
            "printf 'new\n' > src/new.txt; printf 'bad\n' > src/file1.txt",
            None,
        )
        .await
        .expect("start the contending command");
        let (_, denied) = concluded(&fixture, &other_job.sandbox.uid).await;
        let outcome = transaction(&denied);
        let CmdOutcome::DeniedCaps { requested, .. } = outcome else {
            panic!("expected a capability denial, got {outcome:?}");
        };
        assert!(
            requested
                .iter()
                .any(|event| event.resource == Resource::from(["src", "new.txt"])),
            "the rolled-back command did request the independent resource, got {requested:?}"
        );

        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file1.txt")).expect("read the held file"),
            "owned\n",
            "the denied command changed nothing"
        );
        assert!(
            !fixture.seed("src/new.txt").exists(),
            "including the file it was free to create"
        );

        let active = mux.active_capabilities();
        assert!(
            active
                .iter()
                .all(|event| event.principal.as_str() != "other"),
            "a denied command holds no claim, got {active:?}"
        );
        let held = Event::new("owner", Action::Edit, Resource::from(["src", "file1.txt"]));
        assert!(active.contains(&held), "got {active:?}");

        mux.stop(&owner, true).await.expect("close the owning job");
        assert!(
            wait_until(&fixture, |_| mux.job(&owner).is_none()).await,
            "the owning job closed"
        );
        assert!(
            mux.active_capabilities().contains(&held),
            "a claim is a principal's, not a tab's"
        );
    });
}
