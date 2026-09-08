//! Commands that only read: what the mux learns about them, and what it stops doing for them.
//!
//! A transaction costs a copy-on-write snapshot per command and a walk of two trees. The claim
//! under test is that a command a traced run showed to be read-only stops paying either — it shares
//! one snapshot per committed seed version with every other read-only command — while still
//! declaring the reads it made, because a read is what takes a resource's read claim. The bypass is
//! traced too, so a verdict that has gone wrong is reported, quarantined and withdrawn.
//!
//! The two checker modes are separate claims: a learned checker approves what a trace showed, a
//! static one approves what syntax proves, and neither borrows the other's evidence.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use common::{Fixture, main_sandbox};
use shellmux::{Action, CmdOutcome, PurityCheckerBuilder, Reaped, ShellId, ShellMux};

/// A fixture whose mux learns which commands are read-only.
///
/// `seed_log` is written into `meta/purity.jsonl` after the executor has taken the session's
/// exclusive lease and before the mux restores the checker from it, which is how a test starts from
/// a verdict an earlier session would have earned — without racing an owner or being overwritten by
/// the restore.
fn learning_fixture(label: &str, seed_log: &'static str) -> Fixture {
    Fixture::prepared(
        label,
        PurityCheckerBuilder::new().learned().build(),
        move |persistence| {
            if !seed_log.is_empty() {
                std::fs::write(persistence.meta().join("purity.jsonl"), seed_log)
                    .expect("seed the purity cache");
            }
        },
    )
}

/// Every line of the session's purity cache, in file order.
fn purity_log(fixture: &Fixture) -> Vec<String> {
    std::fs::read_to_string(fixture.persistence().meta().join("purity.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// The process group of the command running in job `id`.
fn running_pid(mux: &ShellMux, id: &ShellId) -> libc::pid_t {
    mux.job(id)
        .and_then(|view| view.running)
        .unwrap_or_else(|| panic!("{id} is running a command"))
        .pid
}

/// The whole feature in one run: a traced command that asked for nothing is remembered, and the
/// next job to submit it gets no snapshot of its own.
///
/// The second sandbox is the proof. A job that has run a transaction keeps its snapshot, so only a
/// job which never needed one can show that none was taken — and it shows it twice: at `sd` time,
/// and after the bypassed command has already run. What does exist afterwards is the shared reader
/// tree, one per seed version rather than one per command.
#[test]
fn a_read_only_command_is_learned_and_then_skips_the_sandbox() {
    mux_test!(fixture = learning_fixture("purity-learn", ""), {
        let learner = main_sandbox(&fixture).await;

        let outcome = fixture
            .mux()
            .run_cmd(&learner, "ls")
            .await
            .expect("run the first ls");
        let CmdOutcome::Committed { seq, .. } = outcome else {
            panic!("the first run is an ordinary transaction: {outcome:?}");
        };
        assert_eq!(
            purity_log(&fixture),
            vec![r#"{"cmd":"ls","dir":"","pure":true}"#.to_string()],
            "one traced run that asked for nothing earns the verdict"
        );

        let fresh = common::sandbox(&fixture, "fresh", "").await;
        let work = fixture.persistence().work(&fresh.uid);
        assert!(
            !work.exists(),
            "opening a job must not copy the seed: {} exists",
            work.display()
        );

        let outcome = fixture
            .mux()
            .run_cmd(&fresh, "ls")
            .await
            .expect("run the second ls");
        assert!(
            matches!(outcome, CmdOutcome::Bypassed { exit_code: 0, .. }),
            "the learned command runs without a snapshot of its own: {outcome:?}"
        );
        assert!(
            !work.exists(),
            "and takes none while it runs: {} exists",
            work.display()
        );
        assert!(
            fixture.persistence().reader(seq).is_dir(),
            "what it does get is the reader tree of the version it started at"
        );
    });
}

/// A bypass is read-only, not silent. Its reads never reach the write-ahead log or the seed, but
/// they do reach the authority: a read is what takes a resource's read claim, and a principal whose
/// reads stopped being recorded could never take one back.
#[test]
fn a_bypassed_read_is_still_declared_to_the_authority() {
    mux_test!(fixture = learning_fixture("purity-read", ""), {
        let sandbox = main_sandbox(&fixture).await;
        let cmd = "cat -- src/file0.txt";
        let persistence = fixture.persistence();

        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, cmd)
            .await
            .expect("run the read");
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "the first run is an ordinary transaction: {outcome:?}"
        );
        assert_eq!(fixture.mux().history().len(), 1, "it declared its read");
        assert_eq!(
            purity_log(&fixture),
            vec![format!(r#"{{"cmd":"{cmd}","dir":"","pure":true}}"#)],
            "a command that only reads is read-only"
        );

        let wal_before = std::fs::read_to_string(persistence.meta().join("wal.jsonl"))
            .expect("read the write-ahead log");

        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, cmd)
            .await
            .expect("run the read again");
        let CmdOutcome::Bypassed { granted, .. } = &outcome else {
            panic!("expected a bypass, got {outcome:?}");
        };
        assert_eq!(
            granted.len(),
            1,
            "the bypass declared the read it made: {granted:?}"
        );
        assert_eq!(granted[0].action, Action::Read);

        let history = fixture.mux().history();
        assert_eq!(
            history.len(),
            2,
            "and the authority recorded it, so the read claim moved: {history:?}"
        );
        assert_eq!(
            std::fs::read_to_string(persistence.meta().join("wal.jsonl"))
                .expect("read the write-ahead log"),
            wal_before,
            "a bypass frames no transaction: the write-ahead log is untouched"
        );

        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, cmd)
            .await
            .expect("run the read a third time");
        assert!(matches!(outcome, CmdOutcome::Bypassed { .. }));
        let trees: Vec<String> = std::fs::read_dir(persistence.snap())
            .expect("list the snapshot directory")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("read-"))
            .collect();
        assert_eq!(
            trees.len(),
            1,
            "both bypasses shared one tree: the seed version never moved: {trees:?}"
        );
    });
}

/// A command that writes is never let out, however often it is run: the write set is what the
/// verdict is about, and `printf x > written.txt` has one every time.
#[test]
fn a_writing_command_is_never_learned() {
    mux_test!(fixture = learning_fixture("purity-writer", ""), {
        let sandbox = main_sandbox(&fixture).await;
        let cmd = "printf x > written.txt";

        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, cmd)
            .await
            .expect("run the write");
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "the write commits: {outcome:?}"
        );
        assert!(
            purity_log(&fixture).is_empty(),
            "a command that writes leaves the cache alone: {:?}",
            purity_log(&fixture)
        );

        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, cmd)
            .await
            .expect("run the write again");
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "and it is still a transaction the second time: {outcome:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("written.txt")).expect("read the committed file"),
            "x",
            "the seed carries what the transaction merged"
        );
    });
}

/// A verdict that has gone wrong: the command was vouched for as read-only and wrote anyway.
///
/// The reader tree contains it — a snapshot is a snapshot, so nothing reaches the seed and nothing
/// is merged — and the mux owes the report, the quarantine of the tree it dirtied, and the
/// withdrawal that makes the next run a transaction.
#[test]
fn an_escape_is_contained_reported_and_its_verdict_withdrawn() {
    mux_test!(
        fixture = learning_fixture(
            "purity-escape",
            "{\"cmd\":\"printf x > escape.txt\",\"dir\":\"\",\"pure\":true}\n",
        ),
        {
            let cmd = "printf x > escape.txt";
            let sandbox = main_sandbox(&fixture).await;

            let outcome = fixture
                .mux()
                .run_cmd(&sandbox, cmd)
                .await
                .expect("run the escaping command");
            let CmdOutcome::Escaped {
                wrote, exit_code, ..
            } = &outcome
            else {
                panic!("expected an escape, got {outcome:?}");
            };
            assert!(*wrote, "the trace saw the write inside the tree it read");
            assert_eq!(*exit_code, 0);
            assert!(
                !fixture.seed("escape.txt").exists(),
                "the reader tree contained it: nothing reached the seed"
            );
            assert!(
                fixture.mux().history().is_empty(),
                "and nothing was authorized"
            );
            assert_eq!(
                purity_log(&fixture).last().map(String::as_str),
                Some(r#"{"cmd":"printf x > escape.txt","dir":"","pure":false}"#),
                "the verdict that let it out is withdrawn"
            );

            let outcome = fixture
                .mux()
                .run_cmd(&sandbox, cmd)
                .await
                .expect("run it once more");
            assert!(
                matches!(outcome, CmdOutcome::Committed { .. }),
                "the withdrawal takes effect on the next run: {outcome:?}"
            );
            assert_eq!(
                std::fs::read_to_string(fixture.seed("escape.txt"))
                    .expect("read the committed file"),
                "x",
                "and the transaction is what puts it in the seed"
            );
        }
    );
}

/// Two bypassed jobs share one reader snapshot, so the selector a forced stop uses may not be the
/// snapshot root — or the session. Forcing one must leave the other's tracer running.
#[test]
fn force_stop_preserves_another_bypassed_job() {
    mux_test!(
        fixture = learning_fixture(
            "purity-force-reader",
            "{\"cmd\":\"sleep 60\",\"dir\":\"\",\"pure\":true}\n",
        ),
        {
            let cmd = "sleep 60";
            let mux = fixture.mux();
            let persistence = fixture.persistence();
            let first_id = ShellId::from("reader-a");
            let second_id = ShellId::from("reader-b");

            let mut first = mux
                .spawn("", Some(first_id.clone()), None)
                .await
                .expect("open reader-a");
            let mut second = mux
                .spawn("", Some(second_id.clone()), None)
                .await
                .expect("open reader-b");
            mux.start_in(&first_id, cmd).await.expect("start reader-a");
            mux.start_in(&second_id, cmd).await.expect("start reader-b");
            let first_pid = running_pid(mux, &first_id);
            let second_pid = running_pid(mux, &second_id);
            assert!(
                !persistence.work(&first.sandbox.uid).exists()
                    && !persistence.work(&second.sandbox.uid).exists(),
                "a learned read-only command takes no private snapshot"
            );

            mux.stop(&first_id, true).await.expect("force reader-a");
            let Some(Reaped {
                exit_code, outcome, ..
            }) = mux.wait_for_job(&mut first).await
            else {
                panic!("the forced command should end");
            };
            assert_eq!(exit_code, 137, "128 + SIGKILL");
            let concluded = outcome.as_ref().as_ref().expect("the conclusion succeeded");
            assert!(
                matches!(concluded, CmdOutcome::ExecFailed { exit_code: 137, .. }),
                "the forced bypass fails rather than declaring reads: {concluded:?}"
            );
            assert!(
                is_running(second_pid),
                "the other reader of the same snapshot is untouched"
            );
            assert!(!is_running(first_pid), "and the forced one is over");

            mux.stop(&second_id, true).await.expect("force reader-b");
            let Some(Reaped { .. }) = mux.wait_for_job(&mut second).await else {
                panic!("the second forced command should end");
            };
            assert!(
                mux.job(&first_id).is_none() && mux.job(&second_id).is_none(),
                "a forced job is gone from public view"
            );
        }
    );
}

/// A static checker proves from syntax and learns nothing.
///
/// Two independent claims about the cache file: nothing is ever appended to it, and a record an
/// earlier learned session left in it approves nothing. Evidence a trace produced is the learned
/// mode's reason; syntax is the static mode's, and neither borrows the other's.
#[test]
fn a_static_checker_neither_writes_nor_reads_the_learned_cache() {
    /// A verdict a learned session would have earned for a command syntax cannot prove.
    const SEEDED: &str = "{\"cmd\":\"cat -- src/file0.txt\",\"dir\":\"\",\"pure\":true}\n";

    mux_test!(
        fixture = Fixture::prepared(
            "purity-static",
            PurityCheckerBuilder::new().static_checks().build(),
            |persistence| {
                std::fs::write(persistence.meta().join("purity.jsonl"), SEEDED)
                    .expect("seed the purity cache");
            },
        ),
        {
            let sandbox = main_sandbox(&fixture).await;
            let mux = fixture.mux();

            let outcome = mux
                .run_cmd(&sandbox, "true; echo 'literal $(touch hidden)' && pwd")
                .await
                .expect("run the provable command");
            assert!(
                matches!(outcome, CmdOutcome::Bypassed { .. }),
                "syntax alone proves this one read-only: {outcome:?}"
            );
            assert!(
                !fixture.seed("hidden").exists(),
                "nothing inside the single quotes was expanded, let alone run"
            );

            let outcome = mux
                .run_cmd(&sandbox, "cat -- src/file0.txt")
                .await
                .expect("run the read");
            assert!(
                matches!(outcome, CmdOutcome::Committed { .. }),
                "a static checker may not approve a command from another mode's record: \
                 {outcome:?}"
            );

            let outcome = mux
                .run_cmd(&sandbox, "printf x > written.txt")
                .await
                .expect("run the write");
            assert!(
                matches!(outcome, CmdOutcome::Committed { .. }),
                "and a write is a transaction as always: {outcome:?}"
            );

            assert_eq!(
                purity_log(&fixture),
                vec![SEEDED.trim_end().to_string()],
                "a static checker appends nothing at all, proved or refused"
            );
        }
    );
}

/// Whether a process exists in a non-zombie state.
fn is_running(pid: libc::pid_t) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, tail)| tail.as_bytes().first())
        .is_some_and(|state| *state != b'Z')
}
