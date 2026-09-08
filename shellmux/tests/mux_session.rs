//! The seed a session is derived from: the claims the CWD-based model exists for.
//!
//! Discovery finds the subvolume above the working directory, a write anywhere in the seed lands in
//! the user's own directory, nested repositories are each git's own, and an interrupted transaction
//! is finished by the next startup.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use common::{Fixture, executor, git_env};
use marsh_exec::ExecError;
use shellmux::{
    Action, CmdOutcome, Event, MarshExecutor, PersistenceLayer, Principal, PurityCheckerBuilder,
    Resource, ShellId,
};

/// `sha1("recovered\n")`: what tells an already-applied record from an interrupted one once the
/// snapshot it came from is gone.
const RECOVERED_SHA1: &str = "8d65cba9cd791e30c28632ce019a5c0fb1860e29";

/// A command that changes nothing and still takes the full transaction.
///
/// `true` would not: the fixture's static purity checker proves it read-only from its own syntax
/// and runs it in the shared reader tree, so the job would never get the private snapshot these
/// recovery tests then interfere with. `printf` is deliberately outside the provable set.
const SNAPSHOT_TAKING_NOOP: &str = "printf ''";

/// Test-owned native process that cannot leak when an assertion unwinds.
struct TestChild(Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts a HUP-ignoring process carrying one snapshot ownership marker.
fn spawn_marked_process(marker: &Path) -> TestChild {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "trap '' HUP; printf 'ready\\n'; exec sleep 60"])
        .env(marsh_exec::SNAPSHOT_ROOT_VAR, marker)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn marked process");
    let stdout = child.stdout.take().expect("capture readiness output");
    let mut ready = String::new();
    BufReader::new(stdout)
        .read_line(&mut ready)
        .expect("read process readiness");
    assert_eq!(ready, "ready\n");
    TestChild(child)
}

/// Creates `name` under the seed as its own repository with a seed commit, and returns its path.
fn nested_repository(fixture: &Fixture, name: &str) -> std::path::PathBuf {
    let dir = fixture.seed(name);
    std::fs::create_dir_all(dir.join("src")).expect("create the nested directory");
    std::fs::write(dir.join("src/file0.txt"), b"seed\n").expect("seed the nested repository");
    let env = git_env(&Principal::from("seed"));
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["add", "-A"],
        vec!["commit", "-q", "-m", "seed"],
    ] {
        let output = std::process::Command::new("git")
            .args(&args)
            .current_dir(&dir)
            .envs(env.iter().cloned())
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    dir
}

/// The session is derived from the working directory, not from an argument: starting anywhere
/// inside the seed finds the same seed, and the job starts where marsh was started.
#[test]
fn the_seed_is_the_subvolume_above_the_cwd() {
    let fixture = Fixture::cold("session-discover");
    let inner = fixture.seed("src");

    let persistence = PersistenceLayer::discover(&inner).expect("discover from a subdirectory");
    assert_eq!(
        persistence.seed,
        fixture.seed_root(),
        "the seed is the enclosing subvolume, not the directory marsh was started in"
    );
    assert_eq!(
        persistence.root,
        fixture.scratch().join(".marsh").join("seed"),
        "and the state lives beside it, namespaced by the seed's name"
    );
    assert_eq!(
        persistence.default_dir(&inner),
        "src",
        "the default job is rooted where marsh was started"
    );
}

/// The seed root is the user's own directory, so a write there is a capability like any other and
/// lands in the seed: there is nowhere inside the seed for a write to be dropped.
#[test]
fn a_write_at_the_seed_root_commits() {
    mux_test!(fixture = Fixture::new("session-root-write"), {
        let mux = fixture.mux();
        let sandbox = common::sandbox(&fixture, "main", "").await;

        let outcome = mux
            .run_cmd(&sandbox, "printf 'x\\n' > stray.txt")
            .await
            .expect("run the root write");
        let CmdOutcome::Committed { granted, .. } = &outcome else {
            panic!("expected a commit, got {outcome:?}");
        };
        assert_eq!(
            granted,
            &vec![Event::new(
                "main",
                Action::Edit,
                Resource::from(vec!["stray.txt"])
            )],
            "the resource is the seed-relative path itself"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("stray.txt")).expect("read the seed"),
            "x\n"
        );
    });
}

/// A seed may hold many repositories at any depth. Each git command uses the one above it, and the
/// resources it requests are seed-relative — so two repositories never collide in the history, and
/// no `.git/` path at any depth becomes a capability.
#[test]
fn a_nested_repository_is_the_one_git_uses() {
    mux_test!(fixture = Fixture::new("session-nested"), {
        for name in ["alpha", "beta"] {
            nested_repository(&fixture, name);
        }
        let mux = fixture.mux();

        for name in ["alpha", "beta"] {
            let sandbox = common::sandbox(&fixture, name, name).await;
            let outcome = mux
                .run_cmd(
                    &sandbox,
                    "printf 'edit\\n' > src/file0.txt && git add -- src/file0.txt",
                )
                .await
                .expect("run the nested git command");
            let CmdOutcome::Committed { granted, .. } = &outcome else {
                panic!("expected a commit in {name}, got {outcome:?}");
            };
            assert_eq!(
                granted,
                &vec![
                    Event::new(
                        name,
                        Action::Edit,
                        Resource::from(vec![name, "src", "file0.txt"])
                    ),
                    Event::new(
                        name,
                        Action::Stage,
                        Resource::from(vec![name, "src", "file0.txt"])
                    ),
                ],
                "the resource names the repository's own path under the seed"
            );
            assert_eq!(
                std::fs::read_to_string(fixture.seed(&format!("{name}/src/file0.txt")))
                    .expect("read the seed"),
                "edit\n"
            );
        }
    });
}

/// The crash window the log exists for: the records are durable, the seed is not yet whole. The
/// next startup finishes the transaction before anything else reads the seed, and re-derives the
/// history entry the crash cost.
#[test]
fn an_interrupted_transaction_is_finished_on_open() {
    mux_test!(fixture = Fixture::new("session-recover"), {
        let sandbox = common::sandbox(&fixture, "main", "").await;
        let persistence = fixture.persistence();

        // A job snapshot holding content the seed has never seen, and a complete durable intent
        // that never reached END. Recovery must consume it before startup reclaims any abandoned
        // state.
        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, SNAPSHOT_TAKING_NOOP)
            .await
            .expect("take the recovery snapshot");
        assert!(matches!(outcome, CmdOutcome::Committed { .. }));
        let work = persistence.work(&sandbox.uid);
        std::fs::write(work.join("src/recovered.txt"), b"recovered\n").expect("snapshot file");

        let orphan = common::sandbox(&fixture, "orphan", "").await;
        let outcome = fixture
            .mux()
            .run_cmd(&orphan, SNAPSHOT_TAKING_NOOP)
            .await
            .expect("take the unrelated snapshot");
        assert!(matches!(outcome, CmdOutcome::Committed { .. }));
        let orphan_work = persistence.work(&orphan.uid);
        assert!(orphan_work.exists());
        let temporary = fixture.seed("src/orphan.tmp-wal");
        std::fs::write(&temporary, b"garbage\n").expect("create abandoned temporary");

        let log = interrupted_log(&sandbox.uid);
        std::fs::write(persistence.meta().join("wal.jsonl"), log).expect("write the log");
        fixture.finish_mux().await;

        let reopened = common::reopen(&persistence).await;
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/recovered.txt"))
                .expect("the interrupted transaction was finished"),
            "recovered\n"
        );
        assert!(
            !work.exists(),
            "the recovery snapshot is reclaimed afterward"
        );
        assert!(!orphan_work.exists(), "unrelated snapshots are reclaimed");
        assert!(!temporary.exists(), "abandoned temporaries are reclaimed");
        common::close_mux(reopened).await;

        let reopened = common::reopen(&persistence).await;
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/recovered.txt"))
                .expect("read recovered file"),
            "recovered\n"
        );
        let history = std::fs::read_to_string(persistence.meta().join("history.jsonl"))
            .expect("read the history");
        assert_eq!(
            history.lines().filter(|line| !line.is_empty()).count(),
            1,
            "recovery records the transaction exactly once: {history}"
        );
        common::close_mux(reopened).await;
    });
}

/// A complete durable intent for `uid` that never reached END.
fn interrupted_log(uid: &str) -> String {
    format!(
        concat!(
            r#"{{"op":"BEGIN","seq":1,"uid":"{uid}","principal":"main","cmd":"printf recovered","events":[],"op_count":1}}"#,
            "\n",
            r#"{{"op":"MOVE","from":"src/recovered.txt","to":"src/recovered.txt","sha1":"{sha1}"}}"#,
            "\n"
        ),
        uid = uid,
        sha1 = RECOVERED_SHA1,
    )
}

/// A prefix whose BEGIN promises more records than reached disk is never authorized or applied.
#[test]
fn an_incomplete_intent_never_reaches_the_seed() {
    mux_test!(fixture = Fixture::new("session-incomplete-intent"), {
        let sandbox = common::sandbox(&fixture, "main", "").await;
        let persistence = fixture.persistence();
        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, SNAPSHOT_TAKING_NOOP)
            .await
            .expect("take the interrupted snapshot");
        assert!(matches!(outcome, CmdOutcome::Committed { .. }));
        let work = persistence.work(&sandbox.uid);
        std::fs::write(work.join("src/abandoned.txt"), b"recovered\n").expect("snapshot file");
        let log = format!(
            concat!(
                r#"{{"op":"BEGIN","seq":1,"uid":"{uid}","principal":"main","cmd":"write two files","events":[],"op_count":2}}"#,
                "\n",
                r#"{{"op":"MOVE","from":"src/abandoned.txt","to":"src/abandoned.txt","sha1":"{sha1}"}}"#,
                "\n",
                r#"{{"op":"MOVE","from":"src/torn""#
            ),
            uid = sandbox.uid,
            sha1 = RECOVERED_SHA1,
        );
        std::fs::write(persistence.meta().join("wal.jsonl"), log).expect("write torn log");
        fixture.finish_mux().await;

        let reopened = common::reopen(&persistence).await;
        assert!(!fixture.seed("src/abandoned.txt").exists());
        assert!(reopened.history().is_empty());

        let next = reopened
            .spawn("", Some(ShellId::from("next")), None)
            .await
            .expect("open next job")
            .sandbox;
        let outcome = reopened
            .run_cmd(&next, "printf 'survived\\n' > src/survived.txt")
            .await
            .expect("commit after abandoned intent");
        assert!(
            matches!(outcome, CmdOutcome::Committed { seq: 1, .. }),
            "the abandoned intent did not consume its sequence: {outcome:?}"
        );
        common::close_mux(reopened).await;

        let reopened = common::reopen(&persistence).await;
        assert!(!fixture.seed("src/abandoned.txt").exists());
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/survived.txt")).expect("read surviving file"),
            "survived\n"
        );
        let history = std::fs::read_to_string(persistence.meta().join("history.jsonl"))
            .expect("read history");
        assert_eq!(history.lines().filter(|line| !line.is_empty()).count(), 1);
        common::close_mux(reopened).await;
    });
}

/// Startup kills only positively identified leftovers before reclaiming their snapshots.
#[test]
fn startup_stops_owned_leftovers_before_reclaiming_their_snapshots() {
    mux_test!(fixture = Fixture::new("session-orphan-process"), {
        let sandbox = common::sandbox(&fixture, "leftover", "").await;
        let persistence = fixture.persistence();
        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, SNAPSHOT_TAKING_NOOP)
            .await
            .expect("take the leftover snapshot");
        assert!(matches!(outcome, CmdOutcome::Committed { .. }));
        let snapshot = persistence
            .work(&sandbox.uid)
            .canonicalize()
            .expect("canonical snapshot");

        let mut owned = spawn_marked_process(&snapshot);
        let peer_marker = persistence.snap().with_file_name("snap-other").join("peer");
        let mut peer = spawn_marked_process(&peer_marker);
        fixture.finish_mux().await;

        let reopened = common::reopen(&persistence).await;
        assert!(
            owned.0.try_wait().expect("inspect owned process").is_some(),
            "the owned leftover is terminated before open returns"
        );
        assert!(
            peer.0.try_wait().expect("inspect peer process").is_none(),
            "a marker outside the exact session root is not owned"
        );
        assert!(
            !snapshot.exists(),
            "the dead process's snapshot is reclaimed"
        );
        common::close_mux(reopened).await;

        peer.0.kill().expect("stop peer process");
        peer.0.wait().expect("reap peer process");
    });
}

/// Startup must not inspect or reclaim state while another mux still owns the session.
///
/// The competitor now fails where ownership is actually taken — building its executor — so it never
/// reaches the recovery that reads, repairs and truncates logs. A torn purity log is the sharpest
/// witness of that: reading one repairs it in place, so a competitor that touched it would leave a
/// different file behind.
#[test]
fn startup_refuses_a_live_session_without_touching_its_state() {
    mux_test!(fixture = Fixture::new("session-busy"), {
        let sandbox = common::sandbox(&fixture, "main", "").await;
        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, "printf 'busy\\n' > busy.txt")
            .await
            .expect("take the snapshot");
        assert!(matches!(outcome, CmdOutcome::Committed { .. }));

        let persistence = fixture.persistence();
        let snapshot = persistence.work(&sandbox.uid);
        let seed_before = std::fs::read(fixture.seed("src/file0.txt")).expect("read the seed");
        let wal_path = persistence.meta().join("wal.jsonl");
        let wal_before = std::fs::read(&wal_path).expect("read the WAL");
        let purity_path = persistence.meta().join("purity.jsonl");
        let torn = "{\"cmd\":\"ls\",\"dir\":\"\",\"pure\":true}\n{\"cmd\":\"cat -- s";
        std::fs::write(&purity_path, torn).expect("write a torn purity log");

        let competitor = MarshExecutor::builder(PersistenceLayer::new(
            persistence.seed.clone(),
            persistence.root.clone(),
        ))
        .worker(executor())
        .build();
        let Err(ExecError::SessionBusy(path)) = competitor else {
            panic!("a live session must reject a second owner")
        };
        assert_eq!(path, fixture.seed_root());
        assert!(snapshot.exists(), "the live snapshot must not be reclaimed");
        assert_eq!(
            std::fs::read(fixture.seed("src/file0.txt")).expect("reread the seed"),
            seed_before
        );
        assert_eq!(
            std::fs::read(&wal_path).expect("reread the WAL"),
            wal_before
        );
        assert_eq!(
            std::fs::read_to_string(&purity_path).expect("reread the purity log"),
            torn,
            "a competitor that never took the lease cannot repair a torn log"
        );

        fixture.finish_mux().await;
        let reopened = common::reopen(&persistence).await;
        assert!(
            !snapshot.exists(),
            "startup reclaims the abandoned snapshot"
        );
        common::close_mux(reopened).await;
    });
}

/// The whole restart contract in one run: a fresh layer, a fresh executor and a fresh mux over the
/// same paths repair the interrupted transaction *before* sweeping the snapshot that carried it,
/// and restore the learned purity cache *after* that repair.
#[test]
fn a_released_session_is_recovered_then_swept_then_restored() {
    mux_test!(fixture = Fixture::new("session-restart"), {
        let sandbox = common::sandbox(&fixture, "main", "").await;
        let persistence = fixture.persistence();
        let outcome = fixture
            .mux()
            .run_cmd(&sandbox, SNAPSHOT_TAKING_NOOP)
            .await
            .expect("take the recovery snapshot");
        assert!(matches!(outcome, CmdOutcome::Committed { .. }));

        let work = persistence.work(&sandbox.uid);
        std::fs::write(work.join("src/recovered.txt"), b"recovered\n").expect("snapshot file");
        std::fs::write(
            persistence.meta().join("wal.jsonl"),
            interrupted_log(&sandbox.uid),
        )
        .expect("write the log");
        std::fs::write(
            persistence.meta().join("purity.jsonl"),
            "{\"cmd\":\"ls\",\"dir\":\"\",\"pure\":true}\n",
        )
        .expect("seed the purity cache");
        fixture.finish_mux().await;

        let reopened =
            common::reopen_with(&persistence, PurityCheckerBuilder::new().learned().build()).await;
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/recovered.txt"))
                .expect("the interrupted transaction was finished"),
            "recovered\n",
            "recovery ran before the sweep that reclaims the snapshot it read from"
        );
        assert!(!work.exists(), "and the sweep then reclaimed it");

        let fresh = reopened
            .spawn("", Some(ShellId::from("fresh")), None)
            .await
            .expect("open a job")
            .sandbox;
        let outcome = reopened
            .run_cmd(&fresh, "ls")
            .await
            .expect("run the learned command");
        assert!(
            matches!(outcome, CmdOutcome::Bypassed { .. }),
            "the restored cache is what lets it skip the sandbox: {outcome:?}"
        );
        common::close_mux(reopened).await;
    });
}
