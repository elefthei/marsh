//! The seed a session is derived from: the claims the CWD-based model exists for.
//!
//! Discovery finds the subvolume above the working directory, a write anywhere in the seed lands in
//! the user's own directory, nested repositories are each git's own, and an interrupted transaction
//! is finished by the next startup.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use common::{Fixture, git_env, options};
use shellmux::{Action, CmdOutcome, Event, Principal, Resource, Session, ShellMux};

/// `sha1("recovered\n")`: what tells an already-applied record from an interrupted one once the
/// snapshot it came from is gone.
const RECOVERED_SHA1: &str = "8d65cba9cd791e30c28632ce019a5c0fb1860e29";

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
    let fixture = Fixture::new("session-discover");
    let inner = fixture.seed("src");

    let session = Session::discover(&inner).expect("discover from a subdirectory");
    assert_eq!(
        session.seed,
        fixture.seed_root(),
        "the seed is the enclosing subvolume, not the directory marsh was started in"
    );
    assert_eq!(
        session.root,
        fixture.scratch().join(".marsh").join("seed"),
        "and the state lives beside it, namespaced by the seed's name"
    );
    assert_eq!(
        session.default_dir(&inner),
        "src",
        "the default job is rooted where marsh was started"
    );
}

/// The seed root is the user's own directory, so a write there is a capability like any other and
/// lands in the seed: there is nowhere inside the seed for a write to be dropped.
#[test]
fn a_write_at_the_seed_root_commits() {
    let fixture = Fixture::new("session-root-write");
    let mux = fixture.mux();
    let sandbox = mux.open_sandbox("main", "").expect("open sandbox");

    let outcome = mux
        .run_cmd(&sandbox, "printf 'x\\n' > stray.txt")
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
}

/// A seed may hold many repositories at any depth. Each git command uses the one above it, and the
/// resources it requests are seed-relative — so two repositories never collide in the history, and
/// no `.git/` path at any depth becomes a capability.
#[test]
fn a_nested_repository_is_the_one_git_uses() {
    let fixture = Fixture::new("session-nested");
    for name in ["alpha", "beta"] {
        nested_repository(&fixture, name);
    }
    let mux = fixture.mux();

    for name in ["alpha", "beta"] {
        let sandbox = mux.open_sandbox(name, name).expect("open sandbox");
        let outcome = mux
            .run_cmd(
                &sandbox,
                "printf 'edit\\n' > src/file0.txt && git add -- src/file0.txt",
            )
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
}

/// The crash window the log exists for: the records are durable, the seed is not yet whole. The
/// next startup finishes the transaction before anything else reads the seed, and re-derives the
/// history entry the crash cost.
#[test]
fn an_interrupted_transaction_is_finished_on_open() {
    let mut fixture = Fixture::new("session-recover");
    let sandbox = fixture
        .mux()
        .open_sandbox("main", "")
        .expect("open sandbox");

    // A job snapshot holding content the seed has never seen, and a log that describes moving it
    // there but never reached its `END`.
    let work = fixture.session().work(&sandbox.uid);
    std::fs::write(work.join("src/recovered.txt"), b"recovered\n").expect("snapshot file");
    let log = format!(
        concat!(
            r#"{{"op":"BEGIN","seq":1,"uid":"{uid}","principal":"main","cmd":"printf recovered","events":[]}}"#,
            "\n",
            r#"{{"op":"MOVE","from":"src/recovered.txt","to":"src/recovered.txt","sha1":"{sha1}"}}"#,
            "\n"
        ),
        uid = sandbox.uid,
        sha1 = RECOVERED_SHA1,
    );
    std::fs::write(fixture.session().meta().join("wal.jsonl"), log).expect("write the log");
    fixture.finish_mux();

    let reopened = ShellMux::open(fixture.session().clone(), options()).expect("reopen mux");
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/recovered.txt"))
            .expect("the interrupted transaction was finished"),
        "recovered\n"
    );
    let history = std::fs::read_to_string(fixture.session().meta().join("history.jsonl"))
        .expect("read the history");
    assert!(
        history.contains("\"seq\":1"),
        "and its history entry was re-derived from the same log: {history}"
    );
    drop(reopened);
}
