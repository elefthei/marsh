//! Behaviour of the executor API against real commands in ordinary directories.
//!
//! Nothing here mocks the worker: each test launches the real `marsh-exec` binary under the real
//! tracer, in a temporary directory, and asserts on what came back.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

use std::ffi::OsString;
use std::path::Path;

use marsh_exec::hooks::BuiltinRecord;
use marsh_exec::{
    ExecutionEvent, ExecutionRequest, ExecutionResult, MarshExecutor, PersistenceLayer,
};

mod common;

/// The run id every fixture command's instrumentation is filed under.
const RUN_ID: &str = "case";

/// An executor over ordinary directories: `cwd` is the seed, `state` the metadata beside it.
///
/// No btrfs materialization — the executor needs only its lease and its own `meta/runs` — and no
/// timeout override, so every command here runs under [`MarshExecutor::DEFAULT_CMD_TIMEOUT`].
fn executor(cwd: &Path, state: &Path) -> MarshExecutor {
    MarshExecutor::builder(PersistenceLayer::new(
        cwd.to_path_buf(),
        state.to_path_buf(),
    ))
    .worker(env!("CARGO_BIN_EXE_marsh-exec"))
    .build()
    .expect("build executor")
}

/// Runs `command` in `cwd` with `envs` added, and collects its result.
fn run(cwd: &Path, state: &Path, command: &str, envs: &[(OsString, OsString)]) -> ExecutionResult {
    executor(cwd, state)
        .prepare()
        .expect("prepare")
        .run(ExecutionRequest {
            command,
            cwd,
            envs,
            run_id: RUN_ID,
        })
        .expect("run")
        .collect()
        .expect("collect")
}

/// Every completed builtin invocation of `name`, as `(argv, exit)`.
fn completed_invocations(result: &ExecutionResult, name: &str) -> Vec<(Vec<String>, u8)> {
    let events = result
        .evidence
        .as_ref()
        .expect("a completed run has evidence")
        .events();
    let mut invocations = Vec::new();
    for event in events {
        let ExecutionEvent::Builtin(BuiltinRecord::Begin {
            id, builtin, argv, ..
        }) = event
        else {
            continue;
        };
        if builtin != name {
            continue;
        }
        let exit = events.iter().find_map(|other| match other {
            ExecutionEvent::Builtin(BuiltinRecord::End {
                id: ended, exit, ..
            }) if ended == id => Some(*exit),
            _ => None,
        });
        if let Some(exit) = exit {
            invocations.push((argv.clone(), exit));
        }
    }
    invocations
}

/// A shell that could replace its own process image would never reach the record dump, so the
/// records of everything it already ran would be lost — including the ones a caller authorizes on.
#[test]
fn worker_cannot_replace_itself_before_record_dump() {
    let work = tempfile::tempdir().expect("work directory");
    let state = tempfile::tempdir().expect("state directory");
    let result = run(
        work.path(),
        state.path(),
        "printf before; exec true",
        &common::git_env(),
    );

    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "before",
        "everything before the replacement attempt really ran"
    );
    assert_ne!(result.exit_code, 0, "and the replacement itself failed");
    assert_eq!(
        completed_invocations(&result, "printf"),
        vec![(vec!["printf".to_string(), "before".to_string()], 0)],
        "the dump still carries the invocation that preceded it"
    );
}

/// A host `core.autocrlf` rewrites line endings while hashing, so the same worktree file would
/// land in the object database as a different blob than the git CLI produces.
#[test]
fn host_git_configuration_does_not_rewrite_staged_bytes() {
    /// `line` followed by CRLF: the bytes `core.autocrlf = true` would rewrite while staging.
    const CRLF: [u8; 6] = [108, 105, 110, 101, 13, 10];

    let work = tempfile::tempdir().expect("work directory");
    let state = tempfile::tempdir().expect("state directory");
    let home = tempfile::tempdir().expect("home directory");
    let xdg = tempfile::tempdir().expect("xdg directory");
    common::init_repository(work.path());
    std::fs::write(
        home.path().join(".gitconfig"),
        "[core]\n\tautocrlf = true\n",
    )
    .expect("host git configuration");
    std::fs::write(work.path().join("src/crlf.txt"), CRLF).expect("crlf file");

    // Set on the child only: this binary holds several tests, and no test may mutate the process
    // environment out from under a sibling.
    let mut envs = common::git_env();
    envs.push((OsString::from("HOME"), OsString::from(home.path())));
    envs.push((
        OsString::from("XDG_CONFIG_HOME"),
        OsString::from(xdg.path()),
    ));
    let result = run(work.path(), state.path(), "git add -- src/crlf.txt", &envs);
    assert_eq!(
        result.exit_code,
        0,
        "staging failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let repository = git2::Repository::open(work.path()).expect("open repository");
    let index = repository.index().expect("index");
    let entry = index
        .get_path(Path::new("src/crlf.txt"), 0)
        .expect("the path is staged");
    let blob = repository.find_blob(entry.id).expect("staged blob");
    assert_eq!(
        blob.content(),
        CRLF,
        "the host's autocrlf setting reached the staged bytes"
    );
}

/// The executor's own persistence decides where instrumentation lands, so a run id names a
/// directory under `meta/runs` and can never name anything else.
#[test]
fn a_run_id_files_both_logs_under_the_executors_own_metadata() {
    let work = tempfile::tempdir().expect("work directory");
    let state = tempfile::tempdir().expect("state directory");
    let result = run(
        work.path(),
        state.path(),
        "printf builtin > builtin.txt; touch external.txt; cat builtin.txt",
        &common::git_env(),
    );

    assert_eq!(
        result.exit_code,
        0,
        "the default budget ran the command to completion: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "builtin",
        "a captured run returns what the command printed"
    );
    assert!(
        work.path().join("external.txt").exists(),
        "the external command really ran"
    );
    assert!(
        result.evidence.is_some(),
        "and a successful captured run carries evidence"
    );

    let run_dir = state.path().join("meta").join("runs").join(RUN_ID);
    assert_eq!(
        result.logs.trace_log,
        run_dir.join("trace.log"),
        "the trace log is filed under the run id"
    );
    assert_eq!(
        result.logs.builtin_log,
        run_dir.join("builtins.json"),
        "and the builtin dump beside it"
    );
    assert!(result.logs.trace_log.exists(), "both logs are real files");
    assert!(result.logs.builtin_log.exists());
}

/// A run id is caller input that becomes a path, so anything that could climb out of the session's
/// metadata must fail before a directory is created.
#[test]
fn an_invalid_run_id_writes_nothing() {
    let work = tempfile::tempdir().expect("work directory");
    let state = tempfile::tempdir().expect("state directory");
    let executor = executor(work.path(), state.path());

    for rejected in ["", "..", "../escape", "nested/run", "/absolute"] {
        let error = executor
            .prepare()
            .expect("prepare")
            .run(ExecutionRequest {
                command: "printf escaped > escaped.txt",
                cwd: work.path(),
                envs: &common::git_env(),
                run_id: rejected,
            })
            .expect_err("an invalid run id is refused");
        assert!(
            format!("{error}").contains("invalid execution run id"),
            "{rejected}: got {error}"
        );
    }
    assert!(
        !work.path().join("escaped.txt").exists(),
        "no command ran at all"
    );
    assert!(
        !state.path().join("meta").join("runs").exists(),
        "and no run directory was created"
    );
}
