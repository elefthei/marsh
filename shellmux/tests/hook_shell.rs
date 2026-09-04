//! Logging as a hook: assertions on the in-memory record log of an embedded shell.
//!
//! No strace, no btrfs, no mux. The shell built here is the *same* shell the executor runs
//! ([`shellmux::gitshell::build_shell`]), a [`RecordingHook`] is installed directly, and the
//! assertions are about what that hook recorded — which is the whole instrumentation contract on the
//! builtin side, tested without a tracer anywhere in sight.
//!
//! One test per binary: it sets process-wide environment variables, which no sibling test may race.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use shellmux::gitshell;
use shellmux::hooks::{BuiltinRecord, RecordingHook};

/// The deterministic git environment the mux runs commands with.
const GIT_ENV: [(&str, &str); 11] = [
    ("GIT_AUTHOR_NAME", "agent0"),
    ("GIT_AUTHOR_EMAIL", "agent0@marsh.local"),
    ("GIT_AUTHOR_DATE", "1112911993 +0000"),
    ("GIT_COMMITTER_NAME", "agent0"),
    ("GIT_COMMITTER_EMAIL", "agent0@marsh.local"),
    ("GIT_COMMITTER_DATE", "1112911993 +0000"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_PAGER", "cat"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("LC_ALL", "C"),
];

/// Initializes a repository with one commit, exactly as the mux seeds one.
///
/// Test code may fork: the no-fork mandate binds the *shell*, and the point of using the real CLI
/// here is that the repository the builtins operate on was not built by the code under test.
fn init_repository(root: &Path) {
    std::fs::create_dir_all(root.join("src")).expect("create dirs");
    std::fs::write(root.join("src/file0.txt"), b"seed\n").expect("seed file");
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["add", "-A"],
        vec!["commit", "-q", "--allow-empty", "-m", "seed"],
    ] {
        let output = Command::new("git")
            .args(&args)
            .current_dir(root)
            .envs(GIT_ENV.iter().map(|(key, value)| (*key, *value)))
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn the_hook_log_records_builtins_and_not_external_commands() {
    for (key, value) in GIT_ENV {
        // SAFETY: this test binary contains exactly one test, so no other thread is reading the
        // environment while it is modified.
        unsafe { std::env::set_var(key, value) };
    }

    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hook-shell");
    let _ = std::fs::remove_dir_all(&root);
    init_repository(&root);

    let hook = Arc::new(RecordingHook::default());
    let mut shell = gitshell::build_shell(Some(Arc::clone(&hook)))
        .await
        .expect("build shell");

    let command = format!("cd {} && touch foo && git add foo", root.display());
    let result = shell
        .run_dash_c_command(&command)
        .await
        .expect("run command");
    let exit: u8 = result.exit_code.into();
    assert_eq!(exit, 0, "the command itself must succeed");

    let records = hook.records();
    assert!(
        records.iter().any(|record| matches!(
            record,
            BuiltinRecord::Begin { builtin, .. } if builtin == "cd"
        )),
        "`cd` is a builtin and is recorded: {records:?}"
    );
    assert!(
        !records.iter().any(|record| matches!(
            record,
            BuiltinRecord::Begin { builtin, .. } if builtin == "touch"
        )),
        "`touch` is an external command: it belongs to the syscall stream, not this one: {records:?}"
    );

    let (id, ts) = records
        .iter()
        .find_map(|record| match record {
            BuiltinRecord::Begin {
                id,
                ts,
                builtin,
                argv,
                cwd,
                ..
            } if builtin == "git add" => {
                assert_eq!(
                    argv,
                    &["git".to_string(), "add".to_string(), "foo".to_string()],
                    "argv reaches the record verbatim, `argv[0]` included"
                );
                assert_eq!(cwd, &root, "and so does the shell's logical cwd");
                Some((*id, *ts))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no `git add` record in {records:?}"));

    let end_ts = records
        .iter()
        .find_map(|record| match record {
            BuiltinRecord::End {
                id: ended,
                ts,
                exit,
                ..
            } if *ended == id => {
                assert_eq!(*exit, 0, "the staging succeeded");
                Some(*ts)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no end record for id {id} in {records:?}"));
    assert!(ts <= end_ts, "a builtin cannot end before it began");

    let mut ids: Vec<u64> = records
        .iter()
        .filter_map(|record| match record {
            BuiltinRecord::Begin { id, .. } => Some(*id),
            BuiltinRecord::End { .. } => None,
        })
        .collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "ids identify invocations: {records:?}");

    // The log describes a real stage, not a stub.
    assert!(root.join("foo").exists(), "`touch` created the file");
    let repo = git2::Repository::open(&root).expect("open repository");
    assert!(
        repo.index()
            .expect("index")
            .get_path(Path::new("foo"), 0)
            .is_some(),
        "and `git add` really put it in the index"
    );
}
