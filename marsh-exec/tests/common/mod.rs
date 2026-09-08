//! Fixtures shared by the executor's integration tests.
//!
//! Everything here builds an *ordinary* directory: the executor knows nothing about snapshots, so
//! its tests need none. Repositories are seeded with the real git CLI on purpose — the point of a
//! behaviour test is that the tree the builtins operate on was not built by the code under test.

#![allow(
    dead_code,
    reason = "each test binary uses a different part of this fixture"
)]

use std::path::Path;
use std::process::Command;

/// The deterministic git environment marsh runs commands with.
pub const GIT_ENV: [(&str, &str); 11] = [
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

/// Initializes a repository at `root` with one commit containing `src/file0.txt`.
///
/// Test code may fork: the no-fork mandate binds the *shell* the executor runs, not the fixture
/// that prepares its input.
pub fn init_repository(root: &Path) {
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

/// The deterministic git environment as owned pairs, for one child process's environment.
pub fn git_env() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    GIT_ENV
        .iter()
        .map(|(key, value)| {
            (
                std::ffi::OsString::from(*key),
                std::ffi::OsString::from(*value),
            )
        })
        .collect()
}
