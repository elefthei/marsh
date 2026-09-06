//! Shared harness for the mux integration tests.
//!
//! The command renderer [`command_for`] and the capability renderer [`expected_event`] are the two
//! halves of one claim: running that shell command through the mux must produce exactly that
//! capability event. Nothing here inspects the mux's internals; the assertions compare its output
//! against real git and against the policy oracle.

#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]
#![allow(dead_code, reason = "each integration test binary uses a subset")]

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use shellmux::{Action, Event, Principal, PuritySource, Resource, Sandbox, Session, ShellMux};

pub mod oracle;

/// The default job's name, and the principal its commands run as.
pub const MAIN: &str = "main";

/// Number of principals, `agent0 … agent{MAX_AGENTS-1}`.
pub const MAX_AGENTS: usize = 3;
/// Number of pooled paths, `src/file0.txt … src/file{MAX_FILES-1}.txt`.
pub const MAX_FILES: usize = 4;
/// Environment variable pinning the generator seed so a failure replays exactly.
pub const SEED_VARIABLE: &str = "MARSH_FUZZ_SEED";
/// Environment variable overriding the per-trace step budget.
pub const STEPS_VARIABLE: &str = "MARSH_FUZZ_STEPS";

/// Deterministic pseudo-random bytes (LCG), taken verbatim from the validator fork's fuzz harness so
/// generation is comparable across the two suites.
pub fn entropy(seed: u64, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((state >> 33) & 0xff) as u8
        })
        .collect()
}

/// Seed for a run: [`SEED_VARIABLE`] when set, otherwise the wall clock.
///
/// # Panics
///
/// Panics when the variable is set to something other than a decimal or `0x`-prefixed hexadecimal
/// `u64`, rather than silently exploring a different trace set than was asked for.
pub fn random_seed() -> u64 {
    let Ok(text) = std::env::var(SEED_VARIABLE) else {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the epoch");
        // Nanoseconds since the epoch, wrapped into 64 bits: this is seed material, and the wrap
        // is what `as_nanos() as u64` did before, stated without a truncating cast.
        return since_epoch
            .as_secs()
            .wrapping_mul(1_000_000_000)
            .wrapping_add(u64::from(since_epoch.subsec_nanos()));
    };
    let trimmed = text.trim();
    let parsed = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => trimmed.parse::<u64>(),
    };
    parsed.unwrap_or_else(|_| panic!("{SEED_VARIABLE}={text:?} is not a u64"))
}

/// Per-trace step budget: [`STEPS_VARIABLE`] when set, otherwise `default`.
pub fn step_budget(default: usize) -> usize {
    std::env::var(STEPS_VARIABLE)
        .ok()
        .and_then(|text| text.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

/// One concrete generated operation. `Create`/`Modify`/`Delete` are distinct working-tree effects
/// that all request [`Action::Edit`]; `Remove` (`git rm`) is the one that requests
/// [`Action::Delete`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneratedOperation {
    /// Write a currently absent pooled path.
    Create,
    /// Append to a present pooled path.
    Modify,
    /// Remove a present pooled path from the working tree.
    Delete,
    /// `git add -- <path>`.
    Stage,
    /// `git restore --staged -- <path>`.
    Unstage,
    /// `git commit -m "step <n>" -- <path>`.
    Commit,
    /// `git checkout HEAD -- <path>`.
    Checkout,
    /// `git stash push -- <path>`.
    Stash,
    /// Read a present pooled path.
    Read,
    /// `git diff -- <path>`.
    Diff,
    /// `git log -- <path>`.
    History,
    /// `git rm -- <path>`.
    Remove,
    /// `git clean -f -- <path>`.
    Clean,
}

/// Every generated operation, in a fixed order so generation is deterministic.
pub const OPS: [GeneratedOperation; 13] = [
    GeneratedOperation::Create,
    GeneratedOperation::Modify,
    GeneratedOperation::Delete,
    GeneratedOperation::Stage,
    GeneratedOperation::Unstage,
    GeneratedOperation::Commit,
    GeneratedOperation::Checkout,
    GeneratedOperation::Stash,
    GeneratedOperation::Read,
    GeneratedOperation::Diff,
    GeneratedOperation::History,
    GeneratedOperation::Remove,
    GeneratedOperation::Clean,
];

/// The pooled path an operation acts on.
pub fn path_for(file: usize) -> String {
    format!("src/file{file}.txt")
}

/// The principal name for an agent index.
pub fn principal_for(agent: usize) -> Principal {
    Principal::from(format!("agent{agent}"))
}

/// The shell command that performs `operation` on pooled path `file` at generation `step`.
///
/// Every mutation embeds `step`, so a write can never coincidentally reproduce an earlier blob and
/// the ground-truth comparison cannot pass by accident. Redirections exercise brush's *in-process*
/// path (which is precisely why execution had to move into a traced subprocess); the git operations
/// exercise the argv-attribution path. The command runs in the sandbox's own directory, which is
/// the seed root for these fixtures.
pub fn command_for(operation: GeneratedOperation, file: usize, step: usize) -> String {
    let path = path_for(file);
    match operation {
        GeneratedOperation::Create => format!("printf 'step %s\\n' {step} > {path}"),
        GeneratedOperation::Modify => format!("printf 'step %s\\n' {step} >> {path}"),
        GeneratedOperation::Delete => format!("rm -- {path}"),
        GeneratedOperation::Read => format!("cat -- {path}"),
        GeneratedOperation::Stage => format!("git add -- {path}"),
        GeneratedOperation::Unstage => format!("git restore --staged -- {path}"),
        GeneratedOperation::Commit => format!("git commit -m 'step {step}' -- {path}"),
        GeneratedOperation::Checkout => format!("git checkout HEAD -- {path}"),
        GeneratedOperation::Stash => format!("git stash push -- {path}"),
        GeneratedOperation::Diff => format!("git diff -- {path}"),
        GeneratedOperation::History => format!("git log -- {path}"),
        GeneratedOperation::Remove => format!("git rm -- {path}"),
        GeneratedOperation::Clean => format!("git clean -f -- {path}"),
    }
}

/// The capability event [`command_for`] must translate to, exactly.
///
/// Resources are seed-relative, because that is what every path the mux reports is.
pub fn expected_event(
    agent: usize,
    operation: GeneratedOperation,
    file: usize,
    step: usize,
) -> Event {
    let action = match operation {
        GeneratedOperation::Create | GeneratedOperation::Modify | GeneratedOperation::Delete => {
            Action::Edit
        }
        GeneratedOperation::Stage => Action::Stage,
        GeneratedOperation::Unstage => Action::Unstage,
        GeneratedOperation::Commit => Action::commit(format!("step {step}")),
        GeneratedOperation::Checkout => Action::Checkout,
        GeneratedOperation::Stash => Action::Stash,
        GeneratedOperation::Read => Action::Read,
        GeneratedOperation::Diff => Action::Diff,
        GeneratedOperation::History => Action::History,
        GeneratedOperation::Remove => Action::Delete,
        GeneratedOperation::Clean => Action::Clean,
    };
    let segments = vec!["src".to_string(), format!("file{file}.txt")];
    Event::new(principal_for(agent), action, Resource::from(segments))
}

/// One generated candidate operation.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    /// Agent index.
    pub agent: usize,
    /// Operation to perform.
    pub operation: GeneratedOperation,
    /// Pooled path index.
    pub file: usize,
    /// Generation step, also the commit-message suffix.
    pub step: usize,
}

impl Candidate {
    /// The shell command for this candidate.
    pub fn command(&self) -> String {
        command_for(self.operation, self.file, self.step)
    }

    /// The capability event this candidate must produce.
    pub fn event(&self) -> Event {
        expected_event(self.agent, self.operation, self.file, self.step)
    }

    /// The principal running it.
    pub fn principal(&self) -> Principal {
        principal_for(self.agent)
    }

    /// Whether the rendered command runs `git` (used to assert the trace recorded the invocation).
    pub fn is_git(&self) -> bool {
        !matches!(
            self.operation,
            GeneratedOperation::Create
                | GeneratedOperation::Modify
                | GeneratedOperation::Delete
                | GeneratedOperation::Read
        )
    }
}

/// Sequential generator: a port of the fork's `TraceGenerator`, with the same eligibility and
/// grant-transition tables, driven by [`entropy`] instead of a fuzzer's byte stream.
///
/// Tracking working-tree presence and index membership is what keeps the *filesystem* preconditions
/// true independently of the policy, so a denial is always the policy's decision and never a
/// command that could not have run.
pub struct SeqGenerator {
    data: Vec<u8>,
    cursor: usize,
    exists: [bool; MAX_FILES],
    tracked: [bool; MAX_FILES],
    step: usize,
}

impl SeqGenerator {
    /// Starts generation from `seed` with every pooled path present and tracked, matching the seed
    /// commit.
    pub fn new(seed: u64, bytes: usize) -> Self {
        Self {
            data: entropy(seed, bytes),
            cursor: 0,
            exists: [true; MAX_FILES],
            tracked: [true; MAX_FILES],
            step: 0,
        }
    }

    /// Draws the next byte, or `None` once the entropy is spent.
    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.data.get(self.cursor).copied()?;
        self.cursor += 1;
        Some(byte)
    }

    /// Chooses one element of `choices`.
    fn choose<T: Copy>(&mut self, choices: &[T]) -> Option<T> {
        if choices.is_empty() {
            return None;
        }
        let byte = self.next_byte()?;
        Some(choices[usize::from(byte) % choices.len()])
    }

    /// Next candidate whose filesystem precondition currently holds, or `None` when spent.
    pub fn next_candidate(&mut self) -> Option<Candidate> {
        let agent = self.choose(&(0..MAX_AGENTS).collect::<Vec<_>>())?;
        let operations: Vec<GeneratedOperation> = OPS
            .iter()
            .copied()
            .filter(|operation| !self.eligible(*operation).is_empty())
            .collect();
        let operation = self.choose(&operations)?;
        let file = self.choose(&self.eligible(operation))?;
        let step = self.step;
        self.step += 1;
        Some(Candidate {
            agent,
            operation,
            file,
            step,
        })
    }

    /// Applies the working-tree and index effect of a *granted* candidate.
    pub fn record_grant(&mut self, candidate: &Candidate) {
        let file = candidate.file;
        match candidate.operation {
            GeneratedOperation::Create => self.exists[file] = true,
            GeneratedOperation::Delete => self.exists[file] = false,
            // `git rm` drops the working-tree file *and* its index entry.
            GeneratedOperation::Remove => {
                self.exists[file] = false;
                self.tracked[file] = false;
            }
            // `git add -- p` stages whatever the working tree says: content when `p` is present,
            // its removal — which drops the index entry — when it is absent.
            GeneratedOperation::Stage => self.tracked[file] = self.exists[file],
            // `git restore --staged -- p` rewrites the index entry from `HEAD`, re-tracking a
            // `git rm`-ed path without touching the working tree.
            GeneratedOperation::Unstage => self.tracked[file] = true,
            // Both restore `p` from `HEAD`, in the working tree and in the index.
            GeneratedOperation::Checkout | GeneratedOperation::Stash => {
                self.exists[file] = true;
                self.tracked[file] = true;
            }
            GeneratedOperation::Commit
            | GeneratedOperation::Modify
            | GeneratedOperation::Read
            | GeneratedOperation::Diff
            | GeneratedOperation::History
            | GeneratedOperation::Clean => {}
        }
    }

    /// Pooled path indices on which `operation` can execute right now.
    fn eligible(&self, operation: GeneratedOperation) -> Vec<usize> {
        (0..MAX_FILES)
            .filter(|&file| match operation {
                // Gating on `tracked` is what keeps `exists` implying `tracked`.
                GeneratedOperation::Create => !self.exists[file] && self.tracked[file],
                GeneratedOperation::Modify
                | GeneratedOperation::Delete
                | GeneratedOperation::Remove
                | GeneratedOperation::Commit
                | GeneratedOperation::Read => self.exists[file],
                GeneratedOperation::Stage
                | GeneratedOperation::Unstage
                | GeneratedOperation::Checkout
                | GeneratedOperation::Stash
                | GeneratedOperation::Diff
                | GeneratedOperation::History
                | GeneratedOperation::Clean => true,
            })
            .collect()
    }
}

/// Unrestricted generator for the concurrent test: any operation on any path.
///
/// Under concurrency no thread can know the global working-tree state, so gating on a private model
/// would be a fiction. Operations whose preconditions do not hold surface as `ExecFailed` or
/// `DeniedCaps`, which is exactly what a real concurrent shell session looks like.
pub struct RaceGenerator {
    data: Vec<u8>,
    cursor: usize,
    agent: usize,
    step: usize,
}

impl RaceGenerator {
    /// Starts generation for `agent` from `seed`.
    pub fn new(agent: usize, seed: u64, bytes: usize) -> Self {
        Self {
            data: entropy(seed, bytes),
            cursor: 0,
            agent,
            step: 0,
        }
    }

    /// Next candidate, or `None` once the entropy is spent.
    pub fn next_candidate(&mut self) -> Option<Candidate> {
        let operation = OPS[usize::from(*self.data.get(self.cursor)?) % OPS.len()];
        let file = usize::from(*self.data.get(self.cursor + 1)?) % MAX_FILES;
        self.cursor += 2;
        let step = self.step;
        self.step += 1;
        Some(Candidate {
            agent: self.agent,
            operation,
            file,
            step,
        })
    }
}

/// The executor binary this test binary was built alongside.
pub fn executor() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_marsh-exec"))
}

/// A seed subvolume holding the pooled paths, and a mux over it. Returns the seed and the mux.
///
/// Everything lands under `CARGO_TARGET_TMPDIR`, which is the btrfs mount the suite already
/// requires, so no test touches anything of the developer's. The scratch path is unique per test,
/// so two fixtures never share a state directory.
///
/// ```text
/// scratch/seed          btrfs subvolume: the seed, with its repository and seed commit
/// scratch/.marsh/seed/  created by Session::materialize
/// scratch/replay/       replay tree, outside the seed
/// ```
fn seeded_session(
    label: &str,
    purity: impl FnOnce(&Session) -> Vec<Arc<dyn PuritySource>>,
) -> (PathBuf, ShellMux) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("create the scratch directory");

    let seed = scratch.join("seed");
    btrfsutil::subvolume::Subvolume::create(&*seed, None::<btrfsutil::qgroup::QgroupInherit>)
        .expect("create the seed subvolume");
    seed_init(&seed).expect("seed the subvolume");
    // The mux no longer creates a repository; the git-heavy traces need one.
    init_repository(&seed);

    let session = Session::discover(&seed).expect("discover the session");
    // The state directory has to exist before a purity source can open its log in it.
    session.materialize().expect("materialize the session");
    let sources = purity(&session);
    let mux = ShellMux::open(
        session,
        Some(executor()),
        None,
        ShellMux::DEFAULT_CMD_TIMEOUT,
        sources,
    )
    .expect("open mux");
    (seed, mux)
}

/// A seeded session and the mux over it, cleaned up when it goes out of scope.
///
/// Cleanup on drop rather than at the end of each test: an assertion failure unwinds, and a leaked
/// subvolume under `CARGO_TARGET_TMPDIR` outlives the run that made it.
pub struct Fixture {
    /// The seed subvolume.
    seed: PathBuf,
    /// The session, held so cleanup outlives the mux.
    session: Session,
    /// The mux, taken by [`Fixture::finish_mux`] before a test reopens one.
    mux: Option<Arc<ShellMux>>,
}

impl Fixture {
    /// A seed subvolume holding the pooled paths, and a mux over it.
    pub fn new(label: &str) -> Self {
        Self::with_purity(label, |_| Vec::new())
    }

    /// A fixture whose purity sources are built from the discovered session.
    ///
    /// The purity sources need the session, which [`seeded_session`] is the first thing to create.
    pub fn with_purity(
        label: &str,
        purity: impl FnOnce(&Session) -> Vec<Arc<dyn PuritySource>>,
    ) -> Self {
        let (seed, mux) = seeded_session(label, purity);
        let session = mux.session().clone();
        Self {
            seed,
            session,
            mux: Some(Arc::new(mux)),
        }
    }

    /// The mux. Panics once [`Fixture::finish_mux`] has run.
    pub fn mux(&self) -> &Arc<ShellMux> {
        self.mux
            .as_ref()
            .expect("the mux is gone: finish_mux already ran")
    }

    /// The session: the seed and every path marsh writes beside it.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// The seed subvolume itself.
    pub fn seed_root(&self) -> &Path {
        &self.seed
    }

    /// A path inside the seed.
    pub fn seed(&self, path: &str) -> PathBuf {
        self.seed.join(path)
    }

    /// The scratch directory holding the seed and the state: where a test puts anything that must
    /// stay outside the seed, such as a replay tree.
    pub fn scratch(&self) -> PathBuf {
        scratch_of(&self.seed)
    }

    /// Drops the mux before a test reopens one.
    ///
    /// Nothing is flushed — there is no committer — but [`ShellMux::open`] sweeps `snap/`, so a
    /// second mux over a live one would reclaim its sandboxes' snapshots. Panics when another `Arc`
    /// clone is still alive, for the same reason.
    pub fn finish_mux(&mut self) {
        if let Some(mux) = self.mux.take() {
            assert_eq!(
                Arc::strong_count(&mux),
                1,
                "a clone of the mux outlived finish_mux"
            );
            drop(mux);
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.finish_mux();
        remove_session(&self.seed, &self.session);
    }
}

/// A job named `name` over the seed-relative `dir`, and the sandbox it opened.
pub fn sandbox(fixture: &Fixture, name: &str, dir: &str) -> Sandbox {
    fixture
        .mux()
        .spawn(dir, Some(name.to_string()), None, None)
        .expect("open sandbox")
        .sandbox
}

/// The default sandbox every single-job test runs in: `main`, rooted at the seed root.
pub fn main_sandbox(fixture: &Fixture) -> Sandbox {
    sandbox(fixture, MAIN, "")
}

/// One sandbox per agent, named as its principal and rooted at the seed root.
///
/// Separate sandboxes are what makes the agents race: each holds its own snapshot of one shared
/// seed.
pub fn agent_sandboxes(fixture: &Fixture, agents: usize) -> Vec<Sandbox> {
    (0..agents)
        .map(|agent| sandbox(fixture, &principal_for(agent).to_string(), ""))
        .collect()
}

/// Removes a session: its snapshots, the seed subvolume, and the scratch directory.
///
/// Takes the session rather than the mux so a test can clean up *after* dropping the mux.
fn remove_session(seed: &Path, session: &Session) {
    if let Ok(entries) = std::fs::read_dir(session.snap()) {
        for entry in entries.flatten() {
            // A subvolume cannot be removed by `remove_dir_all` while it has contents on this
            // mount, so empty it first; the emptied subvolume then rmdirs.
            let _ = std::fs::remove_dir_all(entry.path());
            let _ = std::fs::remove_dir(entry.path());
        }
    }
    let _ = std::fs::remove_dir_all(seed);
    let _ = std::fs::remove_dir(seed);
    let _ = std::fs::remove_dir_all(scratch_of(seed));
}

/// The scratch directory [`seeded_session`] put the seed and the state in.
///
/// Where a test puts anything that must stay *outside* the seed — a replay tree inside it would be
/// snapshotted, diffed and compared against itself.
fn scratch_of(seed: &Path) -> PathBuf {
    seed.parent()
        .expect("the seed has a scratch parent")
        .to_path_buf()
}

/// Writes the pooled paths every trace starts from.
///
/// `src/.keep` is committed alongside them and never generated against. Without it, `git rm` of the
/// last remaining pooled path would prune the now-empty `src/` directory, and the next `Create`
/// would fail on a missing parent — a property of git's cleanup, not of the mux.
pub fn seed_init(seed: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(seed.join("src"))?;
    std::fs::write(seed.join("src/.keep"), b"")?;
    for file in 0..MAX_FILES {
        std::fs::write(seed.join(path_for(file)), b"seed\n")?;
    }
    Ok(())
}

/// The deterministic git environment, mirroring the mux's so replayed commits hash identically.
///
/// Dates are in git's raw `<epoch> <±HHMM>` form — the same instant as `2005-04-07T22:13:13 +0000`
/// — because that is what the in-process git builtins parse out of the environment.
pub fn git_env(principal: &Principal) -> Vec<(OsString, OsString)> {
    let name = principal.to_string();
    let email = format!("{name}@marsh.local");
    [
        ("GIT_AUTHOR_NAME", name.clone()),
        ("GIT_AUTHOR_EMAIL", email.clone()),
        ("GIT_AUTHOR_DATE", "1112911993 +0000".to_string()),
        ("GIT_COMMITTER_NAME", name),
        ("GIT_COMMITTER_EMAIL", email),
        ("GIT_COMMITTER_DATE", "1112911993 +0000".to_string()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_string()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_string()),
        ("GIT_PAGER", "cat".to_string()),
        ("GIT_TERMINAL_PROMPT", "0".to_string()),
        ("LC_ALL", "C".to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
    .collect()
}

/// The serial ground truth: a plain directory (no subvolume, no snapshots, no tracing) where
/// committed commands are re-executed in commit order.
///
/// This is what "the concurrent run is equivalent to some serial order" is checked against. It runs
/// the same `marsh-exec` binary with the same per-principal environment, so any difference is a
/// difference in the mux's snapshot/commit machinery, not in shell or git behaviour.
pub struct Replayer {
    root: PathBuf,
}

impl Replayer {
    /// Creates the replay tree, seeded and with its seed commit, exactly as the fixture's seed is.
    pub fn new(root: PathBuf) -> Self {
        std::fs::create_dir_all(&root).expect("create replay root");
        seed_init(&root).expect("seed the replay tree");
        init_repository(&root);
        Self { root }
    }

    /// The replay root: what a job's snapshot holds, without the snapshotting.
    pub fn dir(&self) -> &Path {
        &self.root
    }

    /// Replays one command as `principal`, asserting it succeeds.
    pub fn apply(&self, principal: &Principal, cmd: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_marsh-exec"))
            .args(["-c", cmd])
            .current_dir(&self.root)
            .envs(git_env(principal))
            .output()
            .expect("run replay executor");
        assert!(
            output.status.success(),
            "replaying {cmd:?} as {principal} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Gives `tree` the repository and seed commit every fixture's seed carries.
fn init_repository(tree: &Path) {
    let env = git_env(&Principal::from("seed"));
    for args in [
        vec!["init", "-q", "-b", "main"],
        vec!["add", "-A"],
        vec!["commit", "-q", "--allow-empty", "-m", "seed"],
    ] {
        let output = Command::new("git")
            .args(&args)
            .current_dir(tree)
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
}

/// Asserts the seed is indistinguishable from the replay tree: identical worktree bytes and modes,
/// identical `git status --porcelain=v1`, identical `HEAD`.
///
/// Comparing `HEAD` is only meaningful because commit timestamps and identities are pinned; it is
/// what makes "same commits, same order" checkable rather than merely "same files".
pub fn assert_same_seed(seed: &Path, replay_root: &Path, context: &str) {
    assert_same_repo(seed, replay_root, context);
}

/// Asserts one repository pair is indistinguishable, working tree and git state alike.
fn assert_same_repo(left: &Path, right: &Path, context: &str) {
    assert_same_worktree(left, right, context);
    assert_same_git(left, right, context);
}

/// Asserts two working trees hold the same bytes and modes at the same paths.
fn assert_same_worktree(left: &Path, right: &Path, context: &str) {
    let left_tree = worktree(left);
    let right_tree = worktree(right);
    let mut paths: Vec<&String> = left_tree.keys().chain(right_tree.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        assert_eq!(
            left_tree.get(path),
            right_tree.get(path),
            "{context}: worktree differs at {path}\n  {}: {:?}\n  {}: {:?}",
            left.display(),
            left_tree.get(path).map(|(bytes, mode)| (
                String::from_utf8_lossy(bytes).into_owned(),
                format!("{mode:o}")
            )),
            right.display(),
            right_tree.get(path).map(|(bytes, mode)| (
                String::from_utf8_lossy(bytes).into_owned(),
                format!("{mode:o}")
            )),
        );
    }
}

/// Runs one git query in both trees and asserts the output matches.
fn assert_same_git(left: &Path, right: &Path, context: &str) {
    for args in [
        vec!["status", "--porcelain=v1"],
        vec!["rev-parse", "HEAD"],
        vec!["log", "--format=%H %an %s"],
    ] {
        assert_eq!(
            git_output(left, &args),
            git_output(right, &args),
            "{context}: `git {}` differs",
            args.join(" ")
        );
    }
}

/// Every worktree file's bytes and permission bits, keyed by relative path, skipping `.git`.
pub fn worktree(root: &Path) -> HashMap<String, (Vec<u8>, u32)> {
    use std::os::unix::fs::MetadataExt;
    let mut files = HashMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = stack.pop() {
        let entries = std::fs::read_dir(&directory).expect("read worktree directory");
        for entry in entries {
            let entry = entry.expect("read worktree entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            // State lives outside every tree being compared, so `.git` is the only exclusion left.
            if prefix.is_empty() && name == ".git" {
                continue;
            }
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = entry
                .path()
                .symlink_metadata()
                .expect("stat worktree entry");
            if metadata.is_dir() {
                stack.push((entry.path(), relative));
            } else {
                files.insert(
                    relative,
                    (
                        std::fs::read(entry.path()).expect("read worktree file"),
                        metadata.mode() & 0o7777,
                    ),
                );
            }
        }
    }
    files
}

/// Runs git in `root` with the pinned environment and returns its stdout.
pub fn git_output(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .envs(git_env(&Principal::from("seed")))
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} in {} failed: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}
