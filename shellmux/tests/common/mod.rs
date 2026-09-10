//! Shared harness for the mux integration tests.
//!
//! The command renderer [`command_for`] and the capability renderer [`expected_event`] are the two
//! halves of one claim: running that shell command through the mux must produce exactly that
//! capability event. Nothing here inspects the mux's internals; the assertions compare its output
//! against real git and against the policy oracle.

#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]
#![allow(dead_code, reason = "each integration test binary uses a subset")]

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use marsh_exec::ExecError;
use shellmux::{
    Action, Event, FrontendEvent, JobView, MarshExecutor, MarshFrontend, MuxError,
    PersistenceLayer, Principal, PurityChecker, PurityCheckerBuilder, Reaped, Resource, Sandbox,
    ShellId, ShellMux, Spawned,
};
use tokio::sync::Notify;

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

/// Rows every fixture's mux gives its jobs, and the height a resize test starts from.
pub const ROWS: u16 = 24;
/// Columns every fixture's mux gives its jobs.
pub const COLS: u16 = 80;

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
}

/// Upper bound on a generated trace's length, and the inclusive top of the encoded step budget.
///
/// The reference generator's `MAX_TRACE_LENGTH`: the first `int_in_range(0..=MAX_TRACE_LENGTH)`
/// draw off an input decides how many candidates that input is worth.
pub const MAX_TRACE_LENGTH: usize = 32;

/// Sequential generator: a port of the fork's `TraceGenerator`, with the same byte decoder, the
/// same eligibility table and the same grant-transition table.
///
/// Borrowed entropy decoded through [`arbitrary::Unstructured`] rather than a private cursor: the
/// reference's candidate stream is *defined* by `int_in_range` and `choose`, down to a singleton
/// choice costing no bytes at all, so a hand-rolled modulo decoder would diverge from the shared
/// corpus the first time a pool narrowed to one path.
///
/// Tracking working-tree presence and index membership is what keeps the *filesystem*
/// preconditions true independently of the policy, so a denial is always the policy's decision and
/// never a command that could not have run.
pub struct SeqGenerator<'data> {
    /// The unconsumed entropy, and the decoder over it.
    unstructured: arbitrary::Unstructured<'data>,
    /// Working-tree presence per pooled path. An array rather than a set, because its ascending
    /// order is what generation draws from.
    exists: [bool; MAX_FILES],
    /// Index-entry presence per pooled path. A path leaves the index only through `git rm` or a
    /// `git add` of an already-absent path, and [`GeneratedOperation::Create`] is gated on it, so
    /// working-tree presence implies trackedness.
    tracked: [bool; MAX_FILES],
    /// Candidates emitted so far, the ones a policy later refused included.
    step: usize,
}

impl<'data> SeqGenerator<'data> {
    /// Starts generation over `data` with every pooled path present and tracked, matching the seed
    /// commit.
    pub fn new(data: &'data [u8]) -> Self {
        Self {
            unstructured: arbitrary::Unstructured::new(data),
            exists: [true; MAX_FILES],
            tracked: [true; MAX_FILES],
            step: 0,
        }
    }

    /// Consumes the encoded step budget in `0..=MAX_TRACE_LENGTH` off the front of the input.
    ///
    /// Call at most once, before any candidate: this is the reference's first draw, and skipping
    /// or repeating it shifts every byte after it.
    pub fn step_budget(&mut self) -> usize {
        // `arbitrary` answers with the range start rather than an error once the input is spent,
        // so trace length is bounded by `is_empty` in `next_candidate` and never by an `Err`.
        self.unstructured
            .int_in_range(0..=MAX_TRACE_LENGTH)
            .unwrap_or(0)
    }

    /// The agent the next candidate would be drawn for, without spending a byte finding out.
    ///
    /// A batch admits at most one command per principal, and that boundary has to be decided
    /// *before* a candidate exists: rerolling a duplicate, or carrying an already-drawn one across
    /// a committing batch, would make this suite's trace a different trace from the reference's.
    /// Decoding a copy of the remaining input answers the question and leaves the real cursor
    /// exactly where it was.
    pub fn peek_agent(&self) -> Option<usize> {
        let remaining = self.unstructured.peek_bytes(self.unstructured.len())?;
        if remaining.is_empty() {
            return None;
        }
        arbitrary::Unstructured::new(remaining)
            .int_in_range(0..=MAX_AGENTS - 1)
            .ok()
    }

    /// Next candidate whose filesystem precondition currently holds, or `None` once the input is
    /// spent.
    ///
    /// Draws an `(agent, operation, file)` triple, restricted to the operations with at least one
    /// eligible path — a set that is never empty, because `Stage`, `Unstage`, `Checkout`, `Stash`,
    /// `Diff`, `History` and `Clean` accept every pooled path. The step counter advances for every
    /// candidate emitted, whether or not the policy later admits it: a filtered candidate still
    /// cost its bytes.
    pub fn next_candidate(&mut self) -> Option<Candidate> {
        if self.unstructured.is_empty() {
            return None;
        }
        let agent = self.unstructured.int_in_range(0..=MAX_AGENTS - 1).ok()?;
        // Fixed arrays with a used prefix: one candidate costs three draws, and the eligible sets
        // are bounded by the operation table and the pool.
        let mut operations = [OPS[0]; OPS.len()];
        let mut eligible_operations = 0;
        for operation in OPS {
            if self.eligible(operation).1 > 0 {
                operations[eligible_operations] = operation;
                eligible_operations += 1;
            }
        }
        let operation = *self
            .unstructured
            .choose(&operations[..eligible_operations])
            .ok()?;
        let (files, eligible_files) = self.eligible(operation);
        let file = *self.unstructured.choose(&files[..eligible_files]).ok()?;
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

    /// Whether pooled path `file` is present in the working tree, and whether the index holds it.
    ///
    /// What a runner compares against the real repository at a settled boundary, so a model that
    /// drifted from disk fails the harness instead of generating impossible commands.
    pub const fn file_state(&self, file: usize) -> (bool, bool) {
        (self.exists[file], self.tracked[file])
    }

    /// Pooled path indices, ascending, on which `operation` can execute right now: the filled
    /// prefix of the returned array, and how long that prefix is.
    fn eligible(&self, operation: GeneratedOperation) -> ([usize; MAX_FILES], usize) {
        let mut files = [0; MAX_FILES];
        let mut used = 0;
        for file in 0..MAX_FILES {
            let allowed = match operation {
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
            };
            if allowed {
                files[used] = file;
                used += 1;
            }
        }
        (files, used)
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

/// The `marsh-exec` worker built for this Cargo target and profile.
///
/// It lives in another package now, so `CARGO_BIN_EXE_*` does not name it here. The running test
/// executable is at `<profile>/deps/<name>-<hash>`, and the worker is at `<profile>/marsh-exec` —
/// which is exactly where the mux's own default resolution looks. Deriving it that way preserves
/// custom target directories and the debug/release split, without searching `PATH`, guessing
/// `target/debug`, or invoking Cargo from inside a test.
pub fn executor() -> PathBuf {
    let test_executable = std::env::current_exe().expect("current test executable");
    let deps = test_executable.parent().expect("test executable directory");
    assert_eq!(
        deps.file_name().and_then(|name| name.to_str()),
        Some("deps"),
        "test executable is not in Cargo's deps directory"
    );
    let worker = deps
        .parent()
        .expect("Cargo profile directory")
        .join("marsh-exec");
    assert!(
        worker.is_file(),
        "marsh-exec not built at {}; build both runtime binaries for this Cargo target/profile \
         first",
        worker.display()
    );
    worker
}

/// Runs a test's asynchronous body over a fixture, with the one teardown order every
/// fixture-owning test uses.
///
/// The runtime and the fixture are built *outside* `block_on`, the body runs inside
/// [`std::panic::catch_unwind`], and the still-live runtime is then used to await the mux's
/// shutdown before the fixture's synchronous btrfs teardown. A saved panic is rethrown last, so a
/// failed assertion neither leaks a subvolume nor drops a mux from inside a runtime.
///
/// A macro rather than a function taking a closure: the body borrows the fixture the same
/// statement created, which no `FnOnce(&mut Fixture) -> impl Future` signature expresses.
///
/// ```ignore
/// mux_test!(fixture = Fixture::new("label"), {
///     let sandbox = common::main_sandbox(fixture).await;
/// });
/// ```
///
/// `local` selects a single-threaded runtime, on which a spawned task cannot run until the
/// awaiting task yields — which is what makes "observed while the job was still starting" a fact
/// rather than a race the test usually wins.
#[macro_export]
macro_rules! mux_test {
    ($fixture:ident = $init:expr, $body:block) => {
        $crate::mux_test!(@drive $crate::common::multi_thread_runtime(), $fixture = $init, $body)
    };
    (local $fixture:ident = $init:expr, $body:block) => {
        $crate::mux_test!(@drive $crate::common::current_thread_runtime(), $fixture = $init, $body)
    };
    (@drive $runtime:expr, $fixture:ident = $init:expr, $body:block) => {{
        let runtime = $runtime;
        // `mut` only for a body that finishes the mux itself; most do not.
        #[allow(unused_mut, reason = "only a body that reopens the session needs it")]
        let mut $fixture = {
            let _guard = runtime.enter();
            $init
        };
        let outcome = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async $body);
        }));
        $crate::common::shut_down(&runtime, &$fixture);
        drop($fixture);
        drop(runtime);
        if let Err(panic) = outcome {
            ::std::panic::resume_unwind(panic);
        }
    }};
}

/// A runtime with several worker threads: what a test that really overlaps jobs needs.
pub fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build the test runtime")
}

/// A runtime with exactly one thread.
pub fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build the test runtime")
}

/// Shuts down whatever mux the fixture still holds, on a runtime that is still alive.
///
/// The half of [`mux_test`] that has to reach the fixture's private mux, and the reason the
/// fixture's own `Drop` never has to: by the time it runs, the job tasks are joined and the
/// commands are dead.
pub fn shut_down(runtime: &tokio::runtime::Runtime, fixture: &Fixture) {
    if let Some(mux) = fixture.mux.as_ref() {
        let _ = runtime.block_on(mux.shutdown());
    }
}

/// Takes the session lease over `seed`/`root`, tolerating the instant an unrelated parallel test
/// child still carries the close-on-exec lock descriptor between fork and exec.
///
/// `fork` duplicates every descriptor, a `flock`ed one included, and the duplicate only goes away
/// at the following `exec`. A test that takes a session someone else has just released therefore
/// has to be willing to wait out that window rather than call it a live competitor.
pub fn acquire_executor(seed: &Path, root: &Path) -> MarshExecutor {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let layer = PersistenceLayer::new(seed.to_path_buf(), root.to_path_buf());
        match MarshExecutor::builder(layer).worker(executor()).build() {
            Ok(executor) => return executor,
            Err(ExecError::SessionBusy(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => panic!("build the executor: {error}"),
        }
    }
}

/// Reopens a released session over the same paths.
///
/// A *fresh* layer every time: a [`PersistenceLayer`] owns the session lease, so it is not `Clone`
/// and the one the previous mux held went away with it. Only the paths survive a restart, which is
/// exactly what a new marsh process would start from.
pub async fn reopen(persistence: &PersistenceLayer) -> Arc<ShellMux> {
    reopen_with(
        persistence,
        PurityCheckerBuilder::new().static_checks().build(),
    )
    .await
}

/// [`reopen`] with the purity checker the test chose.
#[allow(
    clippy::unused_async,
    reason = "a restart is part of an asynchronous test's sequence, and the mux it returns is only \
              usable inside one"
)]
pub async fn reopen_with(persistence: &PersistenceLayer, checker: PurityChecker) -> Arc<ShellMux> {
    let executor = acquire_executor(&persistence.seed, &persistence.root);
    ShellMux::new(
        executor,
        checker,
        brush_core::env::ShellEnvironment::new(),
        Arc::new(Mutex::new(RecordingFrontend::new(ROWS, COLS))),
    )
    .expect("open mux")
}

/// Shuts a reopened mux down and drops it, as [`Fixture::finish_mux`] does the fixture's own.
pub async fn close_mux(mux: Arc<ShellMux>) {
    mux.shutdown().await.expect("shut the mux down");
    assert_eq!(
        Arc::strong_count(&mux),
        1,
        "a clone of the mux outlived close_mux"
    );
    drop(mux);
}

/// The test suite's frontend: everything the mux delivered, kept until a test consumes it.
///
/// An observable frontend rather than a no-op adapter — a job's bytes only exist here, so a test
/// that wants them has to be the thing the mux delivered them to. Byte buffers are keyed by sandbox
/// uid, never by name, so a reused name never mixes two jobs' contents.
pub struct RecordingFrontend {
    /// The mux this recorder was bound to, empty before binding and after shutdown.
    mux: Weak<ShellMux>,
    /// The latest geometry: what it was built with, then whatever a resize reported.
    size: (u16, u16),
    /// The handle of every job opened while bound, by name.
    handles: HashMap<ShellId, Spawned>,
    /// The job table as the last [`FrontendEvent::Changed`] callback read it back.
    ///
    /// Read inside that callback and nowhere else, because `Changed` is the whole invalidation
    /// contract: a recorder that polled the mux when a test asked would answer correctly even for
    /// a session that never said its display was out of date.
    observed_jobs: Vec<JobView>,
    /// The selection the same callback read back.
    observed_current: Option<ShellId>,
    /// Which of `observed_jobs` reported a conclusion in flight when it did.
    observed_merging: HashSet<ShellId>,
    /// Terminal bytes not yet consumed, by sandbox uid.
    terminal: HashMap<String, Vec<u8>>,
    /// Instrumentation bytes not yet consumed, by sandbox uid.
    instrumentation: HashMap<String, Vec<u8>>,
    /// Every completion observed, in delivery order, by the sandbox uid it was delivered for.
    ///
    /// The uid rather than the name, for the same reason the byte buffers are: a name handed out
    /// again is a different sandbox, and one job's results must never answer for another's.
    reaped: Vec<(String, Reaped)>,
    /// Sandboxes whose streams are over.
    closed: HashSet<String>,
    /// Sandboxes whose work tree still existed when their end of stream arrived.
    ///
    /// Recorded rather than asserted: this runs on the mux's own pump task, where a panic is
    /// reported as that task failing rather than as this claim.
    closed_with_storage: HashSet<String>,
    /// The first stream failure per sandbox, as it was reported.
    errors: HashMap<String, String>,
    /// Wakes a test waiting for any of the above to change.
    ///
    /// Shared out by [`RecordingFrontend::signal`], so a waiter registers its interest before it
    /// looks and never holds this recorder's lock across an await.
    signal: Arc<Notify>,
}

/// What a mock frontend does *to* the mux.
///
/// Input and output are separate vocabularies: [`FrontendEvent`] stays the mux's own outbound
/// enum and nothing here is ever delivered to [`MarshFrontend::update`]. A session driven only
/// through these actions is a session in which every command took the path a real front-end's
/// would have.
pub enum FrontendAction<'a> {
    /// Open a named job at the seed root.
    Spawn {
        /// The job's name, which is also its principal.
        id: &'a ShellId,
    },
    /// Submit a command line to an open job.
    Start {
        /// The job to run it in.
        id: &'a ShellId,
        /// The command line, exactly as a user would have typed it.
        command: &'a str,
    },
    /// Write bytes to a job's terminal, as a keystroke would.
    Input {
        /// The job whose terminal receives them.
        id: &'a ShellId,
        /// The bytes, verbatim.
        bytes: &'a [u8],
    },
    /// Ask a job to close, gracefully or by force.
    Stop {
        /// The job to close.
        id: &'a ShellId,
        /// Whether to kill whatever is running rather than wait it out.
        force: bool,
    },
}

impl RecordingFrontend {
    /// Performs one frontend-initiated action through the binding this recorder was handed.
    ///
    /// The acting half of the mock. The binding is upgraded under a short guard that is released
    /// before the await, because a mux operation must never run while a callback is waiting for
    /// this recorder's lock; nothing here reenters the mux from inside [`Self::update`].
    ///
    /// # Errors
    ///
    /// [`MuxError::Exec`] when the recorder is not bound to a live mux — a detached binding is a
    /// harness failure, not a successful no-op — [`MuxError::NoSuchJob`] when
    /// [`FrontendAction::Input`] names a job the mux never published a handle for, and whatever
    /// the underlying mux operation reported otherwise.
    pub async fn dispatch(
        frontend: &Arc<Mutex<Self>>,
        action: FrontendAction<'_>,
    ) -> Result<(), MuxError> {
        let bound = {
            let recorder = frontend.lock().unwrap_or_else(PoisonError::into_inner);
            let bound = recorder.mux();
            drop(recorder);
            bound
        };
        let Some(mux) = bound else {
            return Err(MuxError::Exec(
                "the frontend is not bound to a live mux".to_string(),
            ));
        };
        match action {
            FrontendAction::Spawn { id } => {
                // The returned handle is dropped on purpose: the mock's usable handle is the one
                // `FrontendEvent::Opened` delivered, so a missing callback cannot be hidden by
                // this method's return value.
                let opened = mux.spawn("", Some(id.clone()), None).await?;
                drop(opened);
                Ok(())
            }
            FrontendAction::Start { id, command } => mux.start_in(id, command).await,
            FrontendAction::Input { id, bytes } => {
                let handle = {
                    let recorder = frontend.lock().unwrap_or_else(PoisonError::into_inner);
                    let handle = recorder.handle(id);
                    drop(recorder);
                    handle
                };
                let Some(handle) = handle else {
                    return Err(MuxError::NoSuchJob(id.clone()));
                };
                mux.write_input(&handle, bytes).await
            }
            FrontendAction::Stop { id, force } => mux.stop(id, force).await,
        }
    }

    /// The mux this recorder is bound to, or `None` before binding and after shutdown.
    pub fn mux(&self) -> Option<Arc<ShellMux>> {
        self.mux.upgrade()
    }

    /// The wakeup source, for a waiter that must register before it checks.
    pub fn signal(&self) -> Arc<Notify> {
        Arc::clone(&self.signal)
    }

    /// The handle the mux published for `id`, if one was.
    pub fn handle(&self, id: &ShellId) -> Option<Spawned> {
        self.handles.get(id).cloned()
    }

    /// The job table as the last `Changed` callback read it back, in creation order.
    pub fn observed_jobs(&self) -> &[JobView] {
        &self.observed_jobs
    }

    /// The selection that callback read back.
    pub fn observed_current(&self) -> Option<&ShellId> {
        self.observed_current.as_ref()
    }

    /// Whether `id` was merging when it did.
    pub fn observed_merging(&self, id: &ShellId) -> bool {
        self.observed_merging.contains(id)
    }

    /// Takes the terminal bytes recorded for `uid` so far, keeping the buffer for what follows.
    pub fn take_terminal(&mut self, uid: &str) -> Vec<u8> {
        self.terminal
            .get_mut(uid)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Takes the instrumentation bytes recorded for `uid` so far, keeping the buffer likewise.
    pub fn take_instrumentation(&mut self, uid: &str) -> Vec<u8> {
        self.instrumentation
            .get_mut(uid)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Every completion observed for the sandbox `uid`, oldest first.
    pub fn results(&self, uid: &str) -> Vec<&Reaped> {
        self.reaped
            .iter()
            .filter(|(observed, _)| observed == uid)
            .map(|(_, result)| result)
            .collect()
    }

    /// Every completion observed, in delivery order, paired with the sandbox uid it arrived for.
    ///
    /// The global stream rather than one job's slice: the mux concludes commands on a single
    /// queue, so this order *is* the order the authority saw them in, and a runner checking
    /// authorization has to replay exactly that sequence.
    pub fn reaped(&self) -> &[(String, Reaped)] {
        &self.reaped
    }

    /// Whether `uid`'s streams are over.
    pub fn is_closed(&self, uid: &str) -> bool {
        self.closed.contains(uid)
    }

    /// Whether `uid`'s work tree still existed when its streams were reported over.
    pub fn closed_with_storage(&self, uid: &str) -> bool {
        self.closed_with_storage.contains(uid)
    }

    /// The first stream failure reported for `uid`, if any.
    pub fn error(&self, uid: &str) -> Option<&str> {
        self.errors.get(uid).map(String::as_str)
    }

    /// The geometry the mux last reported.
    pub fn dimensions(&self) -> (u16, u16) {
        self.size
    }

    /// Rereads the table through the binding, as a frontend does when its display is invalidated.
    ///
    /// An absent mux leaves the last observation alone: a detached recorder has nothing to read,
    /// and erasing what it saw would lose the session a test is about to ask about.
    fn reread(&mut self) {
        let Some(mux) = self.mux.upgrade() else {
            return;
        };
        self.observed_jobs = mux.jobs();
        self.observed_current = mux.current_job().map(|view| view.id);
        self.observed_merging = self
            .observed_jobs
            .iter()
            .filter(|view| mux.is_merging(&view.id))
            .map(|view| view.id.clone())
            .collect();
        drop(mux);
    }
}

impl MarshFrontend for RecordingFrontend {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            mux: Weak::new(),
            size: (rows, cols),
            handles: HashMap::new(),
            observed_jobs: Vec::new(),
            observed_current: None,
            observed_merging: HashSet::new(),
            terminal: HashMap::new(),
            instrumentation: HashMap::new(),
            reaped: Vec::new(),
            closed: HashSet::new(),
            closed_with_storage: HashSet::new(),
            errors: HashMap::new(),
            signal: Arc::new(Notify::new()),
        }
    }

    fn size(&self) -> (u16, u16) {
        self.size
    }

    fn bind(&mut self, mux: Weak<ShellMux>) {
        let detached = mux.upgrade().is_none();
        self.mux = mux;
        if detached {
            // Live handles hold a pseudoterminal master open; the observations stay, because what
            // a recorder is for is being asked afterwards.
            self.handles.clear();
        }
        self.signal.notify_waiters();
    }

    fn update(&mut self, event: FrontendEvent<'_>) {
        match event {
            FrontendEvent::Opened(spawned) => {
                self.handles.insert(spawned.id.clone(), spawned.clone());
            }
            FrontendEvent::Terminal { shell, bytes } => self
                .terminal
                .entry(shell.uid.clone())
                .or_default()
                .extend_from_slice(bytes),
            FrontendEvent::Instrumentation { shell, bytes } => self
                .instrumentation
                .entry(shell.uid.clone())
                .or_default()
                .extend_from_slice(bytes),
            FrontendEvent::Reaped { shell, result } => {
                self.reaped.push((shell.uid.clone(), result.clone()));
            }
            FrontendEvent::Closed(shell) => {
                self.closed.insert(shell.uid.clone());
                if self
                    .mux
                    .upgrade()
                    .is_some_and(|mux| mux.persistence().work(&shell.uid).exists())
                {
                    self.closed_with_storage.insert(shell.uid.clone());
                }
                // This sandbox's handle only: a name handed out again is a different job, and the
                // live one under it outlives the closure of the one before it.
                if self
                    .handles
                    .get(&shell.id)
                    .is_some_and(|held| held.sandbox.uid == shell.uid)
                {
                    self.handles.remove(&shell.id);
                }
            }
            FrontendEvent::Resized { rows, cols } => self.size = (rows, cols),
            FrontendEvent::IoError { shell, error } => {
                self.errors
                    .entry(shell.uid.clone())
                    .or_insert_with(|| error.to_string());
            }
            FrontendEvent::Changed => self.reread(),
        }
        self.signal.notify_waiters();
    }
}

/// A seed subvolume holding the pooled paths and a repository, and the path to it.
///
/// Everything lands under `CARGO_TARGET_TMPDIR`, which is the btrfs mount the suite already
/// requires, so no test touches anything of the developer's. The scratch path is unique per test,
/// so two fixtures never share a state directory.
///
/// ```text
/// scratch/seed          btrfs subvolume: the seed, with its repository and seed commit
/// scratch/.marsh/seed/  created by PersistenceLayer::materialize
/// scratch/replay/       replay tree, outside the seed
/// ```
fn seeded_subvolume(label: &str) -> PathBuf {
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
    seed
}

/// A seeded session and the mux over it, cleaned up when it goes out of scope.
///
/// Cleanup on drop rather than at the end of each test: an assertion failure unwinds, and a leaked
/// subvolume under `CARGO_TARGET_TMPDIR` outlives the run that made it.
pub struct Fixture {
    /// The seed subvolume.
    seed: PathBuf,
    /// The state directory beside it.
    ///
    /// Paths rather than a [`PersistenceLayer`]: a layer carries the session lease and is not
    /// `Clone`, so the one the mux owns is the only one, and teardown has to outlive it.
    root: PathBuf,
    /// The mux, taken by [`Fixture::finish_mux`] before a test reopens one.
    mux: Option<Arc<ShellMux>>,
    /// The frontend that mux delivers to, retained so a test can read what it observed.
    ///
    /// Outlives [`Fixture::finish_mux`]: a recorder is what a test asks about the session that
    /// just ended.
    frontend: Arc<Mutex<RecordingFrontend>>,
}

impl Fixture {
    /// A seed subvolume holding the pooled paths, and a mux over it whose purity checker proves
    /// from syntax alone.
    pub fn new(label: &str) -> Self {
        Self::with_checker(label, PurityCheckerBuilder::new().static_checks().build())
    }

    /// A fixture whose mux uses `checker`.
    pub fn with_checker(label: &str, checker: PurityChecker) -> Self {
        Self::prepared(label, checker, |_| {})
    }

    /// A fixture whose persistent state `prepare` seeds, in the one window where that is safe.
    ///
    /// `prepare` runs after the executor took the session's exclusive lease and before the mux
    /// restores anything from it, so a seeded log is neither racing another owner nor written after
    /// the checker already read the file.
    pub fn prepared(
        label: &str,
        checker: PurityChecker,
        prepare: impl FnOnce(&PersistenceLayer),
    ) -> Self {
        let seed = seeded_subvolume(label);
        let root = PersistenceLayer::discover(&seed)
            .expect("discover the persistence layer")
            .root;
        let executor = acquire_executor(&seed, &root);
        prepare(executor.persistence());
        let frontend = Arc::new(Mutex::new(RecordingFrontend::new(ROWS, COLS)));
        let mux = ShellMux::new(
            executor,
            checker,
            brush_core::env::ShellEnvironment::new(),
            Arc::clone(&frontend),
        )
        .expect("open mux");
        Self {
            seed,
            root,
            mux: Some(mux),
            frontend,
        }
    }

    /// A fixture whose mux has already been shut down and released the session.
    ///
    /// The seed, its repository and the state directory exist and nobody owns them: what a test
    /// that drives the real CLI as a child process needs. A separate constructor because shutting a
    /// mux down is asynchronous and such a test has no runtime of its own.
    pub fn cold(label: &str) -> Self {
        let runtime = current_thread_runtime();
        let mut fixture = {
            let _guard = runtime.enter();
            Self::new(label)
        };
        if let Some(mux) = fixture.mux.take() {
            runtime.block_on(mux.shutdown()).expect("shut the mux down");
            drop(mux);
        }
        fixture
    }

    /// The mux. Panics once [`Fixture::finish_mux`] has run.
    pub fn mux(&self) -> &Arc<ShellMux> {
        self.mux
            .as_ref()
            .expect("the mux is gone: finish_mux already ran")
    }

    /// The frontend the mux delivers to.
    pub fn frontend(&self) -> &Arc<Mutex<RecordingFrontend>> {
        &self.frontend
    }

    /// The recorder, recovering a poisoned lock so one failed assertion inside a callback does not
    /// hide every later one.
    pub fn recorder(&self) -> MutexGuard<'_, RecordingFrontend> {
        self.frontend.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A fresh, unlocked view of the session's paths: the seed and everything marsh writes beside
    /// it.
    ///
    /// By value, because the layer the executor owns holds the lease and cannot be shared.
    pub fn persistence(&self) -> PersistenceLayer {
        PersistenceLayer::new(self.seed.clone(), self.root.clone())
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

    /// Shuts the mux down and drops it before a test reopens one.
    ///
    /// Nothing is flushed — there is no committer — but [`ShellMux::new`] sweeps `snap/`, so a
    /// second mux over a live one would reclaim its sandboxes' snapshots. Panics when another `Arc`
    /// clone is still alive, for the same reason.
    pub async fn finish_mux(&mut self) {
        if let Some(mux) = self.mux.take() {
            mux.shutdown().await.expect("shut the mux down");
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
        // Whatever is left. A mux still here was shut down by `drive` on the runtime that is only
        // now going away; one a test finished itself is already gone.
        drop(self.mux.take());
        remove_session(&self.seed, &self.root);
    }
}

/// A job named `name` over the seed-relative `dir`, and the sandbox it opened.
pub async fn sandbox(fixture: &Fixture, name: &str, dir: &str) -> Sandbox {
    fixture
        .mux()
        .spawn(dir, Some(ShellId::from(name)), None)
        .await
        .expect("open sandbox")
        .sandbox
}

/// The default sandbox every single-job test runs in: `main`, rooted at the seed root.
pub async fn main_sandbox(fixture: &Fixture) -> Sandbox {
    sandbox(fixture, MAIN, "").await
}

/// One sandbox per agent, named as its principal and rooted at the seed root.
///
/// Separate sandboxes are what makes the agents race: each holds its own snapshot of one shared
/// seed.
pub async fn agent_sandboxes(fixture: &Fixture, agents: usize) -> Vec<Sandbox> {
    let mut sandboxes = Vec::with_capacity(agents);
    for agent in 0..agents {
        sandboxes.push(sandbox(fixture, &principal_for(agent).to_string(), "").await);
    }
    sandboxes
}

/// Removes a session: its snapshots, the seed subvolume, and the scratch directory.
///
/// Takes the paths rather than the mux so a test can clean up *after* dropping the mux.
fn remove_session(seed: &Path, root: &Path) {
    let persistence = PersistenceLayer::new(seed.to_path_buf(), root.to_path_buf());
    if let Ok(entries) = std::fs::read_dir(persistence.snap()) {
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

/// The scratch directory [`seeded_subvolume`] put the seed and the state in.
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
        let output = Command::new(executor())
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
