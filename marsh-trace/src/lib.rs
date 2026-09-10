//! Pure git trace generation and policy validation: entropy in, granted operations out.
//!
//! A port of the validator fork's `git_policy_harness`, with the same byte decoder, the same
//! operation table, the same eligibility rules and the same grant-only replay boundary. Nothing
//! here touches git, the filesystem or a shell, which is what lets one implementation drive both
//! consumers:
//!
//! * the libFuzzer target in `fuzz/fuzz_targets/fuzz_git_policy.rs`, which explores generation and
//!   policy evaluation for panics and no-surprise violations, millions of inputs deep;
//! * the mux integration suite in `shellmux/tests/`, which executes the *granted* operations as
//!   real shell commands against a real repository, from its own seeds.
//!
//! The split is the fork's: the fuzzer decides what the policy grants, and a separate seeded
//! oracle replays those grants for real. A libFuzzer target that took a btrfs snapshot and forked a
//! traced shell per input would not be a fuzzer.
//!
//! Generation is constrained so the *filesystem* preconditions always hold independently of the
//! policy: a path is created only when it is absent, and edited, deleted, committed or read only
//! when it is present. Every path lives in the seed commit and never leaves `HEAD`, so pathspec
//! matching always succeeds and `checkout`/`stash` always have a source to restore from. Index
//! membership is tracked too, because `git rm` and a `git add` of an absent path drop the index
//! entry, and [`GeneratedOperation::Create`] is gated on it — so working-tree presence implies
//! trackedness, `stash`'s pathspec never misses, and `git clean` is provably a no-op on every
//! pooled path. Every mutation embeds its step index, so a write can never coincidentally
//! reproduce an earlier blob.

use rust_validator::{Action, Bump, Event, GitPolicy, PolicyDecision, Principal, Resource};

pub mod oracle;

pub use oracle::{Surprise, contended_events, no_surprise_violation};

/// Number of principals, `agent0 … agent{MAX_AGENTS-1}`.
pub const MAX_AGENTS: usize = 3;
/// Number of pooled paths, `src/file0.txt … src/file{MAX_FILES-1}.txt`.
pub const MAX_FILES: usize = 4;
/// Upper bound on a generated trace's length, and the inclusive top of the encoded step budget.
///
/// The first `int_in_range(0..=MAX_TRACE_LENGTH)` draw off an input decides how many candidates
/// that input is worth.
pub const MAX_TRACE_LENGTH: usize = 32;

/// Deterministic pseudo-random bytes (LCG), taken verbatim from the validator fork's fuzz harness
/// so generation is comparable across the two suites.
#[must_use]
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
#[must_use]
pub fn path_for(file: usize) -> String {
    format!("src/file{file}.txt")
}

/// The principal name for an agent index.
#[must_use]
pub fn principal_for(agent: usize) -> Principal {
    Principal::from(format!("agent{agent}"))
}

/// The capability an operation requests, exactly.
///
/// Resources are seed-relative, because that is what every path the mux reports is.
#[must_use]
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
///
/// Indices rather than rendered strings: how an operation is *performed* is the executor's
/// business, and this crate has no executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Agent index in `0..MAX_AGENTS`; principal `agent{agent}`.
    pub agent: usize,
    /// Operation to perform.
    pub operation: GeneratedOperation,
    /// Pooled path index in `0..MAX_FILES`; path `src/file{file}.txt`.
    pub file: usize,
    /// Generation step, also the commit-message suffix.
    pub step: usize,
}

impl Candidate {
    /// The capability event this candidate must produce.
    #[must_use]
    pub fn event(&self) -> Event {
        expected_event(self.agent, self.operation, self.file, self.step)
    }

    /// The principal running it.
    #[must_use]
    pub fn principal(&self) -> Principal {
        principal_for(self.agent)
    }
}

/// Whether the policy admits `candidate` after `history`.
///
/// A fresh arena and policy per call: `GitPolicy` borrows its arena and is `!Send`, and compiling
/// the rule set costs microseconds.
#[must_use]
pub fn grants(history: &[Event], candidate: &Event) -> bool {
    let arena = Bump::new();
    matches!(
        GitPolicy::new(&arena).decide(history, candidate),
        PolicyDecision::Grant
    )
}

/// Counters describing one generated and validated trace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceSummary {
    /// Candidates the policy admitted.
    pub granted: usize,
    /// Candidates the policy refused, which were never exported and never executed.
    pub denied: usize,
    /// Admitted candidates that were `git commit`.
    pub commits: usize,
}

/// A generated trace reduced to the operations the policy granted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatedTrace {
    /// Granted operations in generation order; replaying them in order is the property under test.
    pub operations: Vec<Candidate>,
    /// The granted events in order — the same values fed to the policy, for trace-level checks
    /// such as [`no_surprise_violation`].
    pub history: Vec<Event>,
    /// Counters for the whole trace, the refused candidates included.
    pub summary: TraceSummary,
}

/// Generates one trace from `data` and reduces it to the operations the policy granted.
///
/// Empty or exhausted input yields a [`ValidatedTrace::default`]. A refused candidate advances the
/// counters only: it is exported nowhere and leaves both the history and the working-tree model
/// untouched, which is what keeps every exported operation executable.
#[must_use]
pub fn validate_trace(data: &[u8]) -> ValidatedTrace {
    let mut generator = SeqGenerator::new(data);
    let arena = Bump::new();
    let mut policy = GitPolicy::new(&arena);
    let budget = generator.step_budget();

    let mut trace = ValidatedTrace::default();
    for _ in 0..budget {
        let Some(candidate) = generator.next_candidate() else {
            break;
        };
        let event = candidate.event();
        match policy.decide(&trace.history, &event) {
            PolicyDecision::Grant => {
                generator.record_grant(&candidate);
                trace.summary.granted += 1;
                if candidate.operation == GeneratedOperation::Commit {
                    trace.summary.commits += 1;
                }
                trace.operations.push(candidate);
                trace.history.push(event);
            }
            PolicyDecision::Deny { .. } => trace.summary.denied += 1,
        }
    }
    trace
}

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
    #[must_use]
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
    /// a committing batch, would make an executing suite's trace a different trace from the
    /// reference's. Decoding a copy of the remaining input answers the question and leaves the
    /// real cursor exactly where it was.
    #[must_use]
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
    pub const fn record_grant(&mut self, candidate: &Candidate) {
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
    /// What an executing runner compares against the real repository at a settled boundary, so a
    /// model that drifted from disk fails the harness instead of generating impossible commands.
    #[must_use]
    pub const fn file_state(&self, file: usize) -> (bool, bool) {
        (self.exists[file], self.tracked[file])
    }

    /// Pooled path indices, ascending, on which `operation` can execute right now: the filled
    /// prefix of the returned array, and how long that prefix is.
    const fn eligible(&self, operation: GeneratedOperation) -> ([usize; MAX_FILES], usize) {
        let mut files = [0; MAX_FILES];
        let mut used = 0;
        let mut file = 0;
        while file < MAX_FILES {
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
            file += 1;
        }
        (files, used)
    }
}
