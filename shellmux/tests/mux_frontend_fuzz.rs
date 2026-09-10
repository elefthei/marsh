//! Mock front-end proof: the validator fork's generated git traces, executed as real shell
//! commands in real jobs, driven exclusively through frontend actions.
//!
//! Nothing here calls [`shellmux::ShellMux::run_cmd`] or reaches the executor. A session opens
//! three named jobs through [`FrontendAction::Spawn`], submits every workload command through
//! [`FrontendAction::Start`], releases gated batches through [`FrontendAction::Input`] and closes
//! through [`FrontendAction::Stop`]; everything it learns arrives as a `FrontendEvent` callback on
//! the recorder. That is what makes an authorization answer here an answer about the path a real
//! front-end drives, rather than about a batch API no user reaches.
//!
//! Generation is the reference's, unchanged: the same byte decoder, the same eligibility table and
//! the same grant-only admission boundary, so a command is submitted only when the policy admitted
//! it *and* its filesystem precondition holds. A denial that reaches the mux is therefore always
//! the mux's own decision about a command that could have run, and an execution failure is always
//! a defect.
//!
//! Run with a pinned seed to reproduce a failure exactly:
//! `MARSH_FUZZ_SEED=0xdecafbad cargo test -p shellmux --test mux_frontend_fuzz -- --nocapture`.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::collections::HashSet;
use std::fmt::Write as _;
use std::time::Duration;

use common::{
    Candidate, Fixture, FrontendAction, GeneratedOperation, MAX_AGENTS, MAX_FILES,
    RecordingFrontend, Replayer, SEED_VARIABLE, SeqGenerator, assert_same_seed, entropy,
    git_output, oracle, path_for, principal_for, random_seed,
};
use rust_validator::{Bump, GitPolicy, PolicyDecision};
use shellmux::{CmdOutcome, Event, Reaped, ShellId};

/// How long one control action, gate wait or batch conclusion may take before the claim is
/// declared unmet.
///
/// Absolute per wait: a job that keeps producing output must not be able to postpone the failure.
const TIMEOUT: Duration = Duration::from_secs(30);

/// One job per principal, as the reference's agent pool.
const AGENTS: usize = MAX_AGENTS;

/// Fuzzer input bytes per corpus trace, exactly as the reference exporter chunks them.
const BYTES_PER_TRACE: usize = 256;
/// Seed of the deterministic byte stream the fixed corpus is chunked out of.
const DETERMINISTIC_SEED: u64 = 0x5eed_cafe_f00d_beef;
/// Fixed corpus traces.
const SEEDED_TRACE_COUNT: usize = 32;
/// Random corpus traces added to every run.
const RANDOM_TRACE_COUNT: usize = 16;

/// Commands the fixed corpus must commit when it is run one at a time.
///
/// The reference exporter's `seededSummary.granted`. Ordered execution admits exactly the
/// reference's grants, so this is an equality rather than a lower bound.
const SEEDED_ORDERED_COMMITTED: usize = 258;
/// Candidates the policy must filter over that corpus — the exporter's `seededSummary.denied`.
const SEEDED_ORDERED_FILTERED: usize = 191;
/// Git commits the fixed corpus contains: none, and a run that grows one has drifted.
const SEEDED_ORDERED_GIT_COMMITS: usize = 0;

/// The line that releases one gated job.
const GO: &[u8] = b"go\n";

/// The gate a parallel batch member waits at, so every member really is in flight against the one
/// seed state its candidate was generated against.
///
/// The readiness marker goes to fd 3 — the instrumentation stream, which no terminal reader
/// competes for — and the release is one line on the job's own terminal. No sleep and no gate
/// file: a sleep is a guess, and a file inside the seed would be a capability the trace never
/// asked for.
fn gated(agent: usize, step: usize, command: &str) -> String {
    format!(
        "printf 'ready %s %s\\n' {agent} {step} >&3; IFS= read -r __marsh_fuzz_gate && {command}"
    )
}

/// The bytes a gated job writes when it has reached its gate.
fn marker(agent: usize, step: usize) -> Vec<u8> {
    format!("ready {agent} {step}\n").into_bytes()
}

/// The job name — and therefore the principal — for an agent index.
fn job_id(agent: usize) -> ShellId {
    ShellId::from(principal_for(agent).to_string())
}

/// How a trace's commands are submitted.
#[derive(Clone, Copy)]
enum RunMode {
    /// One command at a time, ungated: the reference's own serial replay.
    Ordered,
    /// Up to one command per principal in flight at once, each held at a gate until every member
    /// of its batch has started.
    Parallel,
}

impl RunMode {
    /// The name a report prints.
    const fn name(self) -> &'static str {
        match self {
            Self::Ordered => "ordered",
            Self::Parallel => "parallel",
        }
    }

    /// Whether commands are wrapped in the readiness gate.
    const fn gated(self) -> bool {
        matches!(self, Self::Parallel)
    }

    /// How many commands one batch may admit.
    const fn width(self) -> usize {
        match self {
            Self::Ordered => 1,
            Self::Parallel => AGENTS,
        }
    }
}

/// When a batch's gated members are let go.
#[derive(Clone, Copy)]
enum Release {
    /// Every member, in candidate order, before any of them has concluded: what a fuzz batch does.
    Together,
    /// One member at a time, each concluded and settled before the next is released: what a
    /// deterministic handoff regression needs.
    Sequential,
}

/// What one trace's commands amounted to.
#[derive(Default)]
struct RunSummary {
    /// Commands the mux merged into the seed.
    committed: usize,
    /// Commands the mux refused on policy grounds.
    denied: usize,
    /// Candidates the policy filtered before any command was submitted.
    filtered: usize,
    /// Commands whose snapshot another principal had already moved past.
    stale: usize,
    /// Committed commands that were `git commit`.
    git_commits: usize,
    /// Events acting on a resource another principal held an outstanding view of.
    contended: usize,
    /// Batches observed with two or more members simultaneously running at their gates.
    overlapping_batches: usize,
}

impl RunSummary {
    /// Folds `other` into this total.
    fn absorb(&mut self, other: &Self) {
        self.committed += other.committed;
        self.denied += other.denied;
        self.filtered += other.filtered;
        self.stale += other.stale;
        self.git_commits += other.git_commits;
        self.contended += other.contended;
        self.overlapping_batches += other.overlapping_batches;
    }

    /// One line for the run report.
    fn line(&self) -> String {
        format!(
            "{} committed, {} denied, {} filtered, {} stale, {} git commits, {} contended, \
             {} overlapping batches",
            self.committed,
            self.denied,
            self.filtered,
            self.stale,
            self.git_commits,
            self.contended,
            self.overlapping_batches
        )
    }
}

/// One candidate that will be submitted, with everything the runner needs to check it.
struct Admitted {
    /// The generated operation.
    candidate: Candidate,
    /// The capability its command must translate to, exactly.
    event: Event,
    /// The command the reference renderer produced, which is what a replay re-executes.
    command: String,
    /// What was actually started: `command`, or `command` behind the batch gate.
    submitted: String,
    /// The sandbox uid its completion arrives under.
    uid: String,
}

/// Everything a failure report needs that is not live session state.
struct TraceContext {
    /// `seed/7`, `random/3`, or a scenario name.
    label: String,
    /// How the trace was submitted.
    mode: RunMode,
    /// The exact bytes generation was driven from.
    input: Vec<u8>,
    /// The `MARSH_FUZZ_SEED` value that regenerates `input`.
    seed: String,
}

/// Whether the reference policy admits `candidate` after `history`.
fn policy_grants(history: &[Event], candidate: &Event) -> bool {
    let arena = Bump::new();
    matches!(
        GitPolicy::new(&arena).decide(history, candidate),
        PolicyDecision::Grant
    )
}

/// The capabilities the policy would refuse out of `requested` after `history`.
///
/// The authority's own scan: an intermediate grant is appended while the request set is walked, so
/// a command's second capability is judged against its first, and the whole tentative prefix is
/// discarded afterwards because a refused command records nothing.
fn policy_denials(history: &[Event], requested: &[Event]) -> Vec<Event> {
    let arena = Bump::new();
    let mut policy = GitPolicy::new(&arena);
    let mut tentative = history.to_vec();
    let mut denied = Vec::new();
    for event in requested {
        match policy.decide(&tentative, event) {
            PolicyDecision::Grant => tentative.push(event.clone()),
            PolicyDecision::Deny { .. } => denied.push(event.clone()),
        }
    }
    denied
}

/// The reference's own generate-and-filter loop: no mux, no filesystem, no jobs.
///
/// This is the candidate stream and the grant decisions an executing run has to reproduce, and the
/// half of the fidelity claim that costs nothing to check.
fn reference_trace(bytes: &[u8]) -> (Vec<Candidate>, usize) {
    let mut generator = SeqGenerator::new(bytes);
    let budget = generator.step_budget();
    let mut granted = Vec::new();
    let mut history = Vec::new();
    let mut filtered = 0;
    for _ in 0..budget {
        let Some(candidate) = generator.next_candidate() else {
            break;
        };
        let event = candidate.event();
        if policy_grants(&history, &event) {
            generator.record_grant(&candidate);
            history.push(event);
            granted.push(candidate);
        } else {
            filtered += 1;
        }
    }
    (granted, filtered)
}

/// Waits until `ready` accepts the recorder's state; `false` once the deadline passes.
///
/// The notification is registered *before* the check and awaited with the recorder's lock
/// released, so a change landing between the two is a pending wakeup rather than a lost one. The
/// predicate takes the recorder mutably because draining a stream buffer is part of what several
/// waits are looking for.
async fn wait_until(
    fixture: &Fixture,
    mut ready: impl FnMut(&mut RecordingFrontend) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let signal = fixture.recorder().signal();
        let notified = signal.notified();
        let settled = {
            let mut recorder = fixture.recorder();
            let settled = ready(&mut recorder);
            drop(recorder);
            settled
        };
        if settled {
            return true;
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return false;
        }
    }
}

/// Whether `haystack` holds `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The batch member a completion belongs to.
fn member_for<'batch>(batch: &'batch [Admitted], uid: &str) -> &'batch Admitted {
    batch
        .iter()
        .find(|admitted| admitted.uid == uid)
        .unwrap_or_else(|| panic!("a completion for {uid} outside the batch reached settlement"))
}

/// Renders working-tree presence for a report.
const fn presence(exists: bool) -> &'static str {
    if exists { "present" } else { "absent" }
}

/// Renders index membership for a report.
const fn tracking(tracked: bool) -> &'static str {
    if tracked { "tracked" } else { "untracked" }
}

/// One mocked session: three jobs over one seed, and everything the harness knows about them.
struct Session<'fixture> {
    /// The seed, the mux and the recorder.
    fixture: &'fixture Fixture,
    /// What a failure report prints about the trace being run.
    context: TraceContext,
    /// The sandbox uid of each agent's job, by agent index.
    uids: Vec<String>,
    /// The serial ground truth every committed command is re-executed into.
    replayer: Replayer,
    /// The committed capability stream, accumulated from the global completion order.
    history: Vec<Event>,
    /// The sequence number the next commit must take.
    next_seq: u64,
    /// Every sequence number a commit has taken, so a stale report can be checked against one.
    merged: HashSet<u64>,
    /// Completions consumed from the recorder's global stream.
    reaped: usize,
    /// Commands submitted through [`FrontendAction::Start`].
    starts: usize,
    /// Batches run so far, for the report.
    batch: usize,
    /// The current batch, rendered.
    current: Vec<String>,
    /// The pool model as it stood when the current batch was generated.
    pools: String,
    /// The completions observed for the current batch, in delivery order.
    observed: Vec<String>,
    /// Terminal and instrumentation bytes the current batch's jobs produced.
    diagnostics: Vec<(String, Vec<u8>, Vec<u8>)>,
    /// What the trace amounted to.
    summary: RunSummary,
}

impl<'fixture> Session<'fixture> {
    /// Opens `agent0 … agent{AGENTS-1}` through the mock and reads their handles back.
    ///
    /// The uid comes from the `Opened` callback rather than from `spawn`'s return value: the mock
    /// is only usable if the mux really told its frontend the job exists.
    async fn open(fixture: &'fixture Fixture, context: TraceContext) -> Self {
        let mut uids = Vec::with_capacity(AGENTS);
        for agent in 0..AGENTS {
            let id = job_id(agent);
            RecordingFrontend::dispatch(fixture.frontend(), FrontendAction::Spawn { id: &id })
                .await
                .unwrap_or_else(|error| panic!("opening {id}: {error}"));
            let handle = fixture
                .recorder()
                .handle(&id)
                .unwrap_or_else(|| panic!("the mux never published a handle for {id}"));
            uids.push(handle.sandbox.uid);
        }
        Self {
            fixture,
            context,
            uids,
            // Beside the seed, never inside it: a replay tree in the seed would be snapshotted,
            // diffed and compared against itself.
            replayer: Replayer::new(fixture.scratch().join("replay")),
            history: Vec::new(),
            next_seq: 1,
            merged: HashSet::new(),
            reaped: 0,
            starts: 0,
            batch: 0,
            current: Vec::new(),
            pools: String::new(),
            observed: Vec::new(),
            diagnostics: Vec::new(),
            summary: RunSummary::default(),
        }
    }

    /// Everything a failure needs to be reproduced and understood.
    fn report(&self, what: &str) -> String {
        let mut text = String::new();
        let _ = writeln!(text, "{what}");
        let _ = writeln!(
            text,
            "  source {} ({}), batch {}",
            self.context.label,
            self.context.mode.name(),
            self.batch
        );
        let _ = writeln!(text, "  input  {}", hex::encode(&self.context.input));
        let _ = writeln!(text, "  pools  {}", self.pools);
        for member in &self.current {
            let _ = writeln!(text, "  member {member}");
        }
        let _ = writeln!(text, "  completions {:?}", self.observed);
        for (uid, terminal, instrumentation) in &self.diagnostics {
            let _ = writeln!(
                text,
                "  {uid} terminal {:?} instrumentation {:?}",
                String::from_utf8_lossy(terminal),
                String::from_utf8_lossy(instrumentation)
            );
        }
        let _ = writeln!(
            text,
            "  reproduce: MARSH_FUZZ_SEED={} cargo test -p shellmux --test mux_frontend_fuzz \
             -- --nocapture",
            self.context.seed
        );
        let _ = write!(
            text,
            "  a seed reproduces the entropy; native completion scheduling may still differ, so \
             the drawn actions and the completion order above are part of the report"
        );
        text
    }

    /// Fails the harness with the full report.
    fn fail(&self, what: &str) -> ! {
        panic!("{}", self.report(what));
    }

    /// Asserts the generator's pool model still describes the real repository.
    ///
    /// One `git ls-files` for index membership and one `exists` per pooled path for the working
    /// tree. `src/.keep` is never generated against and is ignored here for the same reason. A
    /// mismatch fails the harness: repairing the model from disk would hide exactly the defect
    /// this suite exists to find.
    fn assert_pools(&mut self, generator: &SeqGenerator<'_>) {
        let listed = git_output(self.fixture.seed_root(), &["ls-files", "--", "src"]);
        let indexed: HashSet<&str> = listed.lines().collect();
        let mut rendered = String::new();
        for file in 0..MAX_FILES {
            let (exists, tracked) = generator.file_state(file);
            let _ = write!(
                rendered,
                "{} {}/{} ",
                path_for(file),
                presence(exists),
                tracking(tracked)
            );
        }
        self.pools = rendered.trim_end().to_string();

        for file in 0..MAX_FILES {
            let path = path_for(file);
            let (exists, tracked) = generator.file_state(file);
            let on_disk = self.fixture.seed(&path).exists();
            let in_index = indexed.contains(path.as_str());
            if exists != on_disk {
                self.fail(&format!(
                    "the model says {path} is {}, the working tree says {}",
                    presence(exists),
                    presence(on_disk)
                ));
            }
            if tracked != in_index {
                self.fail(&format!(
                    "the model says {path} is {}, the index says {}",
                    tracking(tracked),
                    tracking(in_index)
                ));
            }
            if exists && !tracked {
                self.fail(&format!(
                    "{path} is present and untracked; the reference invariant is that presence \
                     implies trackedness"
                ));
            }
        }
    }

    /// Builds one submittable member from a candidate.
    fn admit(&self, candidate: Candidate) -> Admitted {
        let command = candidate.command();
        let submitted = if self.context.mode.gated() {
            gated(candidate.agent, candidate.step, &command)
        } else {
            command.clone()
        };
        Admitted {
            event: candidate.event(),
            uid: self.uids[candidate.agent].clone(),
            candidate,
            command,
            submitted,
        }
    }

    /// Submits one member through the mock.
    async fn start(&self, admitted: &Admitted) {
        let id = job_id(admitted.candidate.agent);
        if let Err(error) = RecordingFrontend::dispatch(
            self.fixture.frontend(),
            FrontendAction::Start {
                id: &id,
                command: &admitted.submitted,
            },
        )
        .await
        {
            self.fail(&format!(
                "starting {:?} in {id}: {error}",
                admitted.submitted
            ));
        }
    }

    /// Waits for every member of a gated batch to reach its gate, then proves they are all running
    /// at once.
    ///
    /// Markers accumulate across arbitrary chunk boundaries, because instrumentation is a byte
    /// stream and a marker may arrive split. The running check reads the recorder's own
    /// `Changed`-observed table: a job that became busy without the mux saying so is a job a real
    /// front-end would still be drawing as idle.
    async fn await_gates(&mut self, batch: &[Admitted]) {
        let wanted: Vec<(String, Vec<u8>)> = batch
            .iter()
            .map(|admitted| {
                (
                    admitted.uid.clone(),
                    marker(admitted.candidate.agent, admitted.candidate.step),
                )
            })
            .collect();
        let mut seen: Vec<Vec<u8>> = vec![Vec::new(); wanted.len()];
        let fixture = self.fixture;
        let reached = wait_until(fixture, |recorder| {
            let mut ready = true;
            for (index, (uid, want)) in wanted.iter().enumerate() {
                seen[index].extend_from_slice(&recorder.take_instrumentation(uid));
                ready &= contains(&seen[index], want);
            }
            ready
        })
        .await;
        for (index, (uid, _)) in wanted.iter().enumerate() {
            let bytes = std::mem::take(&mut seen[index]);
            self.record_instrumentation(uid, &bytes);
        }
        if !reached {
            self.fail("a gated batch member never reported ready");
        }

        let ids: Vec<ShellId> = batch
            .iter()
            .map(|admitted| job_id(admitted.candidate.agent))
            .collect();
        let recorder = self.fixture.recorder();
        let all_running = ids.iter().all(|id| {
            recorder
                .observed_jobs()
                .iter()
                .any(|view| view.id == *id && view.running.is_some())
        });
        drop(recorder);
        if !all_running {
            self.fail(
                "a batch member was at its gate but the observed table did not say it was running",
            );
        }
        if batch.len() >= 2 {
            self.summary.overlapping_batches += 1;
        }
    }

    /// Releases one gated job.
    async fn release(&self, admitted: &Admitted) {
        let id = job_id(admitted.candidate.agent);
        if let Err(error) = RecordingFrontend::dispatch(
            self.fixture.frontend(),
            FrontendAction::Input { id: &id, bytes: GO },
        )
        .await
        {
            self.fail(&format!("releasing {id}: {error}"));
        }
    }

    /// Awaits exactly one completion per `expected` uid, in the recorder's global order.
    ///
    /// The global stream rather than `wait_for_job`: the mux concludes on one queue and delivers
    /// `Reaped` before the job goes idle, so this order *is* the order the authority saw. A
    /// missing, duplicated or foreign completion fails here rather than being papered over by a
    /// handle's return value.
    async fn collect(&mut self, expected: &[String]) -> Vec<(String, Reaped)> {
        let start = self.reaped;
        let target = start + expected.len();
        let fixture = self.fixture;
        if !wait_until(fixture, |recorder| recorder.reaped().len() >= target).await {
            self.fail("a submitted command never reported a completion");
        }
        let recorder = fixture.recorder();
        let delivered = recorder.reaped().len();
        let taken: Vec<(String, Reaped)> = recorder.reaped()[start..target].to_vec();
        drop(recorder);
        if delivered > target {
            self.fail(&format!(
                "{delivered} completions were delivered and {target} commands were submitted"
            ));
        }
        let mut outstanding: Vec<&String> = expected.iter().collect();
        for (uid, _) in &taken {
            let Some(index) = outstanding.iter().position(|held| *held == uid) else {
                self.fail(&format!(
                    "a completion arrived for {uid}, which this batch did not submit for"
                ));
            };
            outstanding.remove(index);
        }
        self.reaped = target;
        for (uid, reaped) in &taken {
            self.observed
                .push(format!("{uid} exit {}", reaped.exit_code));
        }
        taken
    }

    /// Applies one completion to the model, the history and the replay tree.
    fn settle(&mut self, generator: &mut SeqGenerator<'_>, admitted: &Admitted, reaped: &Reaped) {
        let outcome = match reaped.outcome.as_ref() {
            Ok(outcome) => outcome,
            Err(error) => self.fail(&format!(
                "{:?} concluded with a mux failure: {error}",
                admitted.command
            )),
        };
        match outcome {
            CmdOutcome::Committed {
                seq,
                exit_code,
                granted,
                ..
            } => self.settle_commit(generator, admitted, *seq, *exit_code, granted),
            CmdOutcome::DeniedCaps {
                exit_code,
                requested,
                denials,
                ..
            } => {
                if *exit_code != 0 {
                    self.fail(&format!(
                        "{:?} was refused after failing with exit {exit_code}; a denial is about a \
                         command that ran",
                        admitted.command
                    ));
                }
                self.expect_request(admitted, requested);
                let expected = policy_denials(&self.history, requested);
                if expected.is_empty() {
                    self.fail(&format!(
                        "the mux refused {:?}, which the reference policy would grant",
                        admitted.command
                    ));
                }
                let observed: Vec<Event> =
                    denials.iter().map(|denial| denial.event.clone()).collect();
                if observed != expected {
                    self.fail(&format!(
                        "the refused capabilities are {observed:?}, the policy refuses {expected:?}"
                    ));
                }
                self.summary.denied += 1;
            }
            CmdOutcome::StaleSnapshot {
                requested, stale, ..
            } => {
                if !self.context.mode.gated() {
                    self.fail(&format!(
                        "{:?} lost a race in an ordered run, where nothing else was in flight",
                        admitted.command
                    ));
                }
                self.expect_request(admitted, requested);
                if stale.is_empty() {
                    self.fail(&format!(
                        "{:?} was called stale without naming a path that moved on",
                        admitted.command
                    ));
                }
                for path in stale {
                    if !self.merged.contains(&path.merged_seq) {
                        self.fail(&format!(
                            "{:?} lost {} to transaction {}, which never committed here",
                            admitted.command, path.path, path.merged_seq
                        ));
                    }
                }
                self.summary.stale += 1;
            }
            other => self.fail(&format!(
                "{:?} ended as {other:?}; every submitted command is executable in the snapshot it \
                 started from",
                admitted.command
            )),
        }
    }

    /// The committed half of [`Self::settle`].
    fn settle_commit(
        &mut self,
        generator: &mut SeqGenerator<'_>,
        admitted: &Admitted,
        seq: u64,
        exit_code: i32,
        granted: &[Event],
    ) {
        if exit_code != 0 {
            self.fail(&format!(
                "{:?} committed with exit {exit_code}",
                admitted.command
            ));
        }
        if granted != [admitted.event.clone()] {
            self.fail(&format!(
                "{:?} granted {granted:?}, the command means {:?}; a gate must add no capability",
                admitted.command, admitted.event
            ));
        }
        if !policy_grants(&self.history, &admitted.event) {
            self.fail(&format!(
                "the mux committed {:?}, which the reference policy would refuse",
                admitted.command
            ));
        }
        if seq != self.next_seq {
            self.fail(&format!(
                "{:?} took sequence {seq}, expected {}",
                admitted.command, self.next_seq
            ));
        }
        self.next_seq += 1;
        self.merged.insert(seq);
        self.history.push(admitted.event.clone());
        generator.record_grant(&admitted.candidate);
        // The ungated command: the gate is the harness's, and a serial ground truth that replayed
        // it would be comparing the seed against a different program.
        self.replayer
            .apply(&admitted.candidate.principal(), &admitted.command);
        self.summary.committed += 1;
        if admitted.candidate.operation == GeneratedOperation::Commit {
            self.summary.git_commits += 1;
        }
    }

    /// Asserts a refused or lost command still requested exactly what its command line meant.
    fn expect_request(&self, admitted: &Admitted, requested: &[Event]) {
        if requested != [admitted.event.clone()] {
            self.fail(&format!(
                "{:?} requested {requested:?}, the command means {:?}",
                admitted.command, admitted.event
            ));
        }
    }

    /// Runs one batch end to end: start every member, gate them, release them, settle them.
    async fn run_batch(
        &mut self,
        generator: &mut SeqGenerator<'_>,
        batch: &[Admitted],
        release: Release,
    ) {
        self.batch += 1;
        self.current = batch
            .iter()
            .map(|admitted| {
                format!(
                    "{} step {} {:?} -> {:?}",
                    admitted.candidate.principal(),
                    admitted.candidate.step,
                    admitted.submitted,
                    admitted.event
                )
            })
            .collect();
        self.observed.clear();
        self.diagnostics.clear();

        // Every member starts before any is released: that is what makes a batch share one settled
        // seed state rather than a sequence of them.
        for admitted in batch {
            self.start(admitted).await;
            self.starts += 1;
        }
        if self.context.mode.gated() {
            self.await_gates(batch).await;
        }

        match release {
            Release::Together => {
                if self.context.mode.gated() {
                    for admitted in batch {
                        self.release(admitted).await;
                    }
                }
                let expected: Vec<String> =
                    batch.iter().map(|admitted| admitted.uid.clone()).collect();
                for (uid, reaped) in self.collect(&expected).await {
                    self.settle(generator, member_for(batch, &uid), &reaped);
                }
            }
            Release::Sequential => {
                for admitted in batch {
                    if self.context.mode.gated() {
                        self.release(admitted).await;
                    }
                    let expected = vec![admitted.uid.clone()];
                    for (uid, reaped) in self.collect(&expected).await {
                        self.settle(generator, member_for(batch, &uid), &reaped);
                    }
                }
            }
        }

        self.await_idle(batch).await;
        self.drain(batch);
        self.assert_settled();
    }

    /// Waits until every batch job is neither starting, running nor merging.
    async fn await_idle(&self, batch: &[Admitted]) {
        let ids: Vec<ShellId> = batch
            .iter()
            .map(|admitted| job_id(admitted.candidate.agent))
            .collect();
        let fixture = self.fixture;
        let settled = wait_until(fixture, |recorder| {
            ids.iter().all(|id| {
                !recorder.observed_merging(id)
                    && recorder
                        .observed_jobs()
                        .iter()
                        .any(|view| view.id == *id && !view.starting && view.running.is_none())
            })
        })
        .await;
        if !settled {
            self.fail("a batch job never returned to idle");
        }
    }

    /// Takes whatever the batch's jobs still hold, keeping it for this batch's report only.
    fn drain(&mut self, batch: &[Admitted]) {
        let mut recorder = self.fixture.recorder();
        let taken: Vec<(String, Vec<u8>, Vec<u8>)> = batch
            .iter()
            .map(|admitted| {
                (
                    admitted.uid.clone(),
                    recorder.take_terminal(&admitted.uid),
                    recorder.take_instrumentation(&admitted.uid),
                )
            })
            .collect();
        drop(recorder);
        for (uid, terminal, instrumentation) in taken {
            self.record_terminal(&uid, &terminal);
            self.record_instrumentation(&uid, &instrumentation);
        }
    }

    /// Files terminal bytes under `uid` for the current batch's report.
    fn record_terminal(&mut self, uid: &str, bytes: &[u8]) {
        self.slot(uid).1.extend_from_slice(bytes);
    }

    /// Files instrumentation bytes under `uid` for the current batch's report.
    fn record_instrumentation(&mut self, uid: &str, bytes: &[u8]) {
        self.slot(uid).2.extend_from_slice(bytes);
    }

    /// The diagnostics slot for `uid`, created on first use.
    fn slot(&mut self, uid: &str) -> &mut (String, Vec<u8>, Vec<u8>) {
        let existing = self.diagnostics.iter().position(|(held, _, _)| held == uid);
        let index = if let Some(index) = existing {
            index
        } else {
            self.diagnostics
                .push((uid.to_string(), Vec::new(), Vec::new()));
            self.diagnostics.len() - 1
        };
        &mut self.diagnostics[index]
    }

    /// Asserts the authority and the seed agree with what the harness recorded.
    ///
    /// Only commits are replayed, in the order the completions arrived: this is what says rejected
    /// work cannot leak into the seed even when another job committed alongside it.
    fn assert_settled(&self) {
        let observed = self.fixture.mux().history();
        if observed != self.history {
            self.fail(&format!(
                "the authority holds {observed:?}, the harness recorded {:?}",
                self.history
            ));
        }
        assert_same_seed(
            self.fixture.seed_root(),
            self.replayer.dir(),
            &format!(
                "{} ({}) batch {}",
                self.context.label,
                self.context.mode.name(),
                self.batch
            ),
        );
    }

    /// Closes every job through the mock and checks the session ended cleanly.
    async fn finish(mut self) -> RunSummary {
        for agent in 0..AGENTS {
            let id = job_id(agent);
            if let Err(error) = RecordingFrontend::dispatch(
                self.fixture.frontend(),
                FrontendAction::Stop {
                    id: &id,
                    force: false,
                },
            )
            .await
            {
                self.fail(&format!("stopping {id}: {error}"));
            }
        }
        let uids = self.uids.clone();
        let fixture = self.fixture;
        let closed = wait_until(fixture, |recorder| {
            uids.iter().all(|uid| recorder.is_closed(uid))
        })
        .await;
        if !closed {
            self.fail("a job never reported its streams over");
        }

        let mut recorder = self.fixture.recorder();
        // The closing tails, so nothing is left buffered for a job that is already gone.
        for uid in &uids {
            let _ = recorder.take_terminal(uid);
            let _ = recorder.take_instrumentation(uid);
        }
        let open = recorder.observed_jobs().len();
        let failures: Vec<String> = uids
            .iter()
            .filter_map(|uid| recorder.error(uid).map(|error| format!("{uid}: {error}")))
            .collect();
        let retained: Vec<&String> = uids
            .iter()
            .filter(|uid| recorder.closed_with_storage(uid))
            .collect();
        drop(recorder);
        if open != 0 {
            self.fail(&format!("{open} jobs are still in the observed table"));
        }
        if !failures.is_empty() {
            self.fail(&format!("a job's stream failed: {failures:?}"));
        }
        if !retained.is_empty() {
            self.fail(&format!(
                "a job's work tree outlived its end of stream: {retained:?}"
            ));
        }
        if self.starts != self.reaped {
            self.fail(&format!(
                "{} commands were submitted and {} completions arrived",
                self.starts, self.reaped
            ));
        }
        let classified = self.summary.committed + self.summary.denied + self.summary.stale;
        if classified != self.reaped {
            self.fail(&format!(
                "{} completions arrived and {classified} outcomes were classified",
                self.reaped
            ));
        }
        if let Some(surprise) = oracle::no_surprise_violation(&self.history) {
            self.fail(&format!("a principal was surprised: {surprise}"));
        }
        self.summary.contended = oracle::contended_events(&self.history);
        self.summary
    }
}

/// Runs one generated trace through a mocked session and reports what it amounted to.
///
/// The scheduling rule is the load-bearing guarantee: a batch is generated against a *settled*
/// model, every member starts before any is released, and the next batch is generated only from
/// what actually committed. A concurrently deleted file can therefore make another member's
/// snapshot stale, but can never make its command start against an operand that is already gone.
async fn run_trace(fixture: &Fixture, bytes: &[u8], mode: RunMode, label: &str) -> RunSummary {
    drive(fixture, bytes, mode, label, Release::Together).await
}

/// [`run_trace`] with the first batch's release order chosen.
///
/// A deterministic handoff regression needs the two commands started together and concluded in a
/// pinned order; everything else releases the whole batch at once.
async fn drive(
    fixture: &Fixture,
    bytes: &[u8],
    mode: RunMode,
    label: &str,
    first: Release,
) -> RunSummary {
    let mut generator = SeqGenerator::new(bytes);
    let budget = generator.step_budget();
    let mut session = Session::open(
        fixture,
        TraceContext {
            label: label.to_string(),
            mode,
            input: bytes.to_vec(),
            seed: std::env::var(SEED_VARIABLE).unwrap_or_else(|_| "<unset>".to_string()),
        },
    )
    .await;

    let mut drawn = 0;
    let mut release = first;
    let mut exhausted = false;
    while drawn < budget && !exhausted {
        session.assert_pools(&generator);
        let mut batch: Vec<Admitted> = Vec::new();
        while drawn < budget {
            // A batch is at most one command wide per principal, and exactly one in ordered mode.
            if batch.len() >= mode.width() {
                break;
            }
            // Before the draw and without spending a byte: a batch admits one command per
            // principal, and rerolling or carrying a drawn candidate would change the trace.
            let Some(agent) = generator.peek_agent() else {
                exhausted = true;
                break;
            };
            if batch
                .iter()
                .any(|admitted| admitted.candidate.agent == agent)
            {
                break;
            }
            let Some(candidate) = generator.next_candidate() else {
                exhausted = true;
                break;
            };
            drawn += 1;
            // Grant-only admission against the settled batch-start history: no member has
            // committed yet, and all of them run against this one snapshot state.
            if !policy_grants(&session.history, &candidate.event()) {
                session.summary.filtered += 1;
                continue;
            }
            let admitted = session.admit(candidate);
            batch.push(admitted);
        }
        if batch.is_empty() {
            continue;
        }
        session.run_batch(&mut generator, &batch, release).await;
        release = Release::Together;
    }
    session.assert_pools(&generator);

    session.finish().await
}

/// Drives concrete candidates through the mock, one per batch, with no admission filtering.
///
/// The negative probes are physically executable in the snapshot they start from — their operands
/// are present and their writes would succeed — so only authorization may reject them. A separate
/// entry point rather than a mode on [`run_trace`]: the fuzz path must keep submitting grants only.
async fn run_probes(
    fixture: &Fixture,
    probes: &[Candidate],
    mode: RunMode,
    label: &str,
) -> RunSummary {
    let mut generator = SeqGenerator::new(&[]);
    let mut session = Session::open(
        fixture,
        TraceContext {
            label: label.to_string(),
            mode,
            input: Vec::new(),
            seed: "<none: explicit probes>".to_string(),
        },
    )
    .await;
    for candidate in probes {
        session.assert_pools(&generator);
        let batch = vec![session.admit(*candidate)];
        session
            .run_batch(&mut generator, &batch, Release::Together)
            .await;
    }
    session.assert_pools(&generator);
    session.finish().await
}

/// One concrete probe candidate.
const fn probe(agent: usize, operation: GeneratedOperation, file: usize, step: usize) -> Candidate {
    Candidate {
        agent,
        operation,
        file,
        step,
    }
}

/// The decoder must spend no byte on a singleton pool, and peeking must not move the cursor.
#[test]
fn singleton_file_pool_preserves_reference_entropy() {
    let input = [3, 0, 1, 0, 0, 0, 2, 8, 3];
    let mut generator = SeqGenerator::new(&input);
    assert_eq!(
        generator.step_budget(),
        3,
        "the encoded budget is the first draw"
    );

    let expected = [
        (0, GeneratedOperation::Delete, 0, 0),
        // The pool has narrowed to one absent-and-tracked path, and `choose` spends nothing on a
        // singleton: a modulo decoder would consume a byte here and shift everything after it.
        (0, GeneratedOperation::Create, 0, 1),
        (2, GeneratedOperation::Diff, 3, 2),
    ];
    for (agent, operation, file, step) in expected {
        assert_eq!(generator.peek_agent(), Some(agent));
        assert_eq!(
            generator.peek_agent(),
            Some(agent),
            "peeking twice must draw the same agent and consume nothing"
        );
        let candidate = generator
            .next_candidate()
            .unwrap_or_else(|| panic!("step {step} was generated"));
        assert_eq!(
            (
                candidate.agent,
                candidate.operation,
                candidate.file,
                candidate.step
            ),
            (agent, operation, file, step)
        );
        generator.record_grant(&candidate);
    }
    assert!(generator.peek_agent().is_none(), "the input is spent");
    assert!(generator.next_candidate().is_none());
}

/// An input that buys no candidates opens and closes a whole session without submitting one.
#[test]
fn empty_and_exhausted_inputs_submit_nothing() {
    let mut empty = SeqGenerator::new(&[]);
    assert_eq!(empty.step_budget(), 0, "an empty input buys no steps");
    assert!(empty.next_candidate().is_none());

    let spent_input = [32];
    let mut spent = SeqGenerator::new(&spent_input);
    assert_eq!(spent.step_budget(), 32, "the budget byte is still decoded");
    assert!(
        spent.next_candidate().is_none(),
        "and nothing is left to generate a candidate from"
    );

    mux_test!(fixture = Fixture::new("frontend-empty"), {
        let summary = run_trace(&fixture, &[], RunMode::Ordered, "empty").await;
        assert_eq!(summary.committed, 0);
        assert_eq!(summary.filtered, 0);
        assert!(
            fixture.mux().history().is_empty(),
            "an empty trace leaves the authority alone"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the seed"),
            "seed\n",
            "and the seed as it was"
        );
    });

    mux_test!(fixture = Fixture::new("frontend-spent"), {
        let summary = run_trace(&fixture, &spent_input, RunMode::Parallel, "spent").await;
        assert_eq!(summary.committed, 0);
        assert_eq!(summary.filtered, 0);
        assert!(fixture.mux().history().is_empty());
    });
}

/// Generation draws its operands from the two pools, so a read never names a deleted path and a
/// creation never names a present one.
#[test]
fn existing_and_absent_pools_choose_valid_io() {
    mux_test!(fixture = Fixture::new("frontend-pools"), {
        let input = [3, 0, 1, 0, 0, 8, 0, 0, 0];
        let (candidates, filtered) = reference_trace(&input);
        assert_eq!(filtered, 0, "every candidate here is policy-legal");
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| (
                    candidate.agent,
                    candidate.operation,
                    candidate.file,
                    candidate.step
                ))
                .collect::<Vec<_>>(),
            vec![
                (0, GeneratedOperation::Delete, 0, 0),
                (0, GeneratedOperation::Read, 1, 1),
                (0, GeneratedOperation::Create, 0, 2),
            ],
            "the read takes an existing path, the creation the absent one"
        );

        let summary = run_trace(&fixture, &input, RunMode::Ordered, "pools").await;
        assert_eq!(summary.committed, 3);
        assert_eq!(summary.denied, 0);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.filtered, 0);
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the recreation"),
            "step 2\n",
            "the recreated file holds the creating step's payload"
        );
    });
}

/// A candidate the policy refuses never becomes a command, so git is never asked to do the
/// impossible and an execution failure stays a defect rather than a tolerated outcome.
#[test]
fn git_refusals_are_filtered_before_frontend_submission() {
    mux_test!(fixture = Fixture::new("frontend-filtered"), {
        let input = [2, 0, 10, 0, 0, 2, 0];
        let (candidates, filtered) = reference_trace(&input);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| (candidate.operation, candidate.file))
                .collect::<Vec<_>>(),
            vec![(GeneratedOperation::Remove, 0)],
            "only the removal survives admission"
        );
        assert_eq!(filtered, 1, "staging the removed path is filtered");

        let summary = run_trace(&fixture, &input, RunMode::Ordered, "filtered").await;
        assert_eq!(summary.committed, 1, "one command reached a job");
        assert_eq!(summary.filtered, 1, "and one candidate never did");
        assert_eq!(summary.denied, 0, "the mux was never asked to refuse it");
        assert_eq!(summary.stale, 0);
        assert!(
            !fixture.seed("src/file0.txt").exists(),
            "the removal is in the seed"
        );
    });
}

/// A refused command changes nothing: not the working tree, not the index, not the history — and
/// the owner's next edit lands on the file the refusal preserved.
#[test]
fn denied_deletion_keeps_the_existing_pool() {
    mux_test!(fixture = Fixture::new("frontend-denied"), {
        let probes = [
            probe(0, GeneratedOperation::Read, 0, 0),
            probe(1, GeneratedOperation::Delete, 0, 1),
            probe(0, GeneratedOperation::Modify, 0, 2),
        ];
        let summary = run_probes(&fixture, &probes, RunMode::Ordered, "denied-delete").await;
        assert_eq!(
            summary.committed, 2,
            "the read and the owner's append commit"
        );
        assert_eq!(summary.denied, 1, "the foreign deletion is refused");
        assert_eq!(summary.stale, 0);
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the seed"),
            "seed\nstep 2\n",
            "the denied deletion left the file, and the owner's append landed on it"
        );
        assert_eq!(
            fixture.mux().history().len(),
            2,
            "a denied command enters no history"
        );
    });
}

/// Two commands generated against one settled state really overlap: the loser is told its snapshot
/// went stale, not that its operand vanished, and the next batch sees only what committed.
#[test]
fn overlapping_delete_does_not_generate_io_for_an_absent_snapshot() {
    mux_test!(fixture = Fixture::new("frontend-overlap"), {
        let input = [3, 0, 1, 0, 1, 0, 0, 0, 0];
        let summary = drive(
            &fixture,
            &input,
            RunMode::Parallel,
            "overlap",
            Release::Sequential,
        )
        .await;
        assert_eq!(summary.committed, 2, "the deletion and the later creation");
        assert_eq!(summary.stale, 1, "the append lost its snapshot");
        assert_eq!(summary.denied, 0, "staleness precedes policy");
        assert_eq!(summary.filtered, 0);
        assert!(
            summary.overlapping_batches >= 1,
            "the first batch really had both jobs at their gates"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the seed"),
            "step 2\n",
            "the stale append leaked nothing, and the recreation is the whole file"
        );
    });
}

/// Commit and the read claim: staging and committing keep the owner's claim, and only a read
/// transfers it.
#[test]
fn commit_and_read_handoff_obey_policy() {
    mux_test!(fixture = Fixture::new("frontend-handoff"), {
        let probes = [
            probe(0, GeneratedOperation::Modify, 0, 0),
            probe(0, GeneratedOperation::Stage, 0, 1),
            probe(0, GeneratedOperation::Commit, 0, 2),
            probe(0, GeneratedOperation::Read, 0, 3),
            // Physically valid, and by the principal that does not hold the read claim.
            probe(1, GeneratedOperation::Modify, 0, 4),
            probe(1, GeneratedOperation::Read, 0, 5),
            probe(1, GeneratedOperation::Modify, 0, 6),
        ];
        let summary = run_probes(&fixture, &probes, RunMode::Ordered, "handoff").await;
        assert_eq!(summary.committed, 6);
        assert_eq!(summary.denied, 1, "the append before the read handoff");
        assert_eq!(summary.git_commits, 1);
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the seed"),
            "seed\nstep 0\nstep 6\n"
        );
        let log = git_output(fixture.seed_root(), &["log", "--format=%s"]);
        assert_eq!(
            log.lines().next(),
            Some("step 2"),
            "the commit really reached the repository, got {log:?}"
        );
        assert!(summary.contended > 0, "the handoff is a contended sequence");
    });
}

/// Admission is not authorization: a candidate admitted against the batch-start history is still
/// judged against the history its completion actually meets.
#[test]
fn parallel_read_claim_is_checked_at_completion() {
    mux_test!(fixture = Fixture::new("frontend-claim"), {
        let input = [2, 0, 7, 0, 1, 0, 0];
        // The batch-start model, not the reference's serial one: both members are drawn against
        // the same unchanged state and judged against the same empty history, which is precisely
        // what makes the second one's admission valid and its completion still refusable.
        let mut generator = SeqGenerator::new(&input);
        assert_eq!(generator.step_budget(), 2);
        let reader = generator.next_candidate().expect("the read is generated");
        let writer = generator.next_candidate().expect("the append is generated");
        assert_eq!(
            [
                (reader.agent, reader.operation),
                (writer.agent, writer.operation)
            ],
            [
                (0, GeneratedOperation::Read),
                (1, GeneratedOperation::Modify)
            ]
        );
        assert!(
            policy_grants(&[], &reader.event()) && policy_grants(&[], &writer.event()),
            "both are admitted against the empty batch-start history"
        );

        let summary = drive(
            &fixture,
            &input,
            RunMode::Parallel,
            "claim",
            Release::Sequential,
        )
        .await;
        assert_eq!(summary.committed, 1, "only the read commits");
        assert_eq!(
            summary.denied, 1,
            "the writer is refused against the claim the reader took"
        );
        assert_eq!(
            summary.stale, 0,
            "the reader changed no file, so the writer's snapshot is current"
        );
        assert!(
            summary.overlapping_batches >= 1,
            "both jobs were at their gates before either was released"
        );
        let history = fixture.mux().history();
        assert_eq!(history.len(), 1, "only the read is in the authority");
        assert_eq!(
            std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read the seed"),
            "seed\n",
            "and the refused append reached neither the seed nor the file"
        );
    });
}

/// The whole fixed reference corpus, run both ways.
#[test]
fn reference_seeded_traces_drive_frontend() {
    let stream = entropy(DETERMINISTIC_SEED, SEEDED_TRACE_COUNT * BYTES_PER_TRACE);
    println!("mux_frontend_fuzz: fixed corpus, seed {DETERMINISTIC_SEED:#018x}");

    let mut ordered = RunSummary::default();
    let mut parallel = RunSummary::default();
    for (index, bytes) in stream.chunks(BYTES_PER_TRACE).enumerate() {
        let label = format!("seed/{index}");
        mux_test!(
            fixture = Fixture::new(&format!("frontend-seed-{index}-ordered")),
            {
                let summary = run_trace(&fixture, bytes, RunMode::Ordered, &label).await;
                println!("  {label} ordered: {}", summary.line());
                ordered.absorb(&summary);
            }
        );
        mux_test!(
            fixture = Fixture::new(&format!("frontend-seed-{index}-parallel")),
            {
                let summary = run_trace(&fixture, bytes, RunMode::Parallel, &label).await;
                println!("  {label} parallel: {}", summary.line());
                parallel.absorb(&summary);
            }
        );
    }

    println!("  fixed ordered total:  {}", ordered.line());
    println!("  fixed parallel total: {}", parallel.line());
    assert_eq!(
        (
            ordered.committed,
            ordered.filtered,
            ordered.denied,
            ordered.stale,
            ordered.git_commits
        ),
        (
            SEEDED_ORDERED_COMMITTED,
            SEEDED_ORDERED_FILTERED,
            0,
            0,
            SEEDED_ORDERED_GIT_COMMITS
        ),
        "the ordered fixed corpus must reproduce the reference exporter's grants exactly"
    );
    assert!(
        ordered.contended > 0,
        "a corpus with no contention would pass the no-surprise sweep vacuously"
    );
    assert!(
        parallel.overlapping_batches > 0,
        "the parallel run never had two jobs at their gates at once"
    );
    assert!(
        parallel.committed > 0,
        "the parallel run committed nothing at all"
    );
}

/// A fresh corpus every run, so a defect the fixed traces miss still has somewhere to surface.
#[test]
fn reference_random_traces_drive_frontend() {
    let seed = random_seed();
    println!("mux_frontend_fuzz: random corpus, seed {seed:#018x}");
    println!(
        "  reproduce with MARSH_FUZZ_SEED={seed:#018x} cargo test -p shellmux \
         --test mux_frontend_fuzz reference_random_traces_drive_frontend -- --nocapture"
    );
    let stream = entropy(seed, RANDOM_TRACE_COUNT * BYTES_PER_TRACE);

    let mut ordered = RunSummary::default();
    let mut parallel = RunSummary::default();
    for (index, bytes) in stream.chunks(BYTES_PER_TRACE).enumerate() {
        let label = format!("random/{index}");
        mux_test!(
            fixture = Fixture::new(&format!("frontend-random-{index}-ordered")),
            {
                let summary = run_trace(&fixture, bytes, RunMode::Ordered, &label).await;
                println!("  {label} ordered: {}", summary.line());
                ordered.absorb(&summary);
            }
        );
        mux_test!(
            fixture = Fixture::new(&format!("frontend-random-{index}-parallel")),
            {
                let summary = run_trace(&fixture, bytes, RunMode::Parallel, &label).await;
                println!("  {label} parallel: {}", summary.line());
                parallel.absorb(&summary);
            }
        );
    }

    println!("  random ordered total:  {}", ordered.line());
    println!("  random parallel total: {}", parallel.line());
    assert_eq!(ordered.denied, 0, "an ordered run has nothing to race");
    assert_eq!(ordered.stale, 0, "and nothing to lose a snapshot to");
    assert!(
        ordered.committed > 0,
        "the random corpus committed nothing; generation is broken"
    );
}
