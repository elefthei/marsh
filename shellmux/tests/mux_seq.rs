//! Sequential proof: one principal at a time, the mux's answer must equal real git plus the policy
//! oracle, and the capability it derived must equal the capability the command meant.
//!
//! Run with a pinned seed to reproduce a failure exactly:
//! `MARSH_FUZZ_SEED=0xdecafbad cargo test -p shellmux --test mux_seq -- --nocapture`.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use common::{
    Fixture, MAX_AGENTS, Replayer, SeqGenerator, agent_sandboxes, assert_same_seed, oracle,
    random_seed, step_budget,
};
use rust_validator::{Bump, GitPolicy, PolicyDecision};
use shellmux::{Action, CmdOutcome, Event, Resource};

/// Number of independent generated traces.
const TRACE_COUNT: usize = 6;
/// Default steps per trace.
const DEFAULT_STEPS: usize = 24;

/// The policy's own verdict on a candidate, used as the oracle the mux must agree with.
fn oracle_decision(history: &[Event], candidate: &Event) -> PolicyDecision {
    let arena = Bump::new();
    GitPolicy::new(&arena).decide(history, candidate)
}

/// The acceptance anchor on real streams: `touch foo && git add foo` must show *both* the creation
/// syscall (external `touch`, seen by `strace`) and the builtin invocation (`git add`, seen by the
/// hook). One stream cannot produce both, so this is the proof that the two merge end to end.
#[test]
fn touch_and_git_add_are_both_instrumented() {
    let fixture = Fixture::new("seq-instrumented");
    let mux = fixture.mux();
    let sandbox = agent_sandboxes(&fixture, 1).remove(0);
    let agent0 = sandbox.principal();

    let outcome = mux
        .run_cmd(&sandbox, "touch foo && git add foo")
        .expect("run command");
    let CmdOutcome::Committed {
        granted, trace_log, ..
    } = &outcome
    else {
        panic!("expected a commit, got {outcome:?}");
    };
    assert_eq!(
        granted,
        &vec![
            Event::new(agent0.clone(), Action::Edit, Resource::from(vec!["foo"])),
            Event::new(agent0, Action::Stage, Resource::from(vec!["foo"])),
        ],
        "the creation came from the syscall stream, the staging from the record stream"
    );

    let records = std::fs::read_to_string(trace_log.with_file_name("builtins.json"))
        .expect("read builtin records");
    assert!(
        records.contains("\"builtin\":\"git add\""),
        "the dump names the git builtin: {records}"
    );
    assert!(
        records.contains("\"k\":\"e\"") && records.contains("\"exit\":0"),
        "and records that it succeeded: {records}"
    );
    let trace = std::fs::read_to_string(trace_log).expect("read trace log");
    assert!(
        trace
            .lines()
            .any(|line| line.contains("openat") && line.contains("\"foo\"")),
        "the other stream carries the creation syscall"
    );
    assert!(
        !trace
            .lines()
            .any(|line| line.contains("execve(") && line.contains("/git\"")),
        "and no git process was spawned"
    );

    assert_eq!(
        std::fs::read_to_string(fixture.seed("foo")).expect("the committed file"),
        "",
        "the empty file `touch` created is in the seed"
    );
}

/// Bypassing the builtins with a real git binary is not instrumentable, and is refused rather than
/// guessed at.
#[test]
fn raw_git_bypass_is_unsupported() {
    let fixture = Fixture::new("seq-bypass");
    let mux = fixture.mux();
    let sandbox = agent_sandboxes(&fixture, 1).remove(0);

    let outcome = mux
        .run_cmd(&sandbox, "/usr/bin/git add -- src/file0.txt")
        .expect("run bypass");
    let CmdOutcome::Unsupported { reason, .. } = &outcome else {
        panic!("expected an unsupported outcome, got {outcome:?}");
    };
    assert!(reason.contains("outside the git builtin"), "got {reason:?}");
}

/// The concrete new-behaviour proof, spelled out: an edit commits and is visible in the seed, and
/// another principal's attempt to stage that edit is refused with the reason naming its owner.
#[test]
fn an_edit_commits_and_a_foreign_stage_is_refused() {
    let fixture = Fixture::new("seq-proof");
    let mux = fixture.mux();
    let sandboxes = agent_sandboxes(&fixture, 2);
    let agent0 = sandboxes[0].principal();
    let agent1 = sandboxes[1].principal();

    let outcome = mux
        .run_cmd(&sandboxes[0], "printf 'step 0\\n' > src/file0.txt")
        .expect("run edit");
    let CmdOutcome::Committed { seq, granted, .. } = &outcome else {
        panic!("expected a commit, got {outcome:?}");
    };
    assert_eq!(*seq, 1, "the first transaction takes sequence 1");
    assert_eq!(
        granted,
        &vec![Event::new(
            agent0,
            Action::Edit,
            Resource::from(vec!["src", "file0.txt"])
        )],
        "a redirection is exactly one edit capability on exactly one path"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed"),
        "step 0\n",
        "the transaction is visible in the seed"
    );

    let outcome = mux
        .run_cmd(&sandboxes[1], "git add -- src/file0.txt")
        .expect("run foreign stage");
    let CmdOutcome::DeniedCaps {
        requested, denials, ..
    } = &outcome
    else {
        panic!("expected a capability denial, got {outcome:?}");
    };
    assert_eq!(
        requested,
        &vec![Event::new(
            agent1,
            Action::Stage,
            Resource::from(vec!["src", "file0.txt"])
        )],
        "`git add -- p` is exactly one stage capability"
    );
    assert_eq!(denials.len(), 1);
    assert!(
        denials[0]
            .failed_precondition
            .contains("unstaged by agent0"),
        "the denial must name the conflicting owner, got {:?}",
        denials[0].failed_precondition
    );
    assert!(
        !denials[0].allowed_fixes.is_empty(),
        "a denial reports what would unblock it"
    );
    assert_eq!(
        mux.history().len(),
        1,
        "a denied command leaves no trace in the authority"
    );

    // The owner may stage its own edit.
    let outcome = mux
        .run_cmd(&sandboxes[0], "git add -- src/file0.txt")
        .expect("run owner stage");
    assert!(
        matches!(outcome, CmdOutcome::Committed { seq: 2, .. }),
        "the owner's stage commits, got {outcome:?}"
    );
}

/// Randomized sequential traces: every committed command's capability set must be exactly the
/// capability its command line meant, every denial must match the policy oracle, and the seed must
/// equal a plain serial re-execution of the committed commands.
#[test]
fn sequential_traces_are_exact_and_match_git() {
    let seed = random_seed();
    let steps = step_budget(DEFAULT_STEPS);
    println!("mux_seq: seed 0x{seed:016x} ({steps} steps/trace)");

    for trace in 0..TRACE_COUNT {
        run_trace(trace, seed, steps);
    }
}

/// Runs one randomized trace end to end and checks every claim the suite makes about it.
///
/// Each command is checked three ways: its granted (or requested) capability set must be exactly
/// what the command line meant, the mux's verdict must agree with the policy oracle run over the
/// history *before* the command, and — once the trace ends — the seed must equal a plain serial
/// re-execution of everything that committed.
fn run_trace(trace: usize, seed: u64, steps: usize) {
    let trace_seed = seed
        .wrapping_add(trace as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut generator = SeqGenerator::new(trace_seed, steps * 8);
    let fixture = Fixture::new(&format!("seq-{trace}"));
    let mux = fixture.mux();
    let sandboxes = agent_sandboxes(&fixture, MAX_AGENTS);
    // Beside the seed, never inside it: a replay tree in the seed would be snapshotted, diffed
    // and compared against itself.
    let replayer = Replayer::new(fixture.scratch().join("replay"));

    let mut tally = Tally::default();

    for _ in 0..steps {
        let Some(candidate) = generator.next_candidate() else {
            break;
        };
        let principal = candidate.principal();
        let sandbox = &sandboxes[candidate.agent];
        let command = candidate.command();
        let expected = candidate.event();
        let history_before = mux.history();
        let outcome = mux
            .run_cmd(sandbox, &command)
            .unwrap_or_else(|error| panic!("mux failed on {command:?}: {error}"));

        match outcome {
            CmdOutcome::Committed {
                granted, trace_log, ..
            } => {
                assert_eq!(
                    granted,
                    vec![expected.clone()],
                    "translation must be exact for {command:?} (trace {trace}, seed 0x{seed:016x})"
                );
                if candidate.is_git() {
                    assert_git_ran_as_a_builtin(&trace_log, &command);
                }
                assert_eq!(
                    oracle_decision(&history_before, &expected),
                    PolicyDecision::Grant,
                    "the mux committed {command:?} that the policy oracle would refuse"
                );
                generator.record_grant(&candidate);
                replayer.apply(&principal, &command);
                tally.committed += 1;
            }
            CmdOutcome::DeniedCaps {
                requested, denials, ..
            } => {
                assert_eq!(
                    requested,
                    vec![expected.clone()],
                    "a denied command's request set must still be exact for {command:?}"
                );
                assert!(!denials.is_empty(), "a denial reports at least one refusal");
                let PolicyDecision::Deny {
                    failed_precondition,
                    ..
                } = oracle_decision(&history_before, &expected)
                else {
                    panic!(
                        "the mux refused {command:?} that the policy oracle would grant \
                         (trace {trace}, seed 0x{seed:016x})"
                    );
                };
                assert_eq!(
                    denials[0].failed_precondition, failed_precondition,
                    "the mux's reason must be the policy's reason"
                );
                tally.denied += 1;
            }
            // git itself refused the command. Such a command must have been uncommittable anyway:
            // if the policy would have granted it, the mux and the generator disagree about what
            // the repository can do, which is a bug and not a tolerable outcome.
            CmdOutcome::ExecFailed { exit_code, .. } => {
                assert!(
                    matches!(
                        oracle_decision(&history_before, &expected),
                        PolicyDecision::Deny { .. }
                    ),
                    "{command:?} failed at git level (exit {exit_code}) although the policy \
                     would have granted it (trace {trace}, seed 0x{seed:016x})"
                );
                tally.refused_by_git += 1;
            }
            other => panic!(
                "unexpected outcome for {command:?} (trace {trace}, seed 0x{seed:016x}): {other:?}"
            ),
        }
    }

    assert_trace_result(&fixture, &replayer, trace, seed, &tally);
}

/// What one trace's commands amounted to.
#[derive(Default)]
struct Tally {
    /// Commands the mux merged into the seed.
    committed: usize,
    /// Commands the policy refused.
    denied: usize,
    /// Commands git itself rejected before policy could be consulted.
    refused_by_git: usize,
}

/// Checks a finished trace: the seed equals its serial replay, no principal was surprised, and
/// something actually committed.
fn assert_trace_result(
    fixture: &Fixture,
    replayer: &Replayer,
    trace: usize,
    seed: u64,
    tally: &Tally,
) {
    assert_same_seed(
        fixture.seed_root(),
        replayer.dir(),
        &format!("trace {trace} (seed 0x{seed:016x})"),
    );
    let history = fixture.mux().history();
    assert!(
        oracle::no_surprise_violation(&history).is_none(),
        "trace {trace} (seed 0x{seed:016x}) surprised a principal: {:?}",
        oracle::no_surprise_violation(&history)
    );
    println!(
        "  trace {trace}: {} committed, {} denied, {} refused by git, {} contended events",
        tally.committed,
        tally.denied,
        tally.refused_by_git,
        oracle::contended_events(&history)
    );
    assert!(
        tally.committed > 0,
        "trace {trace} committed nothing; generation is broken"
    );
}

/// Asserts that a committed git command ran as a builtin and spawned no git process.
///
/// No git *process* exists any more: the retained evidence of a git operation is its builtin
/// record, beside the trace log.
fn assert_git_ran_as_a_builtin(trace_log: &std::path::Path, command: &str) {
    let records = std::fs::read_to_string(trace_log.with_file_name("builtins.json"))
        .expect("read builtin records");
    assert!(
        records.contains("\"builtin\":\"git "),
        "the retained records must name the git builtin for {command:?}"
    );
    let text = std::fs::read_to_string(trace_log).expect("read trace log");
    assert!(
        !text
            .lines()
            .any(|line| line.contains("execve") && line.contains("\"git\"")),
        "and no git process may have been spawned for {command:?}"
    );
}
