//! Sequential proof: one principal at a time, the mux's answer must equal real git plus the policy
//! oracle, and the capability it derived must equal the capability the command meant.
//!
//! Run with a pinned seed to reproduce a failure exactly:
//! `MARSH_FUZZ_SEED=0xdecafbad cargo test -p shellmux --test mux_seq -- --nocapture`.

mod common;

use std::path::PathBuf;

use common::{
    Replayer, SeqGenerator, assert_same_repo, mux_root, oracle, principal_for, random_seed,
    remove_root, seed_init, step_budget,
};
use rust_validator::{Bump, GitPolicy, PolicyDecision};
use shellmux::{Action, CmdOutcome, Event, MuxOptions, Resource, ShellMux};

/// Number of independent generated traces.
const TRACE_COUNT: usize = 6;
/// Default steps per trace.
const DEFAULT_STEPS: usize = 24;

/// Mux options pointing at the executor this test binary was built alongside.
fn options() -> MuxOptions {
    MuxOptions {
        executor: Some(PathBuf::from(env!("CARGO_BIN_EXE_marsh-exec"))),
        ..MuxOptions::default()
    }
}

/// The policy's own verdict on a candidate, used as the oracle the mux must agree with.
fn oracle_decision(history: &[Event], candidate: &Event) -> PolicyDecision {
    let arena = Bump::new();
    GitPolicy::new(&arena).decide(history, candidate)
}

/// The acceptance anchor on real streams: `touch foo && git add foo` must show *both* the creation
/// syscall (external `touch`, seen by `strace`) and the builtin invocation (`git add`, seen by the
/// hook). One stream cannot produce both, so this is the proof that the merge works end to end.
#[test]
fn touch_and_git_add_are_both_instrumented() {
    let root = mux_root("seq-instrumented");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");
    let agent0 = principal_for(0);

    let outcome = mux
        .run_cmd(&agent0, "touch foo && git add foo")
        .expect("run command");
    let CmdOutcome::Merged {
        granted, trace_log, ..
    } = &outcome
    else {
        panic!("expected a merge, got {outcome:?}");
    };
    assert_eq!(
        granted,
        &vec![
            Event::new(agent0.clone(), Action::Edit, Resource::from(vec!["foo"])),
            Event::new(agent0.clone(), Action::Stage, Resource::from(vec!["foo"])),
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
        std::fs::read_to_string(mux.seed_dir().join("foo")).expect("merged file"),
        "",
        "the empty file `touch` created is in the seed"
    );

    drop(mux);
    remove_root(&root);
}

/// Bypassing the builtins with a real git binary is not instrumentable, and is refused rather than
/// guessed at.
#[test]
fn raw_git_bypass_is_unsupported() {
    let root = mux_root("seq-bypass");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");

    let outcome = mux
        .run_cmd(&principal_for(0), "/usr/bin/git add -- src/file0.txt")
        .expect("run bypass");
    let CmdOutcome::Unsupported { reason, .. } = &outcome else {
        panic!("expected an unsupported outcome, got {outcome:?}");
    };
    assert!(reason.contains("outside the git builtin"), "got {reason:?}");

    drop(mux);
    remove_root(&root);
}

/// The concrete new-behaviour proof, spelled out: an edit merges and is visible in the seed, and
/// another principal's attempt to stage that edit is refused with the reason naming its owner.
#[test]
fn an_edit_merges_and_a_foreign_stage_is_refused() {
    let root = mux_root("seq-proof");
    let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");

    let agent0 = principal_for(0);
    let outcome = mux
        .run_cmd(&agent0, "printf 'step 0\\n' > src/file0.txt")
        .expect("run edit");
    let CmdOutcome::Merged { seq, granted, .. } = &outcome else {
        panic!("expected a merge, got {outcome:?}");
    };
    assert_eq!(*seq, 1, "the first merge takes sequence 1");
    assert_eq!(
        granted,
        &vec![Event::new(
            agent0.clone(),
            Action::Edit,
            Resource::from(vec!["src", "file0.txt"])
        )],
        "a redirection is exactly one edit capability on exactly one path"
    );
    assert_eq!(
        std::fs::read_to_string(mux.seed_dir().join("src/file0.txt")).expect("read seed"),
        "step 0\n",
        "the merge is visible in the seed"
    );

    let agent1 = principal_for(1);
    let outcome = mux
        .run_cmd(&agent1, "git add -- src/file0.txt")
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
            agent1.clone(),
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
        .run_cmd(&agent0, "git add -- src/file0.txt")
        .expect("run owner stage");
    assert!(
        matches!(outcome, CmdOutcome::Merged { seq: 2, .. }),
        "the owner's stage merges, got {outcome:?}"
    );

    drop(mux);
    remove_root(&root);
}

/// Randomized sequential traces: every merged command's capability set must be exactly the
/// capability its command line meant, every denial must match the policy oracle, and the seed must
/// equal a plain serial re-execution of the merged commands.
#[test]
fn sequential_traces_are_exact_and_match_git() {
    let seed = random_seed();
    let steps = step_budget(DEFAULT_STEPS);
    println!("mux_seq: seed 0x{seed:016x} ({} steps/trace)", steps);

    for trace in 0..TRACE_COUNT {
        let trace_seed = seed
            .wrapping_add(trace as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut generator = SeqGenerator::new(trace_seed, steps * 8);
        let root = mux_root(&format!("seq-{trace}"));
        let mux = ShellMux::create(&root, options(), seed_init).expect("create mux");
        let replayer = Replayer::new(root.join("replay"));

        let mut merged = 0usize;
        let mut denied = 0usize;
        let mut refused_by_git = 0usize;

        for _ in 0..steps {
            let Some(candidate) = generator.next_candidate() else {
                break;
            };
            let principal = candidate.principal();
            let command = candidate.command();
            let expected = candidate.event();
            let history_before = mux.history();
            let outcome = mux
                .run_cmd(&principal, &command)
                .unwrap_or_else(|error| panic!("mux failed on {command:?}: {error}"));

            match outcome {
                CmdOutcome::Merged {
                    granted, trace_log, ..
                } => {
                    assert_eq!(
                        granted,
                        vec![expected.clone()],
                        "translation must be exact for {command:?} (trace {trace}, seed 0x{seed:016x})"
                    );
                    if candidate.is_git() {
                        // No git *process* exists any more: the retained evidence of a git
                        // operation is its builtin record, beside the trace log.
                        let records =
                            std::fs::read_to_string(trace_log.with_file_name("builtins.json"))
                                .expect("read builtin records");
                        assert!(
                            records.contains("\"builtin\":\"git "),
                            "the retained records must name the git builtin for {command:?}"
                        );
                        let text = std::fs::read_to_string(&trace_log).expect("read trace log");
                        assert!(
                            !text
                                .lines()
                                .any(|line| line.contains("execve") && line.contains("\"git\"")),
                            "and no git process may have been spawned for {command:?}"
                        );
                    }
                    assert_eq!(
                        oracle_decision(&history_before, &expected),
                        PolicyDecision::Grant,
                        "the mux merged {command:?} that the policy oracle would refuse"
                    );
                    generator.record_grant(&candidate);
                    replayer.apply(&principal, &command);
                    merged += 1;
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
                    denied += 1;
                }
                // git itself refused the command. Such a command must have been unmergeable anyway:
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
                    refused_by_git += 1;
                }
                other => panic!(
                    "unexpected outcome for {command:?} (trace {trace}, seed 0x{seed:016x}): {other:?}"
                ),
            }
        }

        assert_same_repo(
            mux.seed_dir(),
            replayer.dir(),
            &format!("trace {trace} (seed 0x{seed:016x})"),
        );
        let history = mux.history();
        assert!(
            oracle::no_surprise_violation(&history).is_none(),
            "trace {trace} (seed 0x{seed:016x}) surprised a principal: {:?}",
            oracle::no_surprise_violation(&history)
        );
        println!(
            "  trace {trace}: {merged} merged, {denied} denied, {refused_by_git} refused by git, \
             {} contended events",
            oracle::contended_events(&history)
        );
        assert!(
            merged > 0,
            "trace {trace} merged nothing; generation is broken"
        );

        drop(mux);
        remove_root(&root);
    }
}
