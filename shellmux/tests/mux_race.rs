//! Concurrent proof: three principals hammering one mux from three Tokio tasks must be
//! indistinguishable from running their committed commands one at a time, in commit order.
//!
//! Nothing here inspects internal locking. The claim is checked from the outside: replay the committed
//! commands serially into plain directories and demand the seed match, byte for byte and commit for
//! commit.
//!
//! Run with a pinned seed to reproduce a failure exactly:
//! `MARSH_FUZZ_SEED=0xdecafbad cargo test -p shellmux --test mux_race -- --nocapture`.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::{
    Fixture, RaceGenerator, Replayer, agent_sandboxes, assert_same_seed, command_of, random_seed,
    step_budget,
};
use marsh_trace::{oracle, principal_for};
use shellmux::{Action, CmdOutcome, Event, PersistenceLayer, Sandbox, ShellMux};

/// Principals racing each other.
const AGENTS: usize = 3;
/// Default commands attempted per principal.
const DEFAULT_STEPS: usize = 20;
/// Reruns allowed after losing a race before the command is abandoned.
///
/// Generous, because the reference a command is diffed against is the live seed: it loses its race
/// whenever *any* principal committed since it snapshotted, whatever paths either of them touched, so
/// a rerun is the norm rather than the exception.
const MAX_ATTEMPTS: usize = 12;

/// One command that made it into the seed.
#[derive(Debug)]
struct CommittedCommand {
    seq: u64,
    agent: usize,
    cmd: String,
    granted: Vec<Event>,
}

/// Per-task counters.
#[derive(Debug, Default)]
struct Counters {
    committed: usize,
    denied: usize,
    stale: usize,
    failed: usize,
    dropped: usize,
}

/// One agent's whole run: generate a command, submit it, retry while it keeps losing races, and
/// report what actually committed.
///
/// Losing a race is expected rather than exceptional — the reference is the live seed, so any other
/// principal's commit invalidates this one's snapshot — which is why the retry budget is generous
/// and a command that exhausts it is counted as dropped instead of failing the test.
///
/// Owned arguments and an owned mux handle: this runs as a Tokio task, not on the test's own
/// future, which is what makes the three agents actually overlap.
async fn run_agent(
    mux: Arc<ShellMux>,
    sandbox: Sandbox,
    agent: usize,
    agent_seed: u64,
    steps: usize,
) -> (Counters, Vec<CommittedCommand>, Sandbox) {
    let mut generator = RaceGenerator::new(agent, agent_seed, steps * 4);
    let mut counters = Counters::default();
    let mut committed = Vec::new();

    for _ in 0..steps {
        let Some(candidate) = generator.next_candidate() else {
            break;
        };
        let cmd = command_of(&candidate);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let outcome = mux
                .run_cmd(&sandbox, &cmd)
                .await
                .unwrap_or_else(|error| panic!("mux failed on {cmd:?}: {error}"));
            match outcome {
                CmdOutcome::Committed { seq, granted, .. } => {
                    counters.committed += 1;
                    committed.push(CommittedCommand {
                        seq,
                        agent,
                        cmd: cmd.clone(),
                        granted,
                    });
                    break;
                }
                // Someone else committed one of this command's paths first. Rerunning against the
                // newer seed is the whole conflict protocol: first to get its caps wins, the loser
                // starts over.
                CmdOutcome::StaleSnapshot { .. } => {
                    counters.stale += 1;
                    if attempts >= MAX_ATTEMPTS {
                        counters.dropped += 1;
                        break;
                    }
                }
                CmdOutcome::DeniedCaps { .. } => {
                    counters.denied += 1;
                    break;
                }
                CmdOutcome::ExecFailed { .. } => {
                    counters.failed += 1;
                    break;
                }
                // Every generated command is mappable by construction; an unmappable one means the
                // renderer and the translator have drifted apart.
                CmdOutcome::Unsupported { reason, .. } => {
                    panic!("generated command {cmd:?} was unmappable: {reason}")
                }
                // Not one generated command is provable from its own syntax — every one is a
                // redirection, a git builtin or an external program — so the static checker this
                // fixture carries sends all of them through the transaction. A bypass here would
                // mean the race is measuring something else.
                CmdOutcome::Bypassed { .. } | CmdOutcome::Escaped { .. } => {
                    panic!("{cmd:?} skipped the sandbox although no syntax proves it read-only")
                }
            }
        }
    }
    (counters, committed, sandbox)
}

#[test]
fn concurrent_principals_are_equivalent_to_their_commit_order() {
    let seed = random_seed();
    let steps = step_budget(DEFAULT_STEPS);
    println!("mux_race: seed 0x{seed:016x} ({steps} steps/agent, {AGENTS} agents)");

    mux_test!(fixture = Fixture::new("race"), {
        let sandboxes = agent_sandboxes(&fixture, AGENTS).await;
        let mux = Arc::clone(fixture.mux());

        let mut handles = Vec::with_capacity(AGENTS);
        for (agent, sandbox) in sandboxes.into_iter().enumerate() {
            let mux = Arc::clone(&mux);
            let agent_seed = seed
                .wrapping_add(agent as u64 + 1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            handles.push(tokio::spawn(run_agent(
                mux, sandbox, agent, agent_seed, steps,
            )));
        }

        let mut all_committed: Vec<CommittedCommand> = Vec::new();
        let mut totals = Counters::default();
        let mut sandboxes = Vec::with_capacity(AGENTS);
        for handle in handles {
            let (counters, committed, sandbox) = handle.await.expect("agent task panicked");
            totals.committed += counters.committed;
            totals.denied += counters.denied;
            totals.stale += counters.stale;
            totals.failed += counters.failed;
            totals.dropped += counters.dropped;
            all_committed.extend(committed);
            sandboxes.push(sandbox);
        }
        all_committed.sort_by_key(|entry| entry.seq);

        println!(
            "  committed {}, denied {}, stale retries {}, failed {}, dropped {}",
            totals.committed, totals.denied, totals.stale, totals.failed, totals.dropped
        );
        assert!(
            totals.committed > 0,
            "nothing committed; the race proved nothing (seed 0x{seed:016x})"
        );

        // 1. Merge sequence numbers are a strict total order with no gaps: one authority, one
        // counter.
        for (index, entry) in all_committed.iter().enumerate() {
            assert_eq!(
                entry.seq,
                index as u64 + 1,
                "sequence numbers must be gapless and unique (seed 0x{seed:016x}): \
                 {all_committed:?}"
            );
        }

        // 2. The committed history is exactly the committed commands' granted events, in commit
        // order.
        let history = mux.history();
        let expected_history: Vec<Event> = all_committed
            .iter()
            .flat_map(|entry| entry.granted.iter().cloned())
            .collect();
        assert_eq!(
            history, expected_history,
            "the authority's history must be the committed commands' capabilities in commit order \
             (seed 0x{seed:016x})"
        );
        assert!(
            oracle::no_surprise_violation(&history).is_none(),
            "a principal was surprised (seed 0x{seed:016x}): {:?}",
            oracle::no_surprise_violation(&history)
        );
        println!(
            "  history {} events, {} contended",
            history.len(),
            oracle::contended_events(&history)
        );

        // 3. Linearizability: the concurrent seed equals a plain serial execution in commit order.
        // Beside the seed, never inside it: a replay tree in the seed would be snapshotted, diffed
        // and compared against itself.
        let replayer = Replayer::new(fixture.scratch().join("replay"));
        for entry in &all_committed {
            replayer.apply(&principal_for(entry.agent), &entry.cmd);
        }
        assert_same_seed(
            fixture.seed_root(),
            replayer.dir(),
            &format!("concurrent run vs its serial commit order (seed 0x{seed:016x})"),
        );

        // 4. A sandbox owns its snapshot for as long as it lives, and gives it back when closed.
        for sandbox in &sandboxes {
            mux.close_sandbox(sandbox);
        }
        let snaps: Vec<PathBuf> = std::fs::read_dir(fixture.persistence().snap())
            .expect("read snapshot directory")
            .map(|entry| entry.expect("read snapshot entry").path())
            .collect();
        assert!(snaps.is_empty(), "snapshots leaked: {snaps:?}");

        // 5. The history log is well formed, and reopening the mux carries over only claims that
        // really happened and that the seed still corroborates — at most one per resource.
        drop(mux);
        fixture.finish_mux().await;
        let persistence = fixture.persistence();
        assert_history_well_formed(&persistence, all_committed.len());

        assert_restart_keeps_only_real_claims(&persistence, &history, seed).await;
    });
}

/// A restart replays ownership; it must not invent it.
///
/// The reopened history is reconciled against the seed, so it is not the log verbatim. What must
/// hold whatever the seed looks like: at most one claim per resource, every survivor a
/// row-defining action, and every survivor an event that really happened.
async fn assert_restart_keeps_only_real_claims(
    persistence: &PersistenceLayer,
    history: &[Event],
    seed: u64,
) {
    let reopened = common::reopen(persistence).await;
    let reopened_history = reopened.history();

    let mut resources: Vec<_> = reopened_history
        .iter()
        .map(|event| &event.resource)
        .collect();
    let retained = resources.len();
    resources.sort();
    resources.dedup();
    assert_eq!(
        resources.len(),
        retained,
        "at most one claim per resource survives a restart (seed 0x{seed:016x})"
    );
    for event in &reopened_history {
        assert!(
            matches!(
                event.action,
                Action::Edit | Action::Unstage | Action::Stage | Action::Delete
            ),
            "only a row-defining action is a claim (seed 0x{seed:016x}): {event:?}"
        );
        assert!(
            history.contains(event),
            "a surviving claim must be one that really happened (seed 0x{seed:016x}): {event:?}"
        );
    }

    common::close_mux(reopened).await;
}

/// Checks the capability history directly: one record per transaction, sequence numbers strictly
/// increasing, and the count matching what the tasks observed.
fn assert_history_well_formed(persistence: &PersistenceLayer, expected_commits: usize) {
    let text = std::fs::read_to_string(persistence.meta().join("history.jsonl")).expect("read log");
    let mut sequences: Vec<u64> = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let record: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("bad history line {line:?}: {error}"));
        sequences.push(record["seq"].as_u64().expect("record carries a seq"));
    }
    assert_eq!(
        sequences.len(),
        expected_commits,
        "every transaction appends exactly one history record"
    );
    assert!(
        sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "history sequence numbers must strictly increase: {sequences:?}"
    );
}
