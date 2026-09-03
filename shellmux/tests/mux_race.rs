//! Concurrent proof: three principals hammering one mux from three OS threads must be
//! indistinguishable from running their merged commands one at a time, in merge order.
//!
//! Nothing here inspects internal locking. The claim is checked from the outside: replay the merged
//! commands serially into a plain directory and demand the seed match, byte for byte and commit for
//! commit.
//!
//! Run with a pinned seed to reproduce a failure exactly:
//! `MARSH_FUZZ_SEED=0xdecafbad cargo test -p shellmux --test mux_race -- --nocapture`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{
    RaceGenerator, Replayer, assert_same_repo, mux_root, oracle, principal_for, random_seed,
    remove_root, seed_init, step_budget,
};
use shellmux::{CmdOutcome, Event, MuxOptions, ShellMux};

/// Principals racing each other.
const AGENTS: usize = 3;
/// Default commands attempted per principal.
const DEFAULT_STEPS: usize = 20;
/// Reruns allowed after losing a race before the command is abandoned.
const MAX_ATTEMPTS: usize = 4;

/// One command that made it into the seed.
#[derive(Debug)]
struct MergedCommand {
    seq: u64,
    agent: usize,
    cmd: String,
    granted: Vec<Event>,
}

/// Per-thread counters.
#[derive(Debug, Default)]
struct Counters {
    merged: usize,
    denied: usize,
    stale: usize,
    failed: usize,
    dropped: usize,
}

#[test]
fn concurrent_principals_are_equivalent_to_their_merge_order() {
    let seed = random_seed();
    let steps = step_budget(DEFAULT_STEPS);
    println!("mux_race: seed 0x{seed:016x} ({steps} steps/agent, {AGENTS} agents)");

    let root = mux_root("race");
    let options = MuxOptions {
        executor: Some(PathBuf::from(env!("CARGO_BIN_EXE_marsh-exec"))),
        ..MuxOptions::default()
    };
    let mux = Arc::new(ShellMux::create(&root, options, seed_init).expect("create mux"));

    let mut handles = Vec::with_capacity(AGENTS);
    for agent in 0..AGENTS {
        let mux = Arc::clone(&mux);
        let agent_seed = seed
            .wrapping_add(agent as u64 + 1)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        handles.push(std::thread::spawn(move || {
            let principal = principal_for(agent);
            let mut generator = RaceGenerator::new(agent, agent_seed, steps * 4);
            let mut counters = Counters::default();
            let mut merged = Vec::new();

            for _ in 0..steps {
                let Some(candidate) = generator.next_candidate() else {
                    break;
                };
                let cmd = candidate.command();
                let mut attempts = 0;
                loop {
                    attempts += 1;
                    let outcome = mux
                        .run_cmd(&principal, &cmd)
                        .unwrap_or_else(|error| panic!("mux failed on {cmd:?}: {error}"));
                    match outcome {
                        CmdOutcome::Merged { seq, granted, .. } => {
                            counters.merged += 1;
                            merged.push(MergedCommand {
                                seq,
                                agent,
                                cmd: cmd.clone(),
                                granted,
                            });
                            break;
                        }
                        // Someone else merged one of this command's paths first. Rerunning against
                        // the newer seed is the whole conflict protocol: first to get its caps wins,
                        // the loser starts over.
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
                        // Every generated command is mappable by construction; an unmappable one
                        // means the renderer and the translator have drifted apart.
                        CmdOutcome::Unsupported { reason, .. } => {
                            panic!("generated command {cmd:?} was unmappable: {reason}")
                        }
                    }
                }
            }
            (counters, merged)
        }));
    }

    let mut all_merged: Vec<MergedCommand> = Vec::new();
    let mut totals = Counters::default();
    for handle in handles {
        let (counters, merged) = handle.join().expect("agent thread panicked");
        totals.merged += counters.merged;
        totals.denied += counters.denied;
        totals.stale += counters.stale;
        totals.failed += counters.failed;
        totals.dropped += counters.dropped;
        all_merged.extend(merged);
    }
    all_merged.sort_by_key(|entry| entry.seq);

    println!(
        "  merged {}, denied {}, stale retries {}, failed {}, dropped {}",
        totals.merged, totals.denied, totals.stale, totals.failed, totals.dropped
    );
    assert!(
        totals.merged > 0,
        "nothing merged; the race proved nothing (seed 0x{seed:016x})"
    );

    // 1. Merge sequence numbers are a strict total order with no gaps: one authority, one counter.
    for (index, entry) in all_merged.iter().enumerate() {
        assert_eq!(
            entry.seq,
            index as u64 + 1,
            "merge sequence numbers must be gapless and unique (seed 0x{seed:016x}): {all_merged:?}"
        );
    }

    // 2. The committed history is exactly the merged commands' granted events, in merge order.
    let history = mux.history();
    let expected_history: Vec<Event> = all_merged
        .iter()
        .flat_map(|entry| entry.granted.iter().cloned())
        .collect();
    assert_eq!(
        history, expected_history,
        "the authority's history must be the merged commands' capabilities in merge order \
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

    // 3. Linearizability: the concurrent seed equals a plain serial execution in merge order.
    let replayer = Replayer::new(root.join("replay"));
    for entry in &all_merged {
        replayer.apply(&principal_for(entry.agent), &entry.cmd);
    }
    assert_same_repo(
        mux.seed_dir(),
        replayer.dir(),
        &format!("concurrent run vs its serial merge order (seed 0x{seed:016x})"),
    );

    // 4. No snapshot leaks: every run cleaned up after itself.
    let snaps: Vec<PathBuf> = std::fs::read_dir(root.join(".marsh/snaps"))
        .expect("read snapshot directory")
        .map(|entry| entry.expect("read snapshot entry").path())
        .collect();
    assert!(snaps.is_empty(), "snapshots leaked: {snaps:?}");

    // 5. The log is well formed and reopening the mux recovers exactly this history.
    drop(mux);
    assert_wal_well_formed(&root, all_merged.len());
    let reopened = ShellMux::open(&root, MuxOptions::default()).expect("reopen mux");
    assert_eq!(
        reopened.history(),
        history,
        "recovery from the log must reproduce the committed history (seed 0x{seed:016x})"
    );

    drop(reopened);
    remove_root(&root);
}

/// Checks the write-ahead log directly: every intent has a matching commit, sequence numbers are
/// strictly increasing, and the count matches what the threads observed.
fn assert_wal_well_formed(root: &Path, expected_merges: usize) {
    let text = std::fs::read_to_string(root.join(".marsh/wal.log")).expect("read wal");
    let mut intents: Vec<u64> = Vec::new();
    let mut commits: Vec<u64> = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let record: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("bad wal line {line:?}: {error}"));
        let seq = record["seq"].as_u64().expect("record carries a seq");
        match record["kind"].as_str().expect("record carries a kind") {
            "intent" => intents.push(seq),
            "commit" => commits.push(seq),
            other => panic!("unknown wal record kind {other:?}"),
        }
    }
    assert_eq!(
        intents.len(),
        expected_merges,
        "every merge writes exactly one intent"
    );
    assert_eq!(intents, commits, "every intent is followed by its commit");
    assert!(
        intents.windows(2).all(|pair| pair[0] < pair[1]),
        "intent sequence numbers must strictly increase: {intents:?}"
    );
}
