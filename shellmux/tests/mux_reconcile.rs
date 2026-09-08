//! Restart proof: a capability claim outlives a restart only while the seed still shows the dirt
//! that justified it.
//!
//! Every assertion here is an observable decision — what a second principal's real command is
//! answered after a real restart — rather than the shape of the replayed history.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::sync::Arc;

use common::Fixture;
use shellmux::{CmdOutcome, Sandbox, ShellId, ShellMux};

/// A job named `name` at the seed root of `mux`.
///
/// Takes the mux rather than the fixture because half of these sandboxes belong to a mux the test
/// reopened, which the fixture no longer holds.
async fn job(mux: &Arc<ShellMux>, name: &str) -> Sandbox {
    mux.spawn("", Some(ShellId::from(name)), None)
        .await
        .expect("open sandbox")
        .sandbox
}

/// Runs `cmd` as `principal` in its own job and asserts it committed.
async fn commit(mux: &Arc<ShellMux>, principal: &str, cmd: &str) {
    let sandbox = job(mux, principal).await;
    let outcome = mux.run_cmd(&sandbox, cmd).await.expect("run command");
    assert!(
        matches!(outcome, CmdOutcome::Committed { .. }),
        "{principal}: `{cmd}` must commit, got {outcome:?}"
    );
    mux.close_sandbox(&sandbox);
}

/// Opens a second mux over the same persistence, the way a new marsh process would.
async fn reopen(fixture: &Fixture) -> Arc<ShellMux> {
    common::reopen(&fixture.persistence()).await
}

/// `agent`'s write of `note.txt` through `mux`, whatever it is answered.
async fn agent_write(mux: &Arc<ShellMux>, content: &str) -> CmdOutcome {
    let agent = job(mux, "agent").await;
    let outcome = mux
        .run_cmd(&agent, &format!("printf '{content}\\n' > note.txt"))
        .await
        .expect("run command");
    mux.close_sandbox(&agent);
    outcome
}

/// The reported bug: an `edit` is never settled by anything in the log, so before this change the
/// claim it took outlived the file itself and refused every later principal forever.
#[test]
fn a_claim_dies_with_the_dirt_that_justified_it() {
    mux_test!(fixture = Fixture::new("reconcile-released"), {
        commit(fixture.mux(), "main", "printf 'foo\\n' > note.txt").await;

        // Behind marsh's back, the way a developer resolves a file with their own git.
        std::fs::remove_file(fixture.seed("note.txt")).expect("delete the seed file");
        fixture.finish_mux().await;

        let reopened = reopen(&fixture).await;
        let history = reopened.history();
        assert!(
            !history
                .iter()
                .any(|event| event.resource.to_string() == "note.txt"),
            "nothing in the seed corroborates a claim on a deleted, untracked file: {history:?}"
        );

        let outcome = agent_write(&reopened, "bar").await;
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "a released claim must not refuse another principal's write: {outcome:?}"
        );
        common::close_mux(reopened).await;
    });
}

/// The property that must not regress: while the seed still holds the uncommitted content, the
/// principal that wrote it still owns it across a restart.
#[test]
fn a_claim_survives_while_the_seed_is_still_dirty() {
    mux_test!(fixture = Fixture::new("reconcile-retained"), {
        commit(fixture.mux(), "main", "printf 'foo\\n' > note.txt").await;
        fixture.finish_mux().await;

        let reopened = reopen(&fixture).await;
        let outcome = agent_write(&reopened, "bar").await;
        let CmdOutcome::DeniedCaps { denials, .. } = &outcome else {
            panic!("expected a denial, got {outcome:?}");
        };
        assert!(
            denials
                .iter()
                .any(|denial| denial.failed_precondition.contains("is unstaged by main")),
            "still-dirty content is still main's: {denials:?}"
        );
        common::close_mux(reopened).await;
    });
}

/// A read claim has no counterpart in the seed at all — no git state records who looked at a file —
/// so it cannot survive a restart. Without dropping reads this is refused by rule 19 instead, which
/// is the second, independent claim the reported transcript was carrying.
#[test]
fn a_read_claim_does_not_survive_a_restart() {
    mux_test!(fixture = Fixture::new("reconcile-read"), {
        commit(fixture.mux(), "main", "printf 'foo\\n' > note.txt").await;
        commit(fixture.mux(), "main", "cat note.txt").await;

        std::fs::remove_file(fixture.seed("note.txt")).expect("delete the seed file");
        fixture.finish_mux().await;

        let reopened = reopen(&fixture).await;
        let outcome = agent_write(&reopened, "bar").await;
        assert!(
            matches!(outcome, CmdOutcome::Committed { .. }),
            "no seed state corroborates a read, so no read claim survives: {outcome:?}"
        );
        common::close_mux(reopened).await;
    });
}
