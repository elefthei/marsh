//! The central capability authority.
//!
//! All principals submit to one authority, and it holds one history. That history is what makes a
//! denial meaningful: `agent1 stage src/a.txt` is refused because of what `agent0` did to that path
//! earlier, and only a shared, ordered history can say so.
//!
//! [`GitPolicy`] is deliberately **not** stored in the authority. It borrows a `Bump` arena
//! (`GitPolicy<'arena>` holds `&'arena Bump`), and `Bump` is `!Sync`, so a retained policy could not
//! live behind a lock shared across principal threads. Each merge therefore builds its own arena and
//! policy: rule compilation is microseconds against a traced command's tens of milliseconds, so
//! nothing is lost and the authority stays `Send + Sync` without interior-mutability tricks.

use std::collections::HashMap;

use rust_validator::{Event, GitPolicy, PolicyDecision};

use crate::history::HistoryLog;
use crate::mux::CapDenial;

/// Everything the authority must hold consistently across principals.
pub(crate) struct AuthorityState {
    /// Committed capability history, in merge order. This is the policy's input.
    pub history: Vec<Event>,
    /// Sequence number of the transaction that last wrote each path: seed-relative, `/`-joined,
    /// `.git/` included. A command whose snapshot predates one of these lost the race for that
    /// path — which is how a git command that decided from `.git/index` loses to a transaction
    /// that rewrote it.
    pub generations: HashMap<String, u64>,
    /// Highest committed sequence number.
    pub seq: u64,
    /// Durable record of transactions, and the policy's memory across restarts.
    pub log: HistoryLog,
}

/// Decides a command's whole event set against the committed history.
///
/// Granted events are appended to `history` as the check proceeds, so an event is judged against
/// both the committed history *and* the prefix of its own command that has already been granted —
/// `printf x > p; git add -- p` must see its own edit when staging.
///
/// A denied event is recorded and **not** appended, and the scan continues. The caller therefore
/// learns every capability the command could not obtain, not merely the first, which is what makes
/// the denial actionable. The caller is responsible for truncating `history` back when any denial
/// occurred: a partially granted command must not leave a trace in the authority.
pub(crate) fn check_events(
    policy: &mut GitPolicy<'_>,
    history: &mut Vec<Event>,
    events: &[Event],
) -> Vec<CapDenial> {
    let mut denials = Vec::new();
    for event in events {
        match policy.decide(history, event) {
            PolicyDecision::Grant => history.push(event.clone()),
            PolicyDecision::Deny {
                failed_precondition,
                allowed_fixes,
            } => denials.push(CapDenial {
                event: event.clone(),
                failed_precondition,
                allowed_fixes,
            }),
        }
    }
    denials
}
