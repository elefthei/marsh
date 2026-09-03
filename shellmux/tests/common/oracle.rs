//! The no-surprise oracle: a simulated repository that decides, from modelled content, whether a
//! validated trace ever made one principal's knowledge of a resource wrong behind its back.
//!
//! Real git is this suite's ground truth for legality — the serial replayer in `common/mod.rs`
//! re-executes every merged command and the seed is compared against it — but it cannot decide
//! surprise: it has no notion of principals or of what a principal has seen. This module, copied
//! from the validator fork's fuzz harness, supplies that ground truth instead.
//! A content change is `worktree_after != worktree_before`, derived from the simulation rather than
//! from a list of which actions "are writes", which is what keeps the oracle independent of the
//! policy it checks.

use std::collections::BTreeMap;
use std::fmt;

use shellmux::{Action, Event, Principal, Resource};

/// A working-tree blob. `0` is the seed commit's content and every `edit` at history index `i`
/// stamps `i + 1`, so no write can reproduce an earlier blob.
type Version = u64;

/// Modelled repository state for one resource. The index is not modelled: no transition reads it,
/// so it cannot change what a principal would observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileState {
    worktree: Option<Version>,
    head: Option<Version>,
}

impl FileState {
    /// The seed commit, in which every pooled path exists and is committed.
    const SEEDED: Self = Self {
        worktree: Some(0),
        head: Some(0),
    };

    /// Applies the event at `index` and returns the state after it.
    fn apply(self, action: &Action, index: usize) -> Self {
        match action {
            Action::Edit => Self {
                worktree: Some(index as Version + 1),
                ..self
            },
            Action::Delete => Self {
                worktree: None,
                ..self
            },
            Action::Commit { .. } => Self {
                head: self.worktree,
                ..self
            },
            Action::Checkout | Action::Stash => Self {
                worktree: self.head,
                ..self
            },
            Action::Stage
            | Action::Unstage
            | Action::Clean
            | Action::Read
            | Action::Diff
            | Action::History => self,
        }
    }
}

/// A no-surprise violation: `principal` rewrote `resource`'s working-tree content and made another
/// principal's knowledge of it wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surprise {
    /// Index in the granted history of the content-changing event.
    pub index: usize,
    /// Principal that changed the content.
    pub principal: String,
    /// The content-changing action, rendered by `Action`'s `Display`.
    pub action: String,
    /// `/`-joined resource path.
    pub resource: String,
    /// Principal whose remembered content the change falsified.
    pub surprised: String,
    /// Index at which that principal last learned the content.
    pub learned_at: usize,
}

impl fmt::Display for Surprise {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "step {}: {} {} {}, which {} had last seen at step {}",
            self.index, self.principal, self.action, self.resource, self.surprised, self.learned_at,
        )
    }
}

/// Replays `history` through the modelled repository. Returns the first violation and how many
/// events acted on a resource another principal held an outstanding view of. Both answers come from
/// one fold so the two public entry points can never drift apart.
///
/// `BTreeMap`, not `HashMap`: with several surprised principals the reported one must be
/// deterministic.
fn replay(history: &[Event]) -> (Option<Surprise>, usize) {
    let mut files: BTreeMap<&Resource, FileState> = BTreeMap::new();
    let mut views: BTreeMap<(&Principal, &Resource), (Option<Version>, usize)> = BTreeMap::new();
    let mut first: Option<Surprise> = None;
    let mut contended = 0usize;

    for (index, event) in history.iter().enumerate() {
        let before = *files.get(&event.resource).unwrap_or(&FileState::SEEDED);
        let after = before.apply(&event.action, index);

        if views.keys().any(|&(principal, resource)| {
            resource == &event.resource && principal != &event.principal
        }) {
            contended += 1;
        }

        if after.worktree != before.worktree && first.is_none() {
            for (&(principal, resource), &(remembered, learned_at)) in &views {
                if resource == &event.resource
                    && principal != &event.principal
                    && remembered == before.worktree
                {
                    first = Some(Surprise {
                        index,
                        principal: event.principal.as_str().to_string(),
                        action: event.action.to_string(),
                        resource: event.resource.to_string(),
                        surprised: principal.as_str().to_string(),
                        learned_at,
                    });
                    break;
                }
            }
        }

        // A read hands the resource over: every other principal's view of it is superseded.
        if matches!(event.action, Action::Read) {
            views.retain(|&(_, resource), _| resource != &event.resource);
        }
        match &event.action {
            Action::Read | Action::Edit => {
                views.insert((&event.principal, &event.resource), (after.worktree, index));
            }
            Action::Stage
            | Action::Delete
            | Action::Commit { .. }
            | Action::Checkout
            | Action::Stash => {
                views.remove(&(&event.principal, &event.resource));
            }
            Action::Unstage | Action::Diff | Action::History | Action::Clean => {}
        }
        files.insert(&event.resource, after);
    }
    (first, contended)
}

/// The first no-surprise violation in `history`, or `None` when the trace has the property.
pub fn no_surprise_violation(history: &[Event]) -> Option<Surprise> {
    replay(history).0
}

/// How many events in `history` acted on a resource another principal held an outstanding view of —
/// the interleavings the property is about. A deterministic sweep whose total is zero would pass
/// [`no_surprise_violation`] vacuously.
pub fn contended_events(history: &[Event]) -> usize {
    replay(history).1
}
