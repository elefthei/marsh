//! Which of a git history's granted events are still active claims.
//!
//! The committed log is append-only: every grant ever made is in it, including the ones a later
//! grant superseded. What a consumer usually wants is the projection the policy itself decides
//! from — per resource, the last event that defines its row plus the last event that claims a
//! read — and that projection is computed here, once, for every consumer.
//!
//! The transitions match [`super::languages`]: `edit`/`unstage` leave a resource unstaged,
//! `stage`/`delete` leave it staged, `commit`/`checkout`/`stash` settle it, a `read` moves the read
//! claim, and `clean`/`diff`/`history` change neither. Resources are compared structurally, never
//! through their `/`-joined display text: `["a/b"]` and `["a", "b"]` are different resources.

use std::collections::HashMap;

use crate::{Action, Event, Resource};

/// The at-most-two events that are still active for one resource, as indices into a history.
#[derive(Clone, Copy, Default)]
pub(super) struct Claims {
    /// The latest event that defines the resource's row, if it is not settled.
    pub(super) row: Option<usize>,
    /// The latest event that claims a read of the resource.
    pub(super) read: Option<usize>,
}

/// Applies one event's transition to the claims of its resource.
const fn apply(claims: &mut Claims, action: &Action, index: usize) {
    match action {
        Action::Edit | Action::Unstage | Action::Stage | Action::Delete => claims.row = Some(index),
        Action::Commit { .. } | Action::Checkout | Action::Stash => claims.row = None,
        Action::Read => claims.read = Some(index),
        Action::Clean | Action::Diff | Action::History => {}
    }
}

/// Folds the claims `history` leaves on `resource` alone.
pub(super) fn claims_for(history: &[Event], resource: &Resource) -> Claims {
    let mut claims = Claims::default();
    for (index, event) in history.iter().enumerate() {
        if &event.resource == resource {
            apply(&mut claims, &event.action, index);
        }
    }
    claims
}

/// Indices of the events in `history` that are still active granted capabilities.
///
/// The returned indices are strictly increasing in the history's own order, and name at most one
/// row-defining event and one read event per structurally equal [`Resource`]. Resources whose
/// claims were all settled contribute nothing, and an empty history yields an empty vector.
///
/// Indices rather than clones: a caller that owns its history can retain the selected events by
/// moving them out of it.
pub fn active_git_capability_indices(history: &[Event]) -> Vec<usize> {
    let mut claims: HashMap<&Resource, Claims> = HashMap::new();
    for (index, event) in history.iter().enumerate() {
        apply(
            claims.entry(&event.resource).or_default(),
            &event.action,
            index,
        );
    }

    let mut indices: Vec<usize> = claims
        .into_values()
        .flat_map(|claims| [claims.row, claims.read])
        .flatten()
        .collect();
    indices.sort_unstable();
    indices
}
