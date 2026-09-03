//! What a git denial says: the failed precondition and the fixes that would unblock it.

use crate::{Action, Event, Resource};

/// Everything a git denial renders from: who acted, on what, who currently holds it dirty, and who
/// holds the outstanding read claim.
pub(super) struct GitContext {
    pub(super) principal: String,
    pub(super) resource: String,
    pub(super) owner: String,
    pub(super) reader: String,
}

/// Builds the context for `candidate`; called only when a rule is violated.
pub(super) fn git_context(history: &[Event], candidate: &Event) -> GitContext {
    GitContext {
        principal: candidate.principal.as_str().to_string(),
        resource: candidate.resource.segments().join("/"),
        owner: current_owner(history, &candidate.resource),
        reader: current_reader(history, &candidate.resource),
    }
}

/// Extracts the current owner of `resource` for diagnostics only — grant/deny is entirely
/// trace-policy driven and never consults this value. Folds to the principal of the most-recent
/// `edit`/`unstage` (reset by `stage`/`commit`/`checkout`/`stash`), or `"another principal"`.
fn current_owner(history: &[Event], resource: &Resource) -> String {
    let mut owner: Option<String> = None;
    for event in history.iter().filter(|event| &event.resource == resource) {
        match &event.action {
            Action::Edit | Action::Unstage => owner = Some(event.principal.as_str().to_string()),
            Action::Stage
            | Action::Delete
            | Action::Commit { .. }
            | Action::Checkout
            | Action::Stash => {
                owner = None;
            }
            Action::Read | Action::Diff | Action::History | Action::Clean => {}
        }
    }
    owner.unwrap_or_else(|| "another principal".to_string())
}

/// Extracts the principal holding the outstanding read claim on `resource`, for diagnostics only.
/// Folds to the principal of the most-recent `read`, or `"another principal"`. Its arms MUST stay
/// in lockstep with `not_read_on_r`.
fn current_reader(history: &[Event], resource: &Resource) -> String {
    let mut reader: Option<&str> = None;
    for event in history.iter().filter(|event| &event.resource == resource) {
        match &event.action {
            Action::Read => reader = Some(event.principal.as_str()),
            Action::Edit
            | Action::Stage
            | Action::Unstage
            | Action::Commit { .. }
            | Action::Checkout
            | Action::Stash
            | Action::Delete
            | Action::Diff
            | Action::History
            | Action::Clean => {}
        }
    }
    reader.map_or_else(|| "another principal".to_string(), str::to_string)
}

/// Owner-protection fixes shared by every foreign-owner contention cell.
pub(super) fn opf(p: &str, r: &str, q: &str) -> Vec<String> {
    vec![
        format!("{q} stage {r}"),
        format!("{q} checkout {r}"),
        format!("{q} stash {r}"),
        format!("{p} only reads, diffs, or histories {r}"),
    ]
}

/// Read-claim fixes shared by every outstanding-read contention cell. The claim moves only when
/// another principal reads `r`, so reading it is the only fix.
pub(super) fn rcf(p: &str, r: &str) -> Vec<String> {
    vec![format!("{p} read {r}")]
}
