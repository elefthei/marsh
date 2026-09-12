//! What a git denial says: the failed precondition and the fixes that would unblock it.

use super::capabilities::claims_for;
use crate::{Action, Event};

/// Everything a git denial renders from: who acted, on what, who currently holds it dirty, and who
/// holds the outstanding read claim.
pub(super) struct GitContext {
    pub(super) principal: String,
    pub(super) resource: String,
    pub(super) owner: String,
    pub(super) reader: String,
}

/// Builds the context for `candidate`; called only when a rule is violated.
///
/// Owner and reader are read off the shared active-capability projection, so a diagnostic can
/// never disagree with the claims the policy itself decides from. The row principal is an owner
/// only while the row is unstaged: a staged row is owned by nobody, which the existing
/// `"another principal"` wording already says.
pub(super) fn git_context(history: &[Event], candidate: &Event) -> GitContext {
    let claims = claims_for(history, &candidate.resource);
    let owner = claims
        .row
        .and_then(|index| history.get(index))
        .filter(|event| matches!(event.action, Action::Edit | Action::Unstage))
        .map(|event| event.principal.as_str().to_string());
    let reader = claims
        .read
        .and_then(|index| history.get(index))
        .map(|event| event.principal.as_str().to_string());

    GitContext {
        principal: candidate.principal.as_str().to_string(),
        resource: candidate.resource.segments().join("/"),
        owner: owner.unwrap_or_else(|| "another principal".to_string()),
        reader: reader.unwrap_or_else(|| "another principal".to_string()),
    }
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
