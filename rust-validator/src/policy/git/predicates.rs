//! One-event [`TestExpr`] composites the git row-languages are assembled from.
//!
//! Each is a conjunction of kernel atoms over the head-bound principal `p` and resource `r`.

use crate::policy::atoms::{action_is, principal_is, resource_is};
use crate::{Action, Comparison, TestExpr};

/// An event that does not change `r`'s state: off-`r`, an observation of `r`, or a `clean` (a
/// no-op on tracked `r`).
pub(super) fn read_only_not_r() -> TestExpr {
    TestExpr::or([
        resource_is(Comparison::Neq),
        action_is(Action::Read, Comparison::Eq),
        action_is(Action::Diff, Comparison::Eq),
        action_is(Action::History, Comparison::Eq),
        action_is(Action::Clean, Comparison::Eq),
    ])
}

/// An on-`r` `stage`/`delete` event: both settle `r` into the staged row.
pub(super) fn stage_delete_on_r() -> TestExpr {
    TestExpr::and([
        resource_is(Comparison::Eq),
        TestExpr::or([
            action_is(Action::Stage, Comparison::Eq),
            action_is(Action::Delete, Comparison::Eq),
        ]),
    ])
}

/// An on-`r`, on-`p` `edit`/`unstage` event.
pub(super) fn edit_unstage_on_r_on_p() -> TestExpr {
    TestExpr::and([
        resource_is(Comparison::Eq),
        TestExpr::or([
            action_is(Action::Edit, Comparison::Eq),
            action_is(Action::Unstage, Comparison::Eq),
        ]),
        principal_is(Comparison::Eq),
    ])
}

/// An on-`r`, not-`p` `edit`/`unstage` event.
pub(super) fn edit_unstage_on_r_not_p() -> TestExpr {
    TestExpr::and([
        resource_is(Comparison::Eq),
        TestExpr::or([
            action_is(Action::Edit, Comparison::Eq),
            action_is(Action::Unstage, Comparison::Eq),
        ]),
        principal_is(Comparison::Neq),
    ])
}

/// An on-`r` event that is none of the eight enumerated actions, i.e. exactly
/// `{commit(any message), checkout, stash}`. The `Neq`-enumeration is message-agnostic by
/// construction, so it matches a commit regardless of its message payload.
pub(super) fn commit_checkout_stash_on_r() -> TestExpr {
    TestExpr::and([
        resource_is(Comparison::Eq),
        action_is(Action::Read, Comparison::Neq),
        action_is(Action::Diff, Comparison::Neq),
        action_is(Action::History, Comparison::Neq),
        action_is(Action::Edit, Comparison::Neq),
        action_is(Action::Stage, Comparison::Neq),
        action_is(Action::Unstage, Comparison::Neq),
        action_is(Action::Delete, Comparison::Neq),
        action_is(Action::Clean, Comparison::Neq),
    ])
}

/// An on-`r` `read` by a principal other than the acting one: the event that takes a read claim.
pub(super) fn read_on_r_not_p() -> TestExpr {
    TestExpr::and([
        resource_is(Comparison::Eq),
        action_is(Action::Read, Comparison::Eq),
        principal_is(Comparison::Neq),
    ])
}

/// Any event that is not a `read` of `r`. The claim on `r` moves only when someone reads it:
/// leaving `r` staged or committed/clean relinquishes it, but the next principal takes it over by
/// reading it.
pub(super) fn not_read_on_r() -> TestExpr {
    TestExpr::or([
        resource_is(Comparison::Neq),
        action_is(Action::Read, Comparison::Neq),
    ])
}
