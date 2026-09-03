//! The four canonical row-languages: what a resource's committed history says its state is.
//!
//! Each is a kernel tail shape instantiated with a git setter and the git notion of a
//! state-preserving event, [`read_only_not_r`].

use super::predicates::{
    commit_checkout_stash_on_r, edit_unstage_on_r_not_p, edit_unstage_on_r_on_p, not_read_on_r,
    read_on_r_not_p, read_only_not_r, stage_delete_on_r,
};
use crate::RegexExpr;
use crate::policy::language::{last_state_change, never_state_change};

/// Never any state-mutating `r` event, OR the last such event is commit/checkout/stash.
pub(super) fn clean_lang() -> RegexExpr {
    RegexExpr::union([
        never_state_change(read_only_not_r()),
        last_state_change(commit_checkout_stash_on_r(), read_only_not_r()),
    ])
}

/// The last state-mutating `r` event is a stage or a delete.
pub(super) fn staged_lang() -> RegexExpr {
    last_state_change(stage_delete_on_r(), read_only_not_r())
}

/// The last state-mutating `r` event is an edit/unstage by the acting principal.
pub(super) fn unstaged_self_lang() -> RegexExpr {
    last_state_change(edit_unstage_on_r_on_p(), read_only_not_r())
}

/// The last state-mutating `r` event is an edit/unstage by another principal.
pub(super) fn unstaged_other_lang() -> RegexExpr {
    last_state_change(edit_unstage_on_r_not_p(), read_only_not_r())
}

/// The last `read` of `r` was by a principal other than the acting one.
///
/// `last_state_change` pins that read as the LAST read of `r`: every later event must not be a read
/// of `r`, so only a newer read — by anyone — moves the claim. Settling `r` does not: an agent that
/// leaves `r` staged or committed/clean has relinquished it, and the next agent takes it over by
/// reading it, which is grantable in every row and every claim state.
pub(super) fn read_claimed_other_lang() -> RegexExpr {
    last_state_change(read_on_r_not_p(), not_read_on_r())
}
