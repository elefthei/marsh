//! The two tail shapes a state-machine policy classifies a resource's history with.

use crate::{RegexExpr, TestExpr};

/// The last state-changing event on the head resource is `setter`.
///
/// `Concat[All, T(setter), Star(T(stable))]` pins `setter` to the LAST state change: `accepts`
/// explores every split point, and the trailing `Star` forbids any later change.
pub(super) fn last_state_change(setter: TestExpr, stable: TestExpr) -> RegexExpr {
    RegexExpr::concat([
        RegexExpr::all(),
        RegexExpr::test(setter),
        RegexExpr::star(RegexExpr::test(stable)),
    ])
}

/// No state-changing event at all: every event in history is `stable`.
pub(super) fn never_state_change(stable: TestExpr) -> RegexExpr {
    RegexExpr::star(RegexExpr::test(stable))
}
