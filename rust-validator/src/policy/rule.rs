//! The rule/diagnostic pairing a policy table is built from, generalized over the per-policy
//! context a denial renders from.

use super::atoms::{PRINCIPAL_VAR, RESOURCE_VAR};
use crate::{Action, ComponentPattern, Head, RegexExpr, Rule, RuleMode};

/// Renders a violated rule's `(failed_precondition, allowed_fixes)` from the policy's context.
pub(super) type Diagnostic<C> = Box<dyn Fn(&C) -> (String, Vec<String>)>;

/// One trace-policy rule paired with the diagnostic its violation surfaces.
pub(super) struct PolicyRule<C> {
    pub(super) rule: Rule,
    pub(super) diagnostic: Diagnostic<C>,
}

/// Builds a `Forbid` rule with an action-constant head over the acting principal and resource.
pub(super) fn forbid<C>(
    action: Action,
    tail: RegexExpr,
    diagnostic: Diagnostic<C>,
) -> PolicyRule<C> {
    PolicyRule {
        rule: Rule::new(
            RuleMode::Forbid,
            Head::new(
                ComponentPattern::variable(PRINCIPAL_VAR),
                ComponentPattern::constant(action),
                ComponentPattern::variable(RESOURCE_VAR),
            ),
            tail,
        ),
        diagnostic,
    }
}
