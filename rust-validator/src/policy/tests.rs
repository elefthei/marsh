//! A miniature non-git policy, assembled only from kernel pieces.
//!
//! The git table is not the contract under test here: this file exists to pin that [`super::atoms`],
//! [`super::language`], [`super::rule`] and [`super::evaluate`] carry no git assumptions, by
//! building a policy over a different vocabulary and running it through the same loop.

use super::atoms::{action_is, principal_is, resource_is};
use super::decision::PolicyDecision;
use super::evaluate::decide;
use super::language::last_state_change;
use super::rule::{PolicyRule, forbid};
use crate::{Action, Comparison, Event, TestExpr};

/// Context of the miniature policy: the resource and who last edited it.
struct LastEditor {
    resource: String,
    editor: String,
}

/// The whole table: reading a resource whose last state change was a foreign edit is forbidden.
fn rules() -> Vec<PolicyRule<LastEditor>> {
    let setter = TestExpr::and([
        resource_is(Comparison::Eq),
        action_is(Action::Edit, Comparison::Eq),
        principal_is(Comparison::Neq),
    ]);
    let stable = TestExpr::or([
        resource_is(Comparison::Neq),
        action_is(Action::Read, Comparison::Eq),
    ]);
    vec![forbid(
        Action::Read,
        last_state_change(setter, stable),
        Box::new(|context| {
            let LastEditor { resource, editor } = context;
            (
                format!("{resource} was last edited by {editor}"),
                vec![format!("{editor} commit {resource}")],
            )
        }),
    )]
}

/// Builds the context for `candidate`: the last principal to edit its resource, or `"nobody"`.
fn context(history: &[Event], candidate: &Event) -> LastEditor {
    let editor = history
        .iter()
        .rfind(|event| event.resource == candidate.resource && matches!(event.action, Action::Edit))
        .map_or_else(
            || "nobody".to_string(),
            |event| event.principal.as_str().to_string(),
        );
    LastEditor {
        resource: candidate.resource.segments().join("/"),
        editor,
    }
}

#[test]
fn a_non_git_policy_reuses_the_kernel_loop() {
    let table = rules();
    let candidate = Event::new("bob", Action::Read, ["src", "x"]);

    let history: Vec<Event> = Vec::new();
    assert_eq!(
        decide(table, &history, &candidate, || context(
            &history, &candidate
        )),
        PolicyDecision::Grant,
    );

    let table = rules();
    let history = vec![Event::new("alice", Action::Edit, ["src", "x"])];
    assert_eq!(
        decide(table, &history, &candidate, || context(
            &history, &candidate
        )),
        PolicyDecision::Deny {
            failed_precondition: "src/x was last edited by alice".to_string(),
            allowed_fixes: vec!["alice commit src/x".to_string()],
        },
    );
}
