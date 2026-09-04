//! End-to-end tests for the validator prototype API.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

use rust_validator::{
    Action, AtomPattern, Bump, Comparison, CompileError, ComponentPattern, Decision, Event, Head,
    RegexExpr, Request, Rule, RuleMode, TestExpr, Validator,
};

fn event(principal: &str, action: Action, path: &[&str]) -> Event {
    Event::new(principal, action, path.to_vec())
}

fn request<M>(principal: &str, action: Action, path: &[&str], metadata: M) -> Request<M> {
    Request::new(event(principal, action, path), metadata)
}

fn same_actor_edit_before_stage() -> Rule {
    let principal = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Principal(ComponentPattern::variable("actor")),
    );
    let action = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Action(ComponentPattern::constant(Action::Edit)),
    );
    let resource = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Resource(ComponentPattern::variable("target")),
    );
    let event = RegexExpr::test(TestExpr::and([principal, action, resource]));
    let tail = RegexExpr::concat([RegexExpr::all(), event]);
    Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        tail,
    )
}

#[test]
fn require_rule_uses_only_committed_pre_candidate_history() {
    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder.add_rule(&same_actor_edit_before_stage()).unwrap();
    let mut validator = builder.finish();

    let denied = validator.check(request("alice", Action::Stage, &["src", "a.rs"], 1));
    assert!(matches!(denied, Decision::Denied(_)));
    assert!(validator.history().is_empty());

    let edit = validator.check(request("alice", Action::Edit, &["src", "a.rs"], 2));
    assert!(matches!(edit, Decision::Grant(grant) if grant.metadata == 2));

    let stage = validator.check(request("alice", Action::Stage, &["src", "a.rs"], 3));
    assert!(matches!(stage, Decision::Grant(grant) if grant.metadata == 3));
    assert_eq!(validator.history().len(), 2);
}

#[test]
fn forbid_rule_denies_duplicate_commit_without_mutating_history() {
    let action = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Action(ComponentPattern::constant(Action::commit("ship"))),
    );
    let resource = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Resource(ComponentPattern::variable("target")),
    );
    let matching_commit = RegexExpr::test(TestExpr::and([action, resource]));
    let tail = RegexExpr::concat([RegexExpr::all(), matching_commit, RegexExpr::all()]);
    let rule = Rule::new(
        RuleMode::Forbid,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::commit("ship")),
            ComponentPattern::variable("target"),
        ),
        tail,
    );

    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder.add_rule(&rule).unwrap();
    let mut validator = builder.finish();

    assert!(
        validator
            .check(request("alice", Action::commit("ship"), &["a"], ()))
            .is_grant()
    );
    let checkpoint = validator.checkpoint();

    let denied = validator.check(request("alice", Action::commit("ship"), &["a"], ()));
    assert!(matches!(denied, Decision::Denied(denial) if denial.mode == RuleMode::Forbid));
    assert_eq!(validator.checkpoint(), checkpoint);

    assert!(
        validator
            .check(request("alice", Action::commit("ship"), &["b"], ()))
            .is_grant()
    );
}

#[test]
fn complement_is_exact_over_complete_history() {
    let edit = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Action(ComponentPattern::constant(Action::Edit)),
    ));
    let contains_edit = RegexExpr::concat([RegexExpr::all(), edit, RegexExpr::all()]);
    let rule = Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        RegexExpr::complement(contains_edit),
    );

    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder.add_rule(&rule).unwrap();
    let mut validator = builder.finish();

    assert!(
        validator
            .check(request("alice", Action::Stage, &["a"], ()))
            .is_grant()
    );
    assert!(
        validator
            .check(request("bob", Action::Edit, &["elsewhere"], ()))
            .is_grant()
    );
    assert!(matches!(
        validator.check(request("alice", Action::Stage, &["a"], ())),
        Decision::Denied(_)
    ));
}

#[test]
fn construction_rejects_unbound_and_cross_component_variables() {
    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    let missing = builder.add_rule(&Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        RegexExpr::test(TestExpr::atom(
            Comparison::Eq,
            AtomPattern::Principal(ComponentPattern::variable("missing")),
        )),
    ));
    assert!(matches!(
        missing,
        Err(CompileError::UnboundVariable { name }) if name == "missing"
    ));

    let mut builder = Validator::builder(&arena);
    let conflict = builder.add_rule(&Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("same"),
            ComponentPattern::variable("same"),
            ComponentPattern::constant(["a"]),
        ),
        RegexExpr::all(),
    ));
    assert!(matches!(
        conflict,
        Err(CompileError::VariableComponentConflict { name }) if name == "same"
    ));
}

#[test]
fn source_expressions_are_revalidated_and_reusable_across_rules() {
    let shared_tail = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Principal(ComponentPattern::variable("actor")),
    ));

    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder
        .add_rule(&Rule::new(
            RuleMode::Require,
            Head::new(
                ComponentPattern::variable("actor"),
                ComponentPattern::constant(Action::Read),
                ComponentPattern::constant(["a"]),
            ),
            shared_tail.clone(),
        ))
        .unwrap();
    builder
        .add_rule(&Rule::new(
            RuleMode::Require,
            Head::new(
                ComponentPattern::variable("actor"),
                ComponentPattern::constant(Action::Diff),
                ComponentPattern::constant(["b"]),
            ),
            shared_tail,
        ))
        .unwrap();
}

#[test]
fn checkpoint_restores_append_only_history() {
    let arena = Bump::new();
    let mut validator = Validator::builder(&arena).finish();
    assert!(
        validator
            .check(request("alice", Action::Read, &["a"], ()))
            .is_grant()
    );
    let checkpoint = validator.checkpoint();
    assert!(
        validator
            .check(request("bob", Action::Diff, &["b"], ()))
            .is_grant()
    );
    validator.rollback(checkpoint);
    assert_eq!(validator.history(), &[event("alice", Action::Read, &["a"])]);
}
