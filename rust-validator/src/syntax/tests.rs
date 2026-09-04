//! White-box tests for source compilation, canonical reuse, and residual-state stability.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::HashSet;

use bumpalo::Bump;

use super::compile::compile_rule;
use super::evaluate::{DerivativeCache, accepts_direct, derive, derive_cached};
use super::node::{RegexKind, TestId, TransitionId, TransitionNode};
use super::source::{
    AtomPattern, Comparison, ComponentPattern, Head, RegexExpr, Rule, RuleMode, TestExpr,
};
use super::store::CanonicalStore;
use super::symbolic::{
    MAX_PRECOMPILED_ATOMS, MAX_PRECOMPILED_STATES, SymbolicDerivativeCache, SymbolicMatcher,
};
use crate::model::{Action, Event};

fn variable_head() -> Head {
    Head::new(
        ComponentPattern::variable("principal"),
        ComponentPattern::variable("action"),
        ComponentPattern::variable("resource"),
    )
}

fn rule(tail: RegexExpr) -> Rule {
    Rule::new(RuleMode::Require, variable_head(), tail)
}

fn action_test_expr_with(comparison: Comparison, action: Action) -> TestExpr {
    TestExpr::atom(
        comparison,
        AtomPattern::Action(ComponentPattern::constant(action)),
    )
}

fn action_test_expr(action: Action) -> TestExpr {
    action_test_expr_with(Comparison::Eq, action)
}

fn action_regex(action: Action) -> RegexExpr {
    RegexExpr::test(action_test_expr(action))
}

fn compiled_test<'arena>(store: &mut CanonicalStore<'arena>, source: TestExpr) -> TestId<'arena> {
    let regex = compile_rule(store, &rule(RegexExpr::test(source)))
        .unwrap()
        .tail;
    let RegexKind::Test(test) = regex.get().kind else {
        panic!("nonconstant test must compile to one test regex")
    };
    test
}

fn action_test<'arena>(store: &mut CanonicalStore<'arena>, action: Action) -> TestId<'arena> {
    compiled_test(store, action_test_expr(action))
}

fn assert_transition_normalized(transition: TransitionId<'_>) {
    match *transition.get() {
        TransitionNode::Const(_) => {}
        TransitionNode::If {
            test,
            then_transition,
            else_transition,
        } => {
            assert!(!matches!(
                *test.get(),
                super::node::TestNode::True | super::node::TestNode::False
            ));
            assert_ne!(then_transition, else_transition);
            assert_transition_normalized(then_transition);
            assert_transition_normalized(else_transition);
        }
        TransitionNode::Union(children) => {
            assert!(children.len() >= 2);
            assert!(children.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(
                children
                    .iter()
                    .all(|child| !matches!(child.get(), TransitionNode::Union(_)))
            );
            children
                .iter()
                .copied()
                .for_each(assert_transition_normalized);
        }
        TransitionNode::Intersect(_) | TransitionNode::Not(_) | TransitionNode::Append { .. } => {
            panic!("normalized transition must be DNF conditionals with regex leaves")
        }
    }
}

#[test]
fn aci_and_identity_normalization_reuse_handles() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);

    let left = RegexExpr::union([
        action_regex(Action::Read),
        RegexExpr::empty(),
        action_regex(Action::Edit),
        action_regex(Action::Read),
    ]);
    let left = compile_rule(&mut store, &rule(left)).unwrap().tail;

    let right = RegexExpr::union([action_regex(Action::Edit), action_regex(Action::Read)]);
    let right = compile_rule(&mut store, &rule(right)).unwrap().tail;
    assert_eq!(left, right);

    let concat = RegexExpr::concat([
        RegexExpr::epsilon(),
        action_regex(Action::Read),
        RegexExpr::epsilon(),
    ]);
    let concat = compile_rule(&mut store, &rule(concat)).unwrap().tail;
    let single = compile_rule(&mut store, &rule(action_regex(Action::Read)))
        .unwrap()
        .tail;
    assert_eq!(concat, single);

    let edit = action_regex(Action::Edit);
    let contradiction = RegexExpr::intersect([edit.clone(), RegexExpr::complement(edit)]);
    let contradiction = compile_rule(&mut store, &rule(contradiction)).unwrap().tail;
    assert_eq!(contradiction, store.empty);
}

#[test]
fn variable_names_share_string_symbols_across_rules() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let first = compile_rule(&mut store, &rule(RegexExpr::all())).unwrap();
    let second = compile_rule(&mut store, &rule(RegexExpr::all())).unwrap();

    let ComponentPattern::Variable(first_variable) = first.head.principal else {
        panic!("principal head pattern was not compiled as a variable")
    };
    let ComponentPattern::Variable(second_variable) = second.head.principal else {
        panic!("principal head pattern was not compiled as a variable")
    };
    assert_eq!(first_variable, second_variable);
    assert_eq!(store.resolver.string_count(), 3);
}

#[test]
fn derivative_cycle_returns_the_same_hashconsed_state() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let cycle = RegexExpr::star(RegexExpr::union([
        action_regex(Action::Read),
        action_regex(Action::Edit),
    ]));
    let runtime_rule = compile_rule(&mut store, &rule(cycle)).unwrap();

    let event = Event::new("alice", Action::Read, ["a"]);
    let substitution = runtime_rule
        .head
        .match_candidate(&mut store, &event)
        .unwrap();
    let before = store.regex_node_count();
    let mut state = runtime_rule.tail;
    for _ in 0..100 {
        state = derive(&mut store, state, &event, &substitution);
        assert_eq!(state, runtime_rule.tail);
    }
    assert_eq!(store.regex_node_count(), before);
}

#[test]
fn concrete_derivatives_reuse_equal_event_transitions() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let cycle = RegexExpr::star(RegexExpr::union([
        action_regex(Action::Read),
        action_regex(Action::Edit),
    ]));
    let runtime_rule = compile_rule(&mut store, &rule(cycle)).unwrap();
    let first_event = Event::new("alice", Action::Read, ["a"]);
    let equal_event = first_event.clone();
    let substitution = runtime_rule
        .head
        .match_candidate(&mut store, &first_event)
        .unwrap();
    let mut derivatives = DerivativeCache::new();

    let first = derive_cached(
        &mut store,
        runtime_rule.tail,
        &first_event,
        &substitution,
        &mut derivatives,
    );
    let entries = derivatives.len();
    assert!(entries > 1, "recursive derivatives must share the cache");

    let second = derive_cached(
        &mut store,
        runtime_rule.tail,
        &equal_event,
        &substitution,
        &mut derivatives,
    );
    assert_eq!(second, first);
    assert_eq!(derivatives.len(), entries);
}

#[test]
fn boolean_and_regex_normalization_matches_symbolic_specification() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);

    let absorbed = RegexExpr::test(TestExpr::and([
        action_test_expr(Action::Read),
        TestExpr::or([
            action_test_expr(Action::Read),
            action_test_expr(Action::Edit),
        ]),
    ]));
    let absorbed = compile_rule(&mut store, &rule(absorbed)).unwrap().tail;
    let read = compile_rule(&mut store, &rule(action_regex(Action::Read)))
        .unwrap()
        .tail;
    assert_eq!(absorbed, read);

    let contradiction = RegexExpr::test(TestExpr::and([
        action_test_expr(Action::Read),
        action_test_expr(Action::Edit),
    ]));
    let contradiction = compile_rule(&mut store, &rule(contradiction)).unwrap().tail;
    assert_eq!(contradiction, store.empty);

    let equality_implies_distinct_disequality = RegexExpr::test(TestExpr::and([
        action_test_expr(Action::Read),
        action_test_expr_with(Comparison::Neq, Action::Edit),
    ]));
    let equality_implies_distinct_disequality =
        compile_rule(&mut store, &rule(equality_implies_distinct_disequality))
            .unwrap()
            .tail;
    assert_eq!(equality_implies_distinct_disequality, read);

    let disequality_absorbs_distinct_equality = RegexExpr::test(TestExpr::or([
        action_test_expr(Action::Read),
        action_test_expr_with(Comparison::Neq, Action::Edit),
    ]));
    let expected_disequality =
        RegexExpr::test(action_test_expr_with(Comparison::Neq, Action::Edit));
    let disequality_absorbs_distinct_equality =
        compile_rule(&mut store, &rule(disequality_absorbs_distinct_equality))
            .unwrap()
            .tail;
    let expected_disequality = compile_rule(&mut store, &rule(expected_disequality))
        .unwrap()
        .tail;
    assert_eq!(disequality_absorbs_distinct_equality, expected_disequality);

    let distinct_disequalities_are_true = RegexExpr::test(TestExpr::or([
        action_test_expr_with(Comparison::Neq, Action::Read),
        action_test_expr_with(Comparison::Neq, Action::Edit),
    ]));
    let distinct_disequalities_are_true =
        compile_rule(&mut store, &rule(distinct_disequalities_are_true))
            .unwrap()
            .tail;
    let true_test = store.regex_test(store.test_true);
    assert_eq!(distinct_disequalities_are_true, true_test);

    let reversed_action_disequalities = RegexExpr::test(TestExpr::or([
        action_test_expr_with(Comparison::Neq, Action::Edit),
        action_test_expr_with(Comparison::Neq, Action::Read),
    ]));
    assert_eq!(
        compile_rule(&mut store, &rule(reversed_action_disequalities))
            .unwrap()
            .tail,
        true_test
    );

    let principal_disequalities = RegexExpr::test(TestExpr::or([
        TestExpr::atom(
            Comparison::Neq,
            AtomPattern::Principal(ComponentPattern::constant("alice")),
        ),
        TestExpr::atom(
            Comparison::Neq,
            AtomPattern::Principal(ComponentPattern::constant("bob")),
        ),
    ]));
    assert_eq!(
        compile_rule(&mut store, &rule(principal_disequalities))
            .unwrap()
            .tail,
        true_test
    );

    let resource_disequalities = RegexExpr::test(TestExpr::or([
        TestExpr::atom(
            Comparison::Neq,
            AtomPattern::Resource(ComponentPattern::constant(["a"])),
        ),
        TestExpr::atom(
            Comparison::Neq,
            AtomPattern::Resource(ComponentPattern::constant(["b"])),
        ),
    ]));
    assert_eq!(
        compile_rule(&mut store, &rule(resource_disequalities))
            .unwrap()
            .tail,
        true_test
    );

    let top_star = RegexExpr::star(RegexExpr::test(TestExpr::true_test()));
    let top_star = compile_rule(&mut store, &rule(top_star)).unwrap().tail;
    assert_eq!(top_star, store.all);
}

#[test]
fn compound_boolean_rewrites_are_construction_order_independent() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let principal_eq = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Principal(ComponentPattern::constant("alice")),
    );
    let principal_neq = TestExpr::atom(
        Comparison::Neq,
        AtomPattern::Principal(ComponentPattern::constant("alice")),
    );
    let action_eq = action_test_expr(Action::Read);
    let action_neq = action_test_expr_with(Comparison::Neq, Action::Read);
    let resource_eq = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Resource(ComponentPattern::constant(["a"])),
    );

    let compound = TestExpr::and([principal_eq.clone(), action_eq.clone()]);
    let complement = TestExpr::or([principal_neq, action_neq]);
    let contradiction = RegexExpr::test(TestExpr::and([compound.clone(), complement.clone()]));
    let tautology = RegexExpr::test(TestExpr::or([compound.clone(), complement]));
    assert_eq!(
        compile_rule(&mut store, &rule(contradiction)).unwrap().tail,
        store.empty
    );
    let true_test = store.regex_test(store.test_true);
    assert_eq!(
        compile_rule(&mut store, &rule(tautology)).unwrap().tail,
        true_test
    );

    let larger_conjunction =
        TestExpr::and([principal_eq.clone(), action_eq.clone(), resource_eq.clone()]);
    let absorbed_disjunction =
        RegexExpr::test(TestExpr::or([compound.clone(), larger_conjunction.clone()]));
    let expected_conjunction = compile_rule(&mut store, &rule(RegexExpr::test(compound.clone())))
        .unwrap()
        .tail;
    assert_eq!(
        compile_rule(&mut store, &rule(absorbed_disjunction))
            .unwrap()
            .tail,
        expected_conjunction
    );
    let reversed = RegexExpr::test(TestExpr::or([larger_conjunction, compound]));
    assert_eq!(
        compile_rule(&mut store, &rule(reversed)).unwrap().tail,
        expected_conjunction
    );

    let smaller_disjunction = TestExpr::or([principal_eq.clone(), action_eq.clone()]);
    let larger_disjunction = TestExpr::or([principal_eq, action_eq, resource_eq]);
    let absorbed_conjunction = RegexExpr::test(TestExpr::and([
        smaller_disjunction.clone(),
        larger_disjunction.clone(),
    ]));
    let expected_disjunction = compile_rule(
        &mut store,
        &rule(RegexExpr::test(smaller_disjunction.clone())),
    )
    .unwrap()
    .tail;
    assert_eq!(
        compile_rule(&mut store, &rule(absorbed_conjunction))
            .unwrap()
            .tail,
        expected_disjunction
    );
    let reversed = RegexExpr::test(TestExpr::and([larger_disjunction, smaller_disjunction]));
    assert_eq!(
        compile_rule(&mut store, &rule(reversed)).unwrap().tail,
        expected_disjunction
    );
}

#[test]
fn epsilon_set_rewrites_use_cached_nullability() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let nullable = RegexExpr::star(action_regex(Action::Read));
    let nullable_id = compile_rule(&mut store, &rule(nullable.clone()))
        .unwrap()
        .tail;
    let union = RegexExpr::union([RegexExpr::epsilon(), nullable.clone()]);
    let intersection = RegexExpr::intersect([RegexExpr::epsilon(), nullable]);
    assert_eq!(
        compile_rule(&mut store, &rule(union)).unwrap().tail,
        nullable_id
    );
    assert_eq!(
        compile_rule(&mut store, &rule(intersection)).unwrap().tail,
        store.epsilon
    );

    let nonnullable = action_regex(Action::Edit);
    let nonnullable_id = compile_rule(&mut store, &rule(nonnullable.clone()))
        .unwrap()
        .tail;
    let impossible = RegexExpr::intersect([RegexExpr::epsilon(), nonnullable.clone()]);
    let excludes_epsilon =
        RegexExpr::intersect([nonnullable, RegexExpr::complement(RegexExpr::epsilon())]);
    assert_eq!(
        compile_rule(&mut store, &rule(impossible)).unwrap().tail,
        store.empty
    );
    assert_eq!(
        compile_rule(&mut store, &rule(excludes_epsilon))
            .unwrap()
            .tail,
        nonnullable_id
    );
}

#[test]
fn mixed_regex_operators_group_all_test_operands() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let non_test = RegexExpr::star(action_regex(Action::Stage));

    let mixed_union = RegexExpr::union([
        action_regex(Action::Read),
        non_test.clone(),
        action_regex(Action::Edit),
    ]);
    let grouped_union = RegexExpr::union([
        RegexExpr::test(TestExpr::or([
            action_test_expr(Action::Read),
            action_test_expr(Action::Edit),
        ])),
        non_test.clone(),
    ]);
    let mixed_union = compile_rule(&mut store, &rule(mixed_union)).unwrap().tail;
    let grouped_union = compile_rule(&mut store, &rule(grouped_union)).unwrap().tail;
    assert_eq!(mixed_union, grouped_union);

    let reordered_union = RegexExpr::union([
        non_test.clone(),
        action_regex(Action::Edit),
        action_regex(Action::Read),
    ]);
    let reordered_union = compile_rule(&mut store, &rule(reordered_union))
        .unwrap()
        .tail;
    assert_eq!(reordered_union, grouped_union);

    let nested_union = RegexExpr::union([
        action_regex(Action::Read),
        RegexExpr::union([action_regex(Action::Edit), non_test.clone()]),
    ]);
    let nested_union = compile_rule(&mut store, &rule(nested_union)).unwrap().tail;
    assert_eq!(nested_union, grouped_union);

    let mixed_intersection = RegexExpr::intersect([
        action_regex(Action::Read),
        non_test,
        action_regex(Action::Edit),
    ]);
    let mixed_intersection = compile_rule(&mut store, &rule(mixed_intersection))
        .unwrap()
        .tail;
    assert_eq!(mixed_intersection, store.empty);

    let read = action_regex(Action::Read);
    let other = RegexExpr::star(action_regex(Action::Stage));
    let absorbed_union = RegexExpr::union([
        read.clone(),
        RegexExpr::intersect([read.clone(), other.clone()]),
    ]);
    let absorbed_intersection =
        RegexExpr::intersect([read.clone(), RegexExpr::union([read.clone(), other])]);
    let expected = compile_rule(&mut store, &rule(read)).unwrap().tail;
    assert_eq!(
        compile_rule(&mut store, &rule(absorbed_union))
            .unwrap()
            .tail,
        expected
    );
    assert_eq!(
        compile_rule(&mut store, &rule(absorbed_intersection))
            .unwrap()
            .tail,
        expected
    );
}

#[test]
fn transition_normalization_applies_dnf_and_path_cleaning() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let read_test = action_test(&mut store, Action::Read);
    let edit_test = action_test(&mut store, Action::Edit);
    let not_read = store.test_not(read_test);
    let read_regex = store.regex_test(read_test);

    assert_eq!(
        store.transition_union(vec![store.transition_empty, store.transition_epsilon]),
        store.transition_epsilon
    );
    assert_eq!(
        store.transition_intersect(vec![store.transition_all, store.transition_epsilon]),
        store.transition_epsilon
    );

    let nested = store.transition_if(not_read, store.transition_epsilon, store.transition_all);
    let cleaned = store.transition_if(read_test, nested, store.transition_empty);
    let expected = store.transition_if(read_test, store.transition_all, store.transition_empty);
    assert_eq!(cleaned, expected);

    let read_branch =
        store.transition_if(read_test, store.transition_epsilon, store.transition_empty);
    let edit_branch =
        store.transition_if(edit_test, store.transition_epsilon, store.transition_empty);
    assert_eq!(
        store.transition_intersect(vec![read_branch, edit_branch]),
        store.transition_empty
    );

    let disjunction = store.transition_union(vec![read_branch, edit_branch]);
    assert_eq!(
        store.transition_intersect(vec![disjunction, read_branch]),
        read_branch
    );
    assert_eq!(
        store.transition_append(store.transition_epsilon, &[read_regex]),
        store.transition_const(read_regex)
    );

    let complemented = store.transition_not(expected);
    let expected_complement =
        store.transition_if(not_read, store.transition_all, store.transition_empty);
    assert_eq!(complemented, expected_complement);
    assert_transition_normalized(complemented);
}

#[test]
fn mixed_transition_operators_group_all_constant_leaves() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let read_test = action_test(&mut store, Action::Read);
    let edit_test = action_test(&mut store, Action::Edit);
    let stage_test = action_test(&mut store, Action::Stage);
    let read = store.regex_test(read_test);
    let edit = store.regex_test(edit_test);
    let branch = store.transition_if(stage_test, store.transition_epsilon, store.transition_empty);
    let read_transition = store.transition_const(read);
    let edit_transition = store.transition_const(edit);

    let mixed = store.transition_union(vec![read_transition, branch, edit_transition]);
    let grouped_regex = store.regex_union(vec![read, edit]);
    let grouped_transition = store.transition_const(grouped_regex);
    let grouped = store.transition_union(vec![grouped_transition, branch]);
    assert_eq!(mixed, grouped);
    assert_eq!(
        store.transition_union(vec![edit_transition, read_transition, branch]),
        grouped
    );

    assert_eq!(
        store.transition_intersect(vec![read_transition, branch, edit_transition]),
        store.transition_empty
    );
}

#[test]
fn conditional_intersection_is_independent_of_grouping_and_order() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let principal = compiled_test(
        &mut store,
        TestExpr::atom(
            Comparison::Eq,
            AtomPattern::Principal(ComponentPattern::constant("alice")),
        ),
    );
    let action = action_test(&mut store, Action::Read);
    let resource = compiled_test(
        &mut store,
        TestExpr::atom(
            Comparison::Eq,
            AtomPattern::Resource(ComponentPattern::constant(["a"])),
        ),
    );

    let first = store.transition_if(principal, store.transition_epsilon, store.transition_all);
    let second = store.transition_if(action, store.transition_all, store.transition_epsilon);
    let third = store.transition_if(resource, store.transition_epsilon, store.transition_all);
    let canonical = store.transition_intersect(vec![first, second, third]);
    let first_second = store.transition_intersect(vec![first, second]);
    let second_third = store.transition_intersect(vec![second, third]);
    assert_eq!(
        store.transition_intersect(vec![first_second, third]),
        canonical
    );
    assert_eq!(
        store.transition_intersect(vec![first, second_third]),
        canonical
    );
    assert_eq!(
        store.transition_intersect(vec![third, first, second]),
        canonical
    );

    let first_one_sided =
        store.transition_if(principal, store.transition_epsilon, store.transition_empty);
    let second_one_sided =
        store.transition_if(action, store.transition_all, store.transition_empty);
    let canonical = store.transition_intersect(vec![first_one_sided, second_one_sided, third]);
    let one_sided = store.transition_intersect(vec![first_one_sided, second_one_sided]);
    let second_then_third = store.transition_intersect(vec![second_one_sided, third]);
    assert_eq!(
        store.transition_intersect(vec![one_sided, third]),
        canonical
    );
    assert_eq!(
        store.transition_intersect(vec![first_one_sided, second_then_third]),
        canonical
    );
    assert_eq!(
        store.transition_intersect(vec![third, second_one_sided, first_one_sided]),
        canonical
    );
}

#[test]
fn symbolic_derivatives_equal_concrete_derivatives_for_every_regex_form() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let read = action_regex(Action::Read);
    let edit = action_regex(Action::Edit);
    let cases = [
        RegexExpr::empty(),
        RegexExpr::all(),
        RegexExpr::epsilon(),
        read.clone(),
        RegexExpr::union([read.clone(), RegexExpr::star(edit.clone())]),
        RegexExpr::intersect([
            RegexExpr::star(read.clone()),
            RegexExpr::complement(RegexExpr::epsilon()),
        ]),
        RegexExpr::concat([
            RegexExpr::star(read.clone()),
            edit.clone(),
            RegexExpr::all(),
        ]),
        RegexExpr::star(RegexExpr::union([read.clone(), edit.clone()])),
        RegexExpr::complement(RegexExpr::concat([read, edit])),
    ];
    let candidate = Event::new("alice", Action::Read, ["a"]);

    for source in cases {
        let mut runtime_rule = compile_rule(&mut store, &rule(source)).unwrap();
        let substitution = runtime_rule
            .head
            .match_candidate(&mut store, &candidate)
            .unwrap();
        let mut derivatives = SymbolicDerivativeCache::new();
        let transition =
            SymbolicMatcher::new(&mut store, &mut derivatives).derivative(runtime_rule.tail);
        assert_transition_normalized(transition);
        for action in [Action::Read, Action::Edit, Action::Stage] {
            let event = Event::new("alice", action, ["a"]);
            let concrete = derive(&mut store, runtime_rule.tail, &event, &substitution);
            let symbolic = SymbolicMatcher::new(&mut store, &mut derivatives).evaluate(
                transition,
                &substitution,
                &event,
            );
            assert_eq!(symbolic, concrete);
        }
        let history = [
            Event::new("alice", Action::Read, ["a"]),
            Event::new("alice", Action::Edit, ["a"]),
            Event::new("alice", Action::Stage, ["a"]),
        ];
        let direct = accepts_direct(&mut store, runtime_rule.tail, history.iter(), &substitution);
        let symbolic = SymbolicMatcher::new(&mut store, &mut derivatives).accepts(
            runtime_rule.tail,
            history.iter(),
            &substitution,
        );
        assert_eq!(symbolic, direct);
        assert_eq!(
            runtime_rule.accepts_history(&mut store, history.iter(), &candidate),
            Some(direct)
        );
    }
}

#[test]
fn symbolic_instantiations_reuse_equal_truth_assignments() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let cycle = RegexExpr::star(RegexExpr::union([
        action_regex(Action::Read),
        action_regex(Action::Edit),
    ]));
    let runtime_rule = compile_rule(&mut store, &rule(cycle)).unwrap();
    let candidate = Event::new("alice", Action::Read, ["a"]);
    let same_event = candidate.clone();
    let equivalent_assignment_event = Event::new("bob", Action::Read, ["b"]);
    let distinct_assignment_event = Event::new("alice", Action::Edit, ["a"]);
    let substitution = runtime_rule
        .head
        .match_candidate(&mut store, &candidate)
        .unwrap();
    let mut derivatives = SymbolicDerivativeCache::new();
    let mut matcher = SymbolicMatcher::new(&mut store, &mut derivatives);
    let transition = matcher.derivative(runtime_rule.tail);

    let first = matcher.instantiate(transition, &substitution, &candidate);
    let entries = matcher.instantiation_count();
    let second = matcher.instantiate(transition, &substitution, &same_event);
    assert_eq!(second, first);
    assert_eq!(matcher.instantiation_count(), entries);
    let equivalent = matcher.instantiate(transition, &substitution, &equivalent_assignment_event);
    assert_eq!(equivalent, first);
    assert_eq!(matcher.instantiation_count(), entries);

    let expected = matcher.evaluate(transition, &substitution, &distinct_assignment_event);
    let distinct = matcher.instantiate(transition, &substitution, &distinct_assignment_event);
    assert_eq!(distinct, expected);
    assert_eq!(matcher.instantiation_count(), entries + 1);
}

#[test]
fn symbolic_derivative_cache_is_shared_across_events_and_bindings() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let tail = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Action(ComponentPattern::variable("action")),
    ));
    let mut runtime_rule = compile_rule(&mut store, &rule(tail)).unwrap();
    let read = Event::new("alice", Action::Read, ["a"]);
    let edit = Event::new("bob", Action::Edit, ["b"]);
    let derivatives = runtime_rule.derivative_count();
    let precompiled = runtime_rule.precompiled_transition_count();
    let transitions = store.transition_node_count();
    assert!(derivatives > 0);
    assert!(precompiled > 0);

    assert_eq!(
        runtime_rule.accepts_history(&mut store, std::slice::from_ref(&read), &read),
        Some(true)
    );
    assert_eq!(runtime_rule.derivative_count(), derivatives);
    assert_eq!(runtime_rule.precompiled_transition_count(), precompiled);
    assert_eq!(store.transition_node_count(), transitions);

    assert_eq!(
        runtime_rule.accepts_history(&mut store, std::slice::from_ref(&edit), &edit),
        Some(true)
    );
    assert_eq!(runtime_rule.derivative_count(), derivatives);
    assert_eq!(store.transition_node_count(), transitions);
}

#[test]
fn wide_symbolic_alphabet_uses_exact_transition_fallback() {
    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let alternatives = (0..=MAX_PRECOMPILED_ATOMS)
        .map(|index| {
            RegexExpr::test(TestExpr::atom(
                Comparison::Eq,
                AtomPattern::Principal(ComponentPattern::constant(format!("principal-{index}"))),
            ))
        })
        .collect::<Vec<_>>();
    let mut runtime_rule = compile_rule(&mut store, &rule(RegexExpr::union(alternatives))).unwrap();
    assert_eq!(runtime_rule.precompiled_transition_count(), 0);

    let candidate = Event::new("candidate", Action::Edit, ["target"]);
    let matching = Event::new("principal-7", Action::Read, ["other"]);
    let nonmatching = Event::new("outside-minterms", Action::Read, ["other"]);
    assert_eq!(
        runtime_rule.accepts_history(&mut store, [&matching], &candidate),
        Some(true)
    );
    assert_eq!(
        runtime_rule.accepts_history(&mut store, [&nonmatching], &candidate),
        Some(false)
    );
}

fn regex_dag_node_count(root: super::node::RegexId<'_>) -> usize {
    let mut visited = HashSet::new();
    let mut pending = vec![root];
    while let Some(regex) = pending.pop() {
        if !visited.insert(regex) {
            continue;
        }
        match regex.get().kind {
            RegexKind::Empty | RegexKind::All | RegexKind::Epsilon | RegexKind::Test(_) => {}
            RegexKind::Union(children)
            | RegexKind::Concat(children)
            | RegexKind::Intersect(children) => pending.extend_from_slice(children),
            RegexKind::Star(inner) | RegexKind::Not(inner) => pending.push(inner),
        }
    }
    visited.len()
}

#[test]
fn suffix_window_policy_residual_grows_after_every_matching_event() {
    const WINDOW: usize = 8;

    let arena = Bump::new();
    let mut store = CanonicalStore::new(&arena);
    let any_event = RegexExpr::test(TestExpr::true_test());
    let factors = std::iter::once(RegexExpr::all())
        .chain(std::iter::once(action_regex(Action::Read)))
        .chain(std::iter::repeat_n(any_event, WINDOW + 1));
    let runtime_rule = compile_rule(&mut store, &rule(RegexExpr::concat(factors))).unwrap();
    assert_eq!(
        runtime_rule.precompiled_transition_count(),
        MAX_PRECOMPILED_STATES,
        "stress policy must exercise the per-rule DFA state budget"
    );
    let candidate = Event::new("candidate", Action::Stage, ["target"]);
    let substitution = runtime_rule
        .head
        .match_candidate(&mut store, &candidate)
        .unwrap();
    let event = Event::new("history", Action::Read, ["event"]);
    let mut derivatives = SymbolicDerivativeCache::new();
    let mut matcher = SymbolicMatcher::new(&mut store, &mut derivatives);
    let mut state = runtime_rule.tail;
    let mut sizes = Vec::with_capacity(WINDOW + 1);
    sizes.push(regex_dag_node_count(state));
    for _ in 0..WINDOW {
        let transition = matcher.derivative(state);
        state = matcher.instantiate(transition, &substitution, &event);
        sizes.push(regex_dag_node_count(state));
    }

    assert!(
        sizes.windows(2).all(|pair| pair[0] < pair[1]),
        "residual DAG sizes must grow at every step: {sizes:?}"
    );
}
