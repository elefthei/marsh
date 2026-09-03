//! Canonical storage for resolved values, tests, regexes, and symbolic transitions.
//!
//! The store owns component resolution and syntax interners while borrowing only the caller's
//! arena. It has no active-rule, environment, candidate, event, substitution, history, or validator
//! backreferences. Compiler and evaluator functions receive the store explicitly.

use bumpalo::Bump;
use hashconsing::BHConsign;
use string_interner::DefaultSymbol;

use super::component::ComponentResolver;
use super::node::{RegexId, RegexKind, RegexNode, TestId, TestNode, TransitionId, TransitionNode};

/// Shared resolver and canonical-node store used by all rules in one validator.
pub(crate) struct CanonicalStore<'arena> {
    /// String interner plus arena allocation used to resolve component values.
    pub(super) resolver: ComponentResolver<'arena>,
    /// Canonical table for boolean event tests.
    pub(super) tests: BHConsign<'arena, TestNode<'arena>>,
    /// Canonical table for normalized regular-expression nodes.
    pub(super) regexes: BHConsign<'arena, RegexNode<'arena>>,
    /// Canonical table for normalized symbolic-transition nodes.
    pub(super) transitions: BHConsign<'arena, TransitionNode<'arena>>,
    /// Canonical true test.
    pub(super) test_true: TestId<'arena>,
    /// Canonical false test.
    pub(super) test_false: TestId<'arena>,
    /// Canonical empty language.
    pub(super) empty: RegexId<'arena>,
    /// Canonical universal language.
    pub(super) all: RegexId<'arena>,
    /// Canonical language containing only the empty history.
    pub(super) epsilon: RegexId<'arena>,
    /// Constant transition to the empty language.
    pub(super) transition_empty: TransitionId<'arena>,
    /// Constant transition to the universal language.
    pub(super) transition_all: TransitionId<'arena>,
    /// Constant transition to epsilon.
    pub(super) transition_epsilon: TransitionId<'arena>,
}

impl<'arena> CanonicalStore<'arena> {
    /// Creates a resolver, empty node tables, and algebraic constants.
    pub(crate) fn new(arena: &'arena Bump) -> Self {
        let resolver = ComponentResolver::new(arena);

        let mut tests = BHConsign::with_capacity(arena, 128);
        let test_true = tests.mk(TestNode::True);
        let test_false = tests.mk(TestNode::False);

        let mut regexes = BHConsign::with_capacity(arena, 1024);
        let empty = regexes.mk(RegexNode::new(RegexKind::Empty, false));
        let all = regexes.mk(RegexNode::new(RegexKind::All, true));
        let epsilon = regexes.mk(RegexNode::new(RegexKind::Epsilon, true));

        let mut transitions = BHConsign::with_capacity(arena, 1024);
        let transition_empty = transitions.mk(TransitionNode::Const(empty));
        let transition_all = transitions.mk(TransitionNode::Const(all));
        let transition_epsilon = transitions.mk(TransitionNode::Const(epsilon));

        Self {
            resolver,
            tests,
            regexes,
            transitions,
            test_true,
            test_false,
            empty,
            all,
            epsilon,
            transition_empty,
            transition_all,
            transition_epsilon,
        }
    }

    /// Interns a variable spelling through the black-box string interner.
    pub(super) fn intern_variable(&mut self, name: &str) -> DefaultSymbol {
        self.resolver.intern_string(name)
    }

    /// Number of canonical regex nodes, used to assert that derivative cycles stabilize.
    #[cfg(test)]
    pub(crate) fn regex_node_count(&self) -> usize {
        self.regexes.len()
    }

    /// Number of canonical transition nodes, used by normalization and cache tests.
    #[cfg(test)]
    pub(crate) fn transition_node_count(&self) -> usize {
        self.transitions.len()
    }
}
