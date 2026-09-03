//! Owned source language for declarative policy rules.
//!
//! Source expressions contain no arena references, canonical handles, compiler identities, or
//! rule-scope backreferences. A complete [`Rule`] is compiled in one pass with its variable
//! environment and canonical store supplied explicitly by the caller.

use crate::model::{Action, Principal, Resource};

/// Constant-or-variable pattern for one statically selected product component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComponentPattern<T, Variable = String> {
    /// Match one structurally equal component value.
    Constant(T),
    /// Bind or resolve a named component value.
    Variable(Variable),
}

impl<T> ComponentPattern<T, String> {
    /// Creates a constant pattern from a value convertible to `T`.
    pub fn constant(value: impl Into<T>) -> Self {
        Self::Constant(value.into())
    }

    /// Creates a named variable pattern.
    pub fn variable(name: impl Into<String>) -> Self {
        Self::Variable(name.into())
    }
}

/// Candidate-only pattern over the capability product.
///
/// Variables occurring here form the rule's variable environment. The tail may resolve exactly
/// those names in the same component domains.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Head {
    /// Principal constant or variable.
    pub principal: ComponentPattern<Principal>,
    /// Action constant or variable.
    pub action: ComponentPattern<Action>,
    /// Resource constant or variable.
    pub resource: ComponentPattern<Resource>,
}

impl Head {
    /// Creates a typed `(principal, action, resource)` head.
    pub fn new(
        principal: ComponentPattern<Principal>,
        action: ComponentPattern<Action>,
        resource: ComponentPattern<Resource>,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
        }
    }
}

/// Coordinate of the capability product.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    /// Principal coordinate.
    Principal,
    /// Action coordinate.
    Action,
    /// Resource coordinate.
    Resource,
}

/// Comparison applied by a one-event atom.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Comparison {
    /// Accept when the event component equals the constant or bound variable.
    Eq,
    /// Accept when the event component differs from the constant or bound variable.
    Neq,
}

impl std::ops::Not for Comparison {
    type Output = Self;

    fn not(self) -> Self::Output {
        match self {
            Self::Eq => Self::Neq,
            Self::Neq => Self::Eq,
        }
    }
}

/// Owned one-event component pattern.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AtomPattern {
    /// Test the event principal.
    Principal(ComponentPattern<Principal>),
    /// Test the event action.
    Action(ComponentPattern<Action>),
    /// Test the event resource.
    Resource(ComponentPattern<Resource>),
}

impl AtomPattern {
    /// Returns the product coordinate selected by this atom.
    pub fn component(&self) -> Component {
        match self {
            Self::Principal(_) => Component::Principal,
            Self::Action(_) => Component::Action,
            Self::Resource(_) => Component::Resource,
        }
    }
}

/// Owned boolean expression over one history event.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TestExpr {
    /// Predicate accepting every event.
    True,
    /// Predicate accepting no event.
    False,
    /// Component equality or disequality predicate.
    Atom {
        /// Comparison applied after resolving the component pattern.
        comparison: Comparison,
        /// Typed component pattern.
        pattern: AtomPattern,
    },
    /// Conjunction. Empty input is true.
    And(Vec<TestExpr>),
    /// Disjunction. Empty input is false.
    Or(Vec<TestExpr>),
}

impl TestExpr {
    /// Returns the predicate accepting every event.
    pub const fn true_test() -> Self {
        Self::True
    }

    /// Returns the predicate accepting no event.
    pub const fn false_test() -> Self {
        Self::False
    }

    /// Creates a component equality or disequality predicate.
    pub fn atom(comparison: Comparison, pattern: AtomPattern) -> Self {
        Self::Atom {
            comparison,
            pattern,
        }
    }

    /// Conjoins source predicates.
    pub fn and(tests: impl IntoIterator<Item = TestExpr>) -> Self {
        Self::And(tests.into_iter().collect())
    }

    /// Disjoins source predicates.
    pub fn or(tests: impl IntoIterator<Item = TestExpr>) -> Self {
        Self::Or(tests.into_iter().collect())
    }
}

/// Owned regular expression over complete event histories.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RegexExpr {
    /// Empty language.
    Empty,
    /// Universal language over complete histories.
    All,
    /// Language containing only the empty history.
    Epsilon,
    /// One-event language selected by a boolean source expression.
    Test(TestExpr),
    /// Set union. Empty input is the empty language.
    Union(Vec<RegexExpr>),
    /// Ordered language concatenation. Empty input is epsilon.
    Concat(Vec<RegexExpr>),
    /// Kleene star.
    Star(Box<RegexExpr>),
    /// Set intersection. Empty input is the universal language.
    Intersect(Vec<RegexExpr>),
    /// Whole-language complement.
    Not(Box<RegexExpr>),
}

impl RegexExpr {
    /// Returns the empty language.
    pub const fn empty() -> Self {
        Self::Empty
    }

    /// Returns the universal language.
    pub const fn all() -> Self {
        Self::All
    }

    /// Returns the language containing only the empty history.
    pub const fn epsilon() -> Self {
        Self::Epsilon
    }

    /// Lifts a one-event predicate into a one-event language.
    pub fn test(test: TestExpr) -> Self {
        Self::Test(test)
    }

    /// Constructs set union.
    pub fn union(regexes: impl IntoIterator<Item = RegexExpr>) -> Self {
        Self::Union(regexes.into_iter().collect())
    }

    /// Constructs ordered language concatenation.
    pub fn concat(regexes: impl IntoIterator<Item = RegexExpr>) -> Self {
        Self::Concat(regexes.into_iter().collect())
    }

    /// Constructs Kleene star.
    pub fn star(regex: RegexExpr) -> Self {
        Self::Star(Box::new(regex))
    }

    /// Constructs set intersection.
    pub fn intersect(regexes: impl IntoIterator<Item = RegexExpr>) -> Self {
        Self::Intersect(regexes.into_iter().collect())
    }

    /// Constructs whole-language complement.
    pub fn complement(regex: RegexExpr) -> Self {
        Self::Not(Box::new(regex))
    }
}

/// Relationship required between committed history and a matching rule tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleMode {
    /// Deny when committed history is outside the tail language.
    Require,
    /// Deny when committed history is inside the tail language.
    Forbid,
}

/// Complete owned source rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rule {
    /// Required or forbidden relationship to the tail language.
    pub mode: RuleMode,
    /// Candidate-only pattern declaring the rule's variables.
    pub head: Head,
    /// Complete-history language evaluated under candidate bindings.
    pub tail: RegexExpr,
}

impl Rule {
    /// Creates a declarative rule with no compiler or validator backreferences.
    pub fn new(mode: RuleMode, head: Head, tail: RegexExpr) -> Self {
        Self { mode, head, tail }
    }
}
