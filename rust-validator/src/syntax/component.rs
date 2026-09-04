//! Component-specific compilation, matching, and typed substitution storage.
//!
//! [`ComponentDomain`] associates each model component with one resolved representation and defines
//! how that value enters and leaves the heterogeneous [`CandidateSubstitution`] range.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

use bumpalo::Bump;
use string_interner::{DefaultStringInterner, DefaultSymbol};

use crate::model::{Action, Event, Principal, Resource};

use super::source::{Component, ComponentPattern};

/// Resolved action value using string-interner symbols for commit messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum ResolvedAction {
    Read,
    Edit,
    Stage,
    Unstage,
    Commit(Option<DefaultSymbol>),
    Checkout,
    Stash,
    Delete,
    Clean,
    Diff,
    History,
}

/// Resolved resource value represented as an arena-backed sequence of segment symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ResolvedResource<'arena>(&'arena [DefaultSymbol]);

/// Resolves model values using a black-box string interner and arena allocation.
pub(super) struct ComponentResolver<'arena> {
    arena: &'arena Bump,
    strings: DefaultStringInterner,
}

impl<'arena> ComponentResolver<'arena> {
    /// Creates a resolver backed by `arena`.
    pub(super) fn new(arena: &'arena Bump) -> Self {
        Self {
            arena,
            strings: DefaultStringInterner::with_capacity(128),
        }
    }

    /// Interns one string through the black-box string interner.
    pub(super) fn intern_string(&mut self, value: &str) -> DefaultSymbol {
        self.strings.get_or_intern(value)
    }

    /// Resolves one ordered resource sequence after interning every segment string.
    pub(super) fn resolve_resource(&mut self, value: &Resource) -> ResolvedResource<'arena> {
        let segments: Vec<DefaultSymbol> = value
            .segments()
            .iter()
            .map(|segment| self.intern_string(segment))
            .collect();
        ResolvedResource(self.arena.alloc_slice_copy(&segments))
    }

    /// Number of distinct interned strings, used to verify value reuse.
    #[cfg(test)]
    pub(super) fn string_count(&self) -> usize {
        self.strings.len()
    }
}

/// Heterogeneous resolved value stored in a candidate substitution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum ResolvedValue<'arena> {
    Principal(<Principal as ComponentDomain<'arena>>::Resolved),
    Action(<Action as ComponentDomain<'arena>>::Resolved),
    Resource(<Resource as ComponentDomain<'arena>>::Resolved),
}

/// Resolved candidate values assigned to variables during one rule evaluation.
#[derive(Debug, Default)]
pub(crate) struct CandidateSubstitution<'arena> {
    values: HashMap<DefaultSymbol, ResolvedValue<'arena>>,
}

impl<'arena> CandidateSubstitution<'arena> {
    /// Creates one partial substitution assignment.
    pub(super) fn singleton(variable: DefaultSymbol, value: ResolvedValue<'arena>) -> Self {
        Self {
            values: HashMap::from([(variable, value)]),
        }
    }

    /// Returns a new compatible union without modifying either input substitution.
    pub(super) fn merge(&self, other: &Self) -> Option<Self> {
        if other.values.iter().any(|(variable, value)| {
            self.values
                .get(variable)
                .is_some_and(|existing| existing != value)
        }) {
            return None;
        }
        let mut values = self.values.clone();
        values.extend(other.values.clone());
        Some(Self { values })
    }
}

/// Resolves and compares one capability-product component domain.
pub(super) trait ComponentDomain<'arena>: Sized + Eq {
    /// Product coordinate occupied by this component.
    const COMPONENT: Component;

    /// Variable-free representation produced by resolution.
    type Resolved: Clone + Copy + Debug + PartialEq + Eq + Hash;

    /// Resolves a model value into the representation shared by constants and substitutions.
    fn resolve(resolver: &mut ComponentResolver<'arena>, value: &Self) -> Self::Resolved;

    /// Injects one domain value into the heterogeneous substitution range.
    fn inject(value: Self::Resolved) -> ResolvedValue<'arena>;

    /// Projects this domain from the heterogeneous substitution range.
    fn project(value: ResolvedValue<'arena>) -> Option<Self::Resolved>;
}

impl<'arena> ComponentDomain<'arena> for Principal {
    const COMPONENT: Component = Component::Principal;
    type Resolved = DefaultSymbol;

    fn resolve(resolver: &mut ComponentResolver<'arena>, value: &Self) -> Self::Resolved {
        resolver.intern_string(value.as_str())
    }

    fn inject(value: Self::Resolved) -> ResolvedValue<'arena> {
        ResolvedValue::Principal(value)
    }

    fn project(value: ResolvedValue<'arena>) -> Option<Self::Resolved> {
        match value {
            ResolvedValue::Principal(value) => Some(value),
            _ => None,
        }
    }
}

impl<'arena> ComponentDomain<'arena> for Action {
    const COMPONENT: Component = Component::Action;
    type Resolved = ResolvedAction;

    fn resolve(resolver: &mut ComponentResolver<'arena>, value: &Self) -> Self::Resolved {
        match value {
            Self::Read => ResolvedAction::Read,
            Self::Edit => ResolvedAction::Edit,
            Self::Stage => ResolvedAction::Stage,
            Self::Unstage => ResolvedAction::Unstage,
            Self::Commit { message } => ResolvedAction::Commit(
                message
                    .as_deref()
                    .map(|message| resolver.intern_string(message)),
            ),
            Self::Checkout => ResolvedAction::Checkout,
            Self::Stash => ResolvedAction::Stash,
            Self::Delete => ResolvedAction::Delete,
            Self::Clean => ResolvedAction::Clean,
            Self::Diff => ResolvedAction::Diff,
            Self::History => ResolvedAction::History,
        }
    }

    fn inject(value: Self::Resolved) -> ResolvedValue<'arena> {
        ResolvedValue::Action(value)
    }

    fn project(value: ResolvedValue<'arena>) -> Option<Self::Resolved> {
        match value {
            ResolvedValue::Action(value) => Some(value),
            _ => None,
        }
    }
}

impl<'arena> ComponentDomain<'arena> for Resource {
    const COMPONENT: Component = Component::Resource;
    type Resolved = ResolvedResource<'arena>;

    fn resolve(resolver: &mut ComponentResolver<'arena>, value: &Self) -> Self::Resolved {
        resolver.resolve_resource(value)
    }

    fn inject(value: Self::Resolved) -> ResolvedValue<'arena> {
        ResolvedValue::Resource(value)
    }

    fn project(value: ResolvedValue<'arena>) -> Option<Self::Resolved> {
        match value {
            ResolvedValue::Resource(value) => Some(value),
            _ => None,
        }
    }
}

/// Compiled pattern for one statically selected component domain.
pub(super) type CompiledPattern<'arena, ComponentType> =
    ComponentPattern<<ComponentType as ComponentDomain<'arena>>::Resolved, DefaultSymbol>;

/// Compiled, structurally hashable atom pattern stored in [`TestNode`](super::node::TestNode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum CompiledAtomPattern<'arena> {
    Principal(CompiledPattern<'arena, Principal>),
    Action(CompiledPattern<'arena, Action>),
    Resource(CompiledPattern<'arena, Resource>),
}

/// Variable-free atom produced by applying a substitution to a compiled atom pattern.
pub(super) enum ResolvedAtom<'arena> {
    Principal(<Principal as ComponentDomain<'arena>>::Resolved),
    Action(<Action as ComponentDomain<'arena>>::Resolved),
    Resource(<Resource as ComponentDomain<'arena>>::Resolved),
}

impl<'arena> ResolvedAtom<'arena> {
    /// Resolves the event component and compares it with this resolved atom value.
    pub(super) fn matches(&self, resolver: &mut ComponentResolver<'arena>, event: &Event) -> bool {
        match self {
            Self::Principal(expected) => {
                *expected == Principal::resolve(resolver, &event.principal)
            }
            Self::Action(expected) => *expected == Action::resolve(resolver, &event.action),
            Self::Resource(expected) => *expected == Resource::resolve(resolver, &event.resource),
        }
    }
}

impl<Resolved> ComponentPattern<Resolved, DefaultSymbol>
where
    Resolved: Copy,
{
    /// Applies a candidate substitution in the selected component domain.
    pub(super) fn subst<'arena, ComponentType>(
        &self,
        substitution: &CandidateSubstitution<'arena>,
    ) -> Option<Resolved>
    where
        ComponentType: ComponentDomain<'arena, Resolved = Resolved>,
    {
        match self {
            Self::Constant(expected) => Some(*expected),
            Self::Variable(variable) => substitution
                .values
                .get(variable)
                .copied()
                .and_then(ComponentType::project),
        }
    }
}

impl<'arena> CompiledAtomPattern<'arena> {
    /// Applies candidate bindings and returns a variable-free atom.
    pub(super) fn subst(
        &self,
        substitution: &CandidateSubstitution<'arena>,
    ) -> Option<ResolvedAtom<'arena>> {
        match self {
            Self::Principal(pattern) => pattern
                .subst::<Principal>(substitution)
                .map(ResolvedAtom::Principal),
            Self::Action(pattern) => pattern
                .subst::<Action>(substitution)
                .map(ResolvedAtom::Action),
            Self::Resource(pattern) => pattern
                .subst::<Resource>(substitution)
                .map(ResolvedAtom::Resource),
        }
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn variable(resolver: &mut ComponentResolver<'_>, name: &str) -> DefaultSymbol {
        resolver.intern_string(name)
    }

    #[test]
    fn component_resolver_unifies_constants_and_candidates() {
        let arena = Bump::new();
        let mut resolver = ComponentResolver::new(&arena);

        let constant_principal = Principal::resolve(&mut resolver, &Principal::new("alice"));
        let candidate_principal = Principal::resolve(&mut resolver, &Principal::new("alice"));
        assert_eq!(constant_principal, candidate_principal);

        let constant_resource = Resource::resolve(&mut resolver, &Resource::new(["src", "a.rs"]));
        let candidate_resource = Resource::resolve(&mut resolver, &Resource::new(["src", "a.rs"]));
        assert_eq!(constant_resource, candidate_resource);

        let constant_action = Action::resolve(&mut resolver, &Action::commit("ship"));
        let candidate_action = Action::resolve(&mut resolver, &Action::commit("ship"));
        assert_eq!(constant_action, candidate_action);
    }

    #[test]
    fn merge_combines_partial_head_substitutions() {
        let arena = Bump::new();
        let mut resolver = ComponentResolver::new(&arena);
        let actor = variable(&mut resolver, "actor");
        let operation = variable(&mut resolver, "operation");
        let alice = resolver.intern_string("alice");
        let same_alice = resolver.intern_string("alice");
        let read = ResolvedAction::Read;

        let mut left = CandidateSubstitution::default();
        left.values.insert(actor, ResolvedValue::Principal(alice));
        let mut right = CandidateSubstitution::default();
        right
            .values
            .insert(actor, ResolvedValue::Principal(same_alice));
        right.values.insert(operation, ResolvedValue::Action(read));

        let merged = left.merge(&right).expect("bindings agree");
        assert_eq!(
            merged.values.get(&actor),
            Some(&ResolvedValue::Principal(alice))
        );
        assert_eq!(
            merged.values.get(&operation),
            Some(&ResolvedValue::Action(read))
        );
        assert!(!left.values.contains_key(&operation));
        assert!(right.values.contains_key(&operation));
    }

    #[test]
    fn merge_rejects_conflicting_same_domain_bindings() {
        let arena = Bump::new();
        let mut resolver = ComponentResolver::new(&arena);
        let actor = variable(&mut resolver, "actor");
        let alice = resolver.intern_string("alice");
        let bob = resolver.intern_string("bob");

        let mut left = CandidateSubstitution::default();
        left.values.insert(actor, ResolvedValue::Principal(alice));
        let mut right = CandidateSubstitution::default();
        right.values.insert(actor, ResolvedValue::Principal(bob));

        assert!(left.merge(&right).is_none());
        assert_eq!(
            left.values.get(&actor),
            Some(&ResolvedValue::Principal(alice))
        );
    }

    #[test]
    fn merge_rejects_cross_domain_bindings() {
        let arena = Bump::new();
        let mut resolver = ComponentResolver::new(&arena);
        let value = variable(&mut resolver, "value");
        let alice = resolver.intern_string("alice");

        let mut left = CandidateSubstitution::default();
        left.values.insert(value, ResolvedValue::Principal(alice));
        let mut right = CandidateSubstitution::default();
        right
            .values
            .insert(value, ResolvedValue::Action(ResolvedAction::Read));

        assert!(left.merge(&right).is_none());
    }

    #[test]
    fn subst_resolves_components_and_atoms() {
        let arena = Bump::new();
        let mut resolver = ComponentResolver::new(&arena);
        let actor = variable(&mut resolver, "actor");
        let alice = Principal::new("alice");
        let bob = Principal::new("bob");
        let alice_symbol = resolver.intern_string("alice");
        let alice_resolved = Principal::resolve(&mut resolver, &alice);
        let bob_resolved = Principal::resolve(&mut resolver, &bob);
        let mut substitution = CandidateSubstitution::default();
        substitution
            .values
            .insert(actor, ResolvedValue::Principal(alice_symbol));

        let constant: CompiledPattern<'_, Principal> = ComponentPattern::Constant(alice_symbol);
        let constant = constant
            .subst::<Principal>(&substitution)
            .expect("constants always substitute");
        assert_eq!(constant, alice_resolved);
        assert_ne!(constant, bob_resolved);

        let variable: CompiledPattern<'_, Principal> = ComponentPattern::Variable(actor);
        let variable = variable
            .subst::<Principal>(&substitution)
            .expect("the candidate bound actor");
        assert_eq!(variable, alice_resolved);
        assert_ne!(variable, bob_resolved);

        let atom: CompiledAtomPattern<'_> =
            CompiledAtomPattern::Principal(ComponentPattern::Variable(actor));
        let event = Event::new("alice", Action::Read, ["a"]);
        assert!(
            atom.subst(&substitution)
                .is_some_and(|resolved| resolved.matches(&mut resolver, &event))
        );
    }
}
