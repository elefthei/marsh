//! Variable typing and per-candidate substitution.
//!
//! A [`VariableEnvironment`] validates one source head while its patterns are compiled. A matching
//! [`CompiledHead`] resolves candidate values into a temporary [`CandidateSubstitution`]. Neither
//! object is stored in source expressions or canonical syntax nodes.

use std::collections::HashMap;
use string_interner::DefaultSymbol;

use crate::model::{Action, Event, Principal, Resource};

use super::component::{CandidateSubstitution, CompiledPattern, ComponentDomain};
use super::source::{Component, ComponentPattern};
use super::store::CanonicalStore;

/// Matches one typed head coordinate and returns its partial substitution.
fn match_head_pattern<'arena, ComponentType>(
    store: &mut CanonicalStore<'arena>,
    pattern: CompiledPattern<'arena, ComponentType>,
    actual: &ComponentType,
) -> Option<CandidateSubstitution<'arena>>
where
    ComponentType: ComponentDomain<'arena>,
{
    match pattern {
        ComponentPattern::Constant(expected) => {
            let actual = ComponentType::resolve(&mut store.resolver, actual);
            (expected == actual).then(CandidateSubstitution::default)
        }
        ComponentPattern::Variable(variable) => {
            let value = ComponentType::resolve(&mut store.resolver, actual);
            Some(CandidateSubstitution::singleton(
                variable,
                ComponentType::inject(value),
            ))
        }
    }
}

/// Compiled head patterns stored in one runtime rule.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CompiledHead<'arena> {
    pub(super) principal: CompiledPattern<'arena, Principal>,
    pub(super) action: CompiledPattern<'arena, Action>,
    pub(super) resource: CompiledPattern<'arena, Resource>,
}

impl<'arena> CompiledHead<'arena> {
    /// Matches the candidate, resolves variable bindings, and merges partial substitutions.
    pub(crate) fn match_candidate(
        &self,
        store: &mut CanonicalStore<'arena>,
        event: &Event,
    ) -> Option<CandidateSubstitution<'arena>> {
        let principal = match_head_pattern(store, self.principal, &event.principal)?;
        let action = match_head_pattern(store, self.action, &event.action)?;
        let principal_action = principal.merge(&action)?;
        let resource = match_head_pattern(store, self.resource, &event.resource)?;
        principal_action.merge(&resource)
    }
}

/// Structural failure while resolving an interned variable symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResolveError {
    /// The rule head did not declare the variable.
    Unbound,
    /// The head declared the variable in another component domain.
    ComponentConflict,
}

/// Rule-local type environment declared by a source head.
///
/// The map records which arena-backed names exist and the product component occupied by each name. It
/// is a transient compiler input and is dropped after the tail has been compiled.
#[derive(Default)]
pub(crate) struct VariableEnvironment {
    variables: HashMap<DefaultSymbol, Component>,
}

impl VariableEnvironment {
    /// Records one head occurrence.
    ///
    /// Returns the existing component when the variable was previously bound in a different domain;
    /// the compiler caller owns source names and diagnostic construction.
    pub(super) fn bind(
        &mut self,
        variable: DefaultSymbol,
        component: Component,
    ) -> Result<(), Component> {
        match self.variables.get(&variable) {
            Some(&bound_component) if bound_component != component => Err(bound_component),
            Some(_) => Ok(()),
            None => {
                self.variables.insert(variable, component);
                Ok(())
            }
        }
    }

    /// Verifies that a tail occurrence is declared by the head in the same component domain.
    pub(super) fn resolve(
        &self,
        variable: DefaultSymbol,
        component: Component,
    ) -> Result<(), ResolveError> {
        match self.variables.get(&variable) {
            Some(&bound_component) if bound_component != component => {
                Err(ResolveError::ComponentConflict)
            }
            Some(_) => Ok(()),
            None => Err(ResolveError::Unbound),
        }
    }
}
