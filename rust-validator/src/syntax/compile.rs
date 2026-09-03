//! Source-rule compilation into canonical runtime representations.
//!
//! Every function receives the canonical store and rule-local variable environment explicitly.
//! Source expressions remain context-free; runtime nodes contain only resolved values, interned
//! variable symbols, and child references. Errors are relative to the one source rule passed to
//! [`compile_rule`].

use crate::model::{Action, Event, Principal, Resource};
use crate::validator::CompileError;

use super::component::{CompiledAtomPattern, CompiledPattern, ComponentDomain};
use super::environment::{CompiledHead, ResolveError, VariableEnvironment};
use super::node::{RegexId, TestId, TestNode};
use super::source::{AtomPattern, ComponentPattern, Head, RegexExpr, Rule, RuleMode, TestExpr};
use super::store::CanonicalStore;
use super::symbolic::{SymbolicDerivativeCache, SymbolicMatcher};

/// Runtime rule with an event-independent derivative cache retained across evaluations.
pub(crate) struct RuntimeRule<'arena> {
    pub(crate) mode: RuleMode,
    pub(crate) head: CompiledHead<'arena>,
    pub(crate) tail: RegexId<'arena>,
    derivatives: SymbolicDerivativeCache<'arena>,
}

impl<'arena> RuntimeRule<'arena> {
    /// Matches the candidate head and evaluates committed history with the persistent cache.
    pub(crate) fn accepts_history<'event>(
        &mut self,
        store: &mut CanonicalStore<'arena>,
        history: impl IntoIterator<Item = &'event Event>,
        candidate: &Event,
    ) -> Option<bool> {
        let substitution = self.head.match_candidate(store, candidate)?;
        let mut matcher = SymbolicMatcher::new(store, &mut self.derivatives);
        Some(matcher.accepts(self.tail, history, &substitution))
    }

    /// Number of event-independent symbolic derivatives retained by this rule.
    #[cfg(test)]
    pub(crate) fn derivative_count(&self) -> usize {
        self.derivatives.len()
    }

    /// Number of dense minterm transitions prepared before the first event is evaluated.
    #[cfg(test)]
    pub(crate) fn precompiled_transition_count(&self) -> usize {
        self.derivatives.precompiled_len()
    }
}

/// Compiles and validates one complete source rule.
pub(crate) fn compile_rule<'arena>(
    store: &mut CanonicalStore<'arena>,
    source: &Rule,
) -> Result<RuntimeRule<'arena>, CompileError> {
    let (head, variables) = compile_head(store, &source.head)?;
    let tail = compile_regex(store, &variables, &source.tail)?;
    let mut derivatives = SymbolicDerivativeCache::new();
    SymbolicMatcher::new(store, &mut derivatives).precompile(tail);
    Ok(RuntimeRule {
        mode: source.mode,
        head,
        tail,
        derivatives,
    })
}

/// Compiles one head coordinate and records variable declarations.
fn compile_head_pattern<'arena, ComponentType: ComponentDomain<'arena>>(
    store: &mut CanonicalStore<'arena>,
    pattern: &ComponentPattern<ComponentType>,
    variables: &mut VariableEnvironment,
) -> Result<CompiledPattern<'arena, ComponentType>, CompileError> {
    Ok(match pattern {
        ComponentPattern::Constant(value) => {
            ComponentPattern::Constant(ComponentType::resolve(&mut store.resolver, value))
        }
        ComponentPattern::Variable(name) => {
            let variable = store.intern_variable(name);
            variables
                .bind(variable, ComponentType::COMPONENT)
                .map_err(|_| CompileError::VariableComponentConflict {
                    name: name.to_owned(),
                })?;
            ComponentPattern::Variable(variable)
        }
    })
}

/// Compiles the fixed capability-product head and its variable environment.
fn compile_head<'arena>(
    store: &mut CanonicalStore<'arena>,
    head: &Head,
) -> Result<(CompiledHead<'arena>, VariableEnvironment), CompileError> {
    let mut variables = VariableEnvironment::default();
    let principal = compile_head_pattern::<Principal>(store, &head.principal, &mut variables)?;
    let action = compile_head_pattern::<Action>(store, &head.action, &mut variables)?;
    let resource = compile_head_pattern::<Resource>(store, &head.resource, &mut variables)?;
    Ok((
        CompiledHead {
            principal,
            action,
            resource,
        },
        variables,
    ))
}

/// Compiles one tail component pattern after resolving its source variable.
fn compile_pattern<'arena, ComponentType: ComponentDomain<'arena>>(
    store: &mut CanonicalStore<'arena>,
    pattern: &ComponentPattern<ComponentType>,
    variables: &VariableEnvironment,
) -> Result<CompiledPattern<'arena, ComponentType>, CompileError> {
    Ok(match pattern {
        ComponentPattern::Constant(value) => {
            ComponentPattern::Constant(ComponentType::resolve(&mut store.resolver, value))
        }
        ComponentPattern::Variable(name) => {
            let variable = store.intern_variable(name);
            variables
                .resolve(variable, ComponentType::COMPONENT)
                .map_err(|error| match error {
                    ResolveError::Unbound => CompileError::UnboundVariable {
                        name: name.to_owned(),
                    },
                    ResolveError::ComponentConflict => CompileError::VariableComponentConflict {
                        name: name.to_owned(),
                    },
                })?;
            ComponentPattern::Variable(variable)
        }
    })
}

/// Compiles the atom representation retained by hashconsed test nodes.
fn compile_atom_pattern<'arena>(
    store: &mut CanonicalStore<'arena>,
    pattern: &AtomPattern,
    variables: &VariableEnvironment,
) -> Result<CompiledAtomPattern<'arena>, CompileError> {
    Ok(match pattern {
        AtomPattern::Principal(pattern) => {
            CompiledAtomPattern::Principal(compile_pattern::<Principal>(store, pattern, variables)?)
        }
        AtomPattern::Action(pattern) => {
            CompiledAtomPattern::Action(compile_pattern::<Action>(store, pattern, variables)?)
        }
        AtomPattern::Resource(pattern) => {
            CompiledAtomPattern::Resource(compile_pattern::<Resource>(store, pattern, variables)?)
        }
    })
}

/// Recursively compiles one owned boolean expression.
fn compile_test<'arena>(
    store: &mut CanonicalStore<'arena>,
    variables: &VariableEnvironment,
    source: &TestExpr,
) -> Result<TestId<'arena>, CompileError> {
    match source {
        TestExpr::True => Ok(store.test_true),
        TestExpr::False => Ok(store.test_false),
        TestExpr::Atom {
            comparison,
            pattern,
        } => {
            let pattern = compile_atom_pattern(store, pattern, variables)?;
            Ok(store.tests.mk(TestNode::Atom {
                comparison: *comparison,
                pattern,
            }))
        }
        TestExpr::And(children) => {
            let mut compiled = Vec::with_capacity(children.len());
            for child in children {
                compiled.push(compile_test(store, variables, child)?);
            }
            Ok(store.test_and(compiled))
        }
        TestExpr::Or(children) => {
            let mut compiled = Vec::with_capacity(children.len());
            for child in children {
                compiled.push(compile_test(store, variables, child)?);
            }
            Ok(store.test_or(compiled))
        }
    }
}

/// Recursively compiles one owned regex expression through canonical smart constructors.
fn compile_regex<'arena>(
    store: &mut CanonicalStore<'arena>,
    variables: &VariableEnvironment,
    source: &RegexExpr,
) -> Result<RegexId<'arena>, CompileError> {
    match source {
        RegexExpr::Empty => Ok(store.empty),
        RegexExpr::All => Ok(store.all),
        RegexExpr::Epsilon => Ok(store.epsilon),
        RegexExpr::Test(test) => {
            let test = compile_test(store, variables, test)?;
            Ok(store.regex_test(test))
        }
        RegexExpr::Union(children) => {
            let mut compiled = Vec::with_capacity(children.len());
            for child in children {
                compiled.push(compile_regex(store, variables, child)?);
            }
            Ok(store.regex_union(compiled))
        }
        RegexExpr::Concat(children) => {
            let mut compiled = Vec::with_capacity(children.len());
            for child in children {
                compiled.push(compile_regex(store, variables, child)?);
            }
            Ok(store.regex_concat(compiled))
        }
        RegexExpr::Star(inner) => {
            let inner = compile_regex(store, variables, inner)?;
            Ok(store.regex_star(inner))
        }
        RegexExpr::Intersect(children) => {
            let mut compiled = Vec::with_capacity(children.len());
            for child in children {
                compiled.push(compile_regex(store, variables, child)?);
            }
            Ok(store.regex_intersect(compiled))
        }
        RegexExpr::Not(inner) => {
            let inner = compile_regex(store, variables, inner)?;
            Ok(store.regex_not(inner))
        }
    }
}
