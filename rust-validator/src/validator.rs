//! Policy compilation, stateful authorization, and rollback.
//!
//! Source rules are complete owned values. `ValidatorBuilder` resolves each rule through the
//! canonical store and a temporary variable environment. The executable validator retains only
//! canonical runtime rules and committed history.

use bumpalo::Bump;
use thiserror::Error;

use crate::model::{Event, Grant, Request};
use crate::syntax::{CanonicalStore, Rule, RuleMode, RuntimeRule, compile_rule};

/// Rule-compilation failure detected before a validator can execute.
///
/// `ValidatorBuilder::add_rule` compiles exactly one source rule, so the caller already knows which
/// rule failed. Errors contain only the local malformed name rather than a derived vector position.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompileError {
    /// One variable name occurs in different product components in the same rule.
    #[error("variable {name:?} occurs in different product components")]
    VariableComponentConflict {
        /// Conflicting variable name.
        name: String,
    },
    /// A tail references a variable that its head does not bind.
    #[error("tail variable {name:?} is not bound by the head")]
    UnboundVariable {
        /// Missing variable name.
        name: String,
    },
}

/// Diagnostic returned when the first matching rule is violated.
///
/// The denial describes the violated relationship without deriving a positional identifier for the
/// internal rule vector. Applications needing rule identity should carry an explicit domain label
/// in their policy model rather than depending on storage order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    /// Whether the violated rule required or forbade its tail language.
    pub mode: RuleMode,
    /// Candidate event that was denied and was not appended to history.
    pub event: Event,
    /// Human-readable explanation of the failed history relation.
    pub message: String,
}

/// Result of checking one capability request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<M> {
    /// Request was accepted and appended to committed history.
    Grant(Grant<M>),
    /// Request was rejected atomically; committed history is unchanged.
    Denied(Denial),
}

impl<M> Decision<M> {
    /// Returns `true` exactly for [`Decision::Grant`].
    pub fn is_grant(&self) -> bool {
        matches!(self, Self::Grant(_))
    }
}

/// Opaque committed-history cursor.
///
/// The position is produced and range-checked only by `Validator`; callers cannot manufacture it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint(usize);

/// Resolves complete source rules into runtime rules sharing one canonical store.
pub struct ValidatorBuilder<'arena> {
    store: CanonicalStore<'arena>,
    rules: Vec<RuntimeRule<'arena>>,
}

impl<'arena> ValidatorBuilder<'arena> {
    /// Creates an empty builder whose resolved values live in `arena`.
    pub fn new(arena: &'arena Bump) -> Self {
        Self {
            store: CanonicalStore::new(arena),
            rules: Vec::new(),
        }
    }

    /// Resolves and appends one complete source rule.
    ///
    /// The source expression is context-free. Its head creates a temporary variable environment,
    /// and only the resulting runtime rule is kept.
    pub fn add_rule(&mut self, source: Rule) -> Result<&mut Self, CompileError> {
        let runtime_rule = compile_rule(&mut self.store, &source)?;
        self.rules.push(runtime_rule);
        Ok(self)
    }

    /// Finishes compilation with an empty committed history.
    pub fn finish(self) -> Validator<'arena> {
        Validator {
            store: self.store,
            rules: self.rules,
            history: Vec::new(),
        }
    }
}

/// Stateful validator for a fixed ordered rule set.
pub struct Validator<'arena> {
    store: CanonicalStore<'arena>,
    rules: Vec<RuntimeRule<'arena>>,
    history: Vec<Event>,
}

impl<'arena> Validator<'arena> {
    /// Starts compiling a validator in `arena`.
    pub fn builder(arena: &'arena Bump) -> ValidatorBuilder<'arena> {
        ValidatorBuilder::new(arena)
    }

    /// Checks one request against all rules in source order.
    ///
    /// A nonmatching head does not fire. For a matching head, `Require` denies when the complete
    /// committed history is outside the tail language, while `Forbid` denies when it is inside.
    /// The first violation wins. On success the candidate is appended once and its metadata is
    /// preserved in the returned grant.
    pub fn check<M>(&mut self, request: Request<M>) -> Decision<M> {
        for rule in &mut self.rules {
            let Some(accepted) =
                rule.accepts_history(&mut self.store, self.history.iter(), &request.event)
            else {
                continue;
            };
            let violated = match rule.mode {
                RuleMode::Require => !accepted,
                RuleMode::Forbid => accepted,
            };
            if violated {
                let relation = match rule.mode {
                    RuleMode::Require => "does not satisfy required",
                    RuleMode::Forbid => "satisfies forbidden",
                };
                return Decision::Denied(Denial {
                    mode: rule.mode,
                    event: request.event,
                    message: format!("committed history {relation} past-regex rule"),
                });
            }
        }

        self.history.push(request.event.clone());
        Decision::Grant(Grant {
            event: request.event,
            metadata: request.metadata,
        })
    }

    /// Returns committed grants' events in exact acceptance order.
    pub fn history(&self) -> &[Event] {
        &self.history
    }

    /// Captures the current committed-history position in constant time.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.history.len())
    }

    /// Restores history to a previously captured position.
    pub fn rollback(&mut self, checkpoint: Checkpoint) {
        assert!(
            checkpoint.0 <= self.history.len(),
            "invalid validator checkpoint"
        );
        self.history.truncate(checkpoint.0);
    }
}
