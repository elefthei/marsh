//! Git legality expressed as a native trace policy over the [`crate::policy`] kernel.
//!
//! The git authorization table is re-expressed as declarative [`crate::Rule`] values whose tails
//! are past-regexes over committed history. Each deny cell of the table is one `Forbid` rule
//! paired with a diagnostic closure carrying the exact precondition/fix strings the consumer
//! boundary surfaces. Grant/deny is entirely trace-policy driven; the commit-message payload is
//! omitted from policy checking (the candidate commit is normalized to a canonical payload-less
//! form).
//!
//! The table is assembled bottom-up: the kernel's [`crate::policy::atoms`] feed [`predicates`]
//! (one-event git tests), which feed [`languages`] (the four canonical row states built on the
//! kernel's tail shapes), which feed [`rules`] (the 23 deny cells). [`GitPolicy`] compiles that table
//! once and retains its canonical nodes and evaluator caches across decisions. [`diagnostics`]
//! renders the strings a denial carries.

mod diagnostics;
mod languages;
mod predicates;
mod rules;

use self::diagnostics::git_context;
use self::rules::git_rules;
use crate::policy::decision::PolicyDecision;
use crate::policy::evaluate::CompiledPolicy;
use crate::{Action, Bump, Event};

/// Compiled Git trace policy reusable across candidate decisions.
///
/// Construction builds and compiles the static 23-rule table once. [`GitPolicy::decide`] accepts an
/// externally owned committed history so callers can preserve append-on-grant semantics while this
/// value retains canonical syntax and derivative caches.
pub struct GitPolicy<'arena> {
    compiled: CompiledPolicy<'arena, diagnostics::GitContext>,
}

impl<'arena> GitPolicy<'arena> {
    /// Builds and compiles the static Git policy in `arena`.
    pub fn new(arena: &'arena Bump) -> Self {
        Self {
            compiled: CompiledPolicy::new(arena, git_rules())
                .expect("static Git policy rules compile"),
        }
    }

    /// Decides one candidate against `history`, reusing the compiled table and evaluator caches.
    ///
    /// Commit-message payloads are ignored by the policy: commit candidates are matched through the
    /// canonical payload-less action, while diagnostics still receive the original candidate.
    pub fn decide(&mut self, history: &[Event], candidate: &Event) -> PolicyDecision {
        let mut probe = candidate.clone();
        if let Action::Commit { .. } = probe.action {
            probe.action = Action::commit_without_message();
        }
        self.compiled
            .decide(history, &probe, || git_context(history, candidate))
    }
}

/// Decides one candidate with a one-shot Git policy.
///
/// Prefer retaining [`GitPolicy`] for repeated decisions. This compatibility function constructs
/// and compiles the policy for this call only.
pub fn git_decision(history: &[Event], candidate: &Event) -> PolicyDecision {
    let arena = Bump::new();
    GitPolicy::new(&arena).decide(history, candidate)
}

#[cfg(test)]
mod tests;
