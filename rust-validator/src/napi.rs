//! Feature-gated napi-rs bindings for a stateful Git authorizer.
//!
//! The handle retains one compiled native policy and a `Vec<Event>` committed history. Gated behind
//! the default-off `napi` cargo feature, so it is absent from default `cargo build`/`check`/`test`.

use napi_derive::napi;
use self_cell::self_cell;

use crate::policy::{PolicyDecision, git::GitPolicy};
use crate::{Action, Bump, Event};

// -- napi surface -----------------------------------------------------------

/// Marshaled action: `{ kind, message? }`, matching `share/caps-types` `Action`'s runtime shape.
#[napi(object)]
pub struct JsAction {
    pub kind: String,
    pub message: Option<String>,
}

impl TryFrom<JsAction> for Action {
    type Error = napi::Error;

    fn try_from(value: JsAction) -> Result<Self, Self::Error> {
        Ok(match value.kind.as_str() {
            "read" => Action::Read,
            "edit" => Action::Edit,
            "stage" => Action::Stage,
            "unstage" => Action::Unstage,
            "commit" => Action::Commit {
                message: value.message,
            },
            "checkout" => Action::Checkout,
            "stash" => Action::Stash,
            "delete" => Action::Delete,
            "clean" => Action::Clean,
            "diff" => Action::Diff,
            "history" => Action::History,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "unknown git action kind: {other}"
                )));
            }
        })
    }
}

/// Marshaled decision: `kind` is `"grant"` or `"soft-error"`; the precondition/fixes are
/// present only for `"soft-error"`. napi renders the fields as `failedPrecondition`/`allowedFixes`.
#[napi(object)]
pub struct JsGitDecision {
    pub kind: String,
    pub failed_precondition: Option<String>,
    pub allowed_fixes: Option<Vec<String>>,
}

self_cell!(
    /// Owns the arena and the compiled Git policy whose canonical nodes borrow it.
    struct GitPolicyCell {
        owner: Bump,

        #[not_covariant]
        dependent: GitPolicy,
    }
);

/// Stateful Git authorizer retaining compiled policy state and committed grant history.
///
/// The 23-rule policy table is compiled once by the constructor. Each request reuses its canonical
/// syntax and derivative caches; append-only-on-grant history updates keep `check` atomic.
#[napi]
pub struct GitValidator {
    policy: GitPolicyCell,
    history: Vec<Event>,
}

#[napi]
impl GitValidator {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            policy: GitPolicyCell::new(Bump::new(), |arena| GitPolicy::new(arena)),
            history: Vec::new(),
        }
    }

    /// Decides one request. On grant, appends to history and returns `{ kind: "grant" }`; on
    /// deny, returns a `soft-error` with the exact git precondition/fixes and does NOT append.
    /// An unknown action `kind` throws (matching the prior TS throw on malformed input).
    #[napi]
    pub fn check(
        &mut self,
        principal: String,
        action: JsAction,
        resource: Vec<String>,
    ) -> napi::Result<JsGitDecision> {
        let action: Action = action.try_into()?;
        let event = Event::new(principal, action, resource);
        let decision = self
            .policy
            .with_dependent_mut(|_, policy| policy.decide(&self.history, &event));
        match decision {
            PolicyDecision::Grant => {
                self.history.push(event);
                Ok(JsGitDecision {
                    kind: "grant".to_string(),
                    failed_precondition: None,
                    allowed_fixes: None,
                })
            }
            PolicyDecision::Deny {
                failed_precondition,
                allowed_fixes,
            } => Ok(JsGitDecision {
                kind: "soft-error".to_string(),
                failed_precondition: Some(failed_precondition),
                allowed_fixes: Some(allowed_fixes),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_appends_only_on_grant_and_threads_history() {
        let mut validator = GitValidator::new();
        let r = || vec!["src".to_string(), "x".to_string()];
        let act = |kind: &str| JsAction {
            kind: kind.to_string(),
            message: None,
        };

        // clean -> stage denied, history unchanged
        let d = validator
            .check("self".to_string(), act("stage"), r())
            .unwrap();
        assert_eq!(d.kind, "soft-error");
        assert_eq!(validator.history.len(), 0);

        // edit -> grant, appended
        let d = validator
            .check("self".to_string(), act("edit"), r())
            .unwrap();
        assert_eq!(d.kind, "grant");
        assert_eq!(validator.history.len(), 1);

        // now stage -> grant (unstaged-self)
        let d = validator
            .check("self".to_string(), act("stage"), r())
            .unwrap();
        assert_eq!(d.kind, "grant");

        // staged + commit (message irrelevant) -> grant, appended
        let before = validator.history.len();
        let d = validator
            .check("self".to_string(), act("commit"), r())
            .unwrap();
        assert_eq!(d.kind, "grant");
        assert_eq!(validator.history.len(), before + 1);
    }

    #[test]
    fn delete_and_clean_marshal_across_the_boundary() {
        let mut validator = GitValidator::new();
        let r = || vec!["src".to_string(), "x".to_string()];
        let act = |kind: &str| JsAction {
            kind: kind.to_string(),
            message: None,
        };

        // clean row -> delete grants and settles the resource into the staged row.
        let d = validator
            .check("self".to_string(), act("delete"), r())
            .unwrap();
        assert_eq!(d.kind, "grant");
        assert_eq!(validator.history.len(), 1);

        // `clean` is transparent to the row, so it grants on the staged row too.
        let d = validator
            .check("self".to_string(), act("clean"), r())
            .unwrap();
        assert_eq!(d.kind, "grant");
        assert_eq!(validator.history.len(), 2);

        // A second delete now hits the staged-row cell.
        let d = validator
            .check("self".to_string(), act("delete"), r())
            .unwrap();
        assert_eq!(d.kind, "soft-error");
        assert_eq!(
            d.failed_precondition.as_deref(),
            Some("delete requires a resource with no staged or unstaged changes"),
        );
        assert_eq!(validator.history.len(), 2);
    }

    #[test]
    fn unknown_action_kind_throws() {
        let mut validator = GitValidator::new();
        let result = validator.check(
            "self".to_string(),
            JsAction {
                kind: "teleport".to_string(),
                message: None,
            },
            vec!["src".to_string()],
        );
        assert!(result.is_err());
    }
}
