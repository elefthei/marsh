//! Exact capability policy validation with finite-product past regular expressions.
//!
//! Policies are assembled from owned, context-free [`Rule`], [`TestExpr`], and [`RegexExpr`]
//! values. `ValidatorBuilder` compiles each complete rule by passing a shared canonical store and a
//! temporary variable environment explicitly. The resulting canonical nodes contain only immutable
//! payloads and child references—never compiler, rule, store, scope, or validator backreferences.
//!
//! Resolved values and canonical nodes live in a caller-owned [`Bump`] arena. Boolean tests and
//! normalized regex nodes are hashconsed, giving structurally equal expressions one reference-like
//! canonical handle. The executable [`Validator`] retains only the canonical store, runtime rules,
//! and committed event history.
//!
//! # Example
//!
//! ```rust
//! use rust_validator::{
//!     Action, AtomPattern, Bump, Comparison, ComponentPattern, Decision, Event, Head, RegexExpr,
//!     Request, Rule, RuleMode, TestExpr, Validator,
//! };
//!
//! let principal = TestExpr::atom(
//!     Comparison::Eq,
//!     AtomPattern::Principal(ComponentPattern::variable("actor")),
//! );
//! let action = TestExpr::atom(
//!     Comparison::Eq,
//!     AtomPattern::Action(ComponentPattern::constant(Action::Edit)),
//! );
//! let resource = TestExpr::atom(
//!     Comparison::Eq,
//!     AtomPattern::Resource(ComponentPattern::variable("target")),
//! );
//! let matching_edit = RegexExpr::test(TestExpr::and([principal, action, resource]));
//! let tail = RegexExpr::concat([RegexExpr::all(), matching_edit]);
//! let rule = Rule::new(
//!     RuleMode::Require,
//!     Head::new(
//!         ComponentPattern::variable("actor"),
//!         ComponentPattern::constant(Action::Stage),
//!         ComponentPattern::variable("target"),
//!     ),
//!     tail,
//! );
//!
//! let arena = Bump::new();
//! let mut builder = Validator::builder(&arena);
//! builder.add_rule(&rule)?;
//! let mut validator = builder.finish();
//!
//! let edit = Request::new(Event::new("alice", Action::Edit, ["src", "a.rs"]), ());
//! assert!(validator.check(edit).is_grant());
//! let stage = Request::new(Event::new("alice", Action::Stage, ["src", "a.rs"]), ());
//! assert!(matches!(validator.check(stage), Decision::Grant(_)));
//! # Ok::<(), rust_validator::CompileError>(())
//! ```

mod model;
mod syntax;
mod validator;

#[cfg(feature = "napi")]
pub mod napi;
mod policy;

pub use bumpalo::Bump;
pub use model::{Action, Event, Grant, Principal, Request, Resource};
pub use policy::{
    PolicyDecision,
    git::{GitPolicy, git_decision},
};
pub use syntax::{
    AtomPattern, Comparison, Component, ComponentPattern, Head, RegexExpr, Rule, RuleMode, TestExpr,
};
pub use validator::{Checkpoint, CompileError, Decision, Denial, Validator, ValidatorBuilder};
