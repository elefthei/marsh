//! Source language, rule compilation, canonical storage, and runtime evaluation.
//!
//! Owned source expressions are independent of arenas and validators. Compiler functions receive a
//! canonical store and transient variable environment explicitly, producing immutable canonical
//! rule nodes. Runtime evaluation receives the store and candidate substitution explicitly. No
//! expression or node points back to its compiler, rule, store, or validator.

mod compile;
mod component;
mod environment;
mod evaluate;
mod node;
mod normalize;
mod source;
mod store;
mod symbolic;
mod transition;

pub use source::{
    AtomPattern, Comparison, Component, ComponentPattern, Head, RegexExpr, Rule, RuleMode, TestExpr,
};

pub(crate) use compile::{RuntimeRule, compile_rule};
pub(crate) use store::CanonicalStore;

#[cfg(test)]
mod tests;
