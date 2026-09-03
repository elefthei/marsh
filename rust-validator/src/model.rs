//! Owned capability-product values accepted and returned by the validator.
//!
//! Public values own their strings so requests and committed history do not borrow caller memory.
//! Rule compilation copies constants into the validator's bump arena, where canonical syntax can
//! reference them immutably for the arena lifetime.

use std::fmt;

/// Identity of the actor requesting a capability.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(String);

impl Principal {
    /// Creates a principal from an owned or borrowed string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the principal's exact string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Principal {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Principal {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Ordered path segments naming a protected resource.
///
/// Equality is structural: segment count, order, and exact segment text all matter. Display joins
/// segments with `/` for diagnostics only; it is not the equality representation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Resource(Vec<String>);

impl Resource {
    /// Creates a resource by collecting ordered path segments.
    pub fn new(segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(segments.into_iter().map(Into::into).collect())
    }

    /// Returns the resource's ordered path segments.
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl<const N: usize> From<[&str; N]> for Resource {
    fn from(segments: [&str; N]) -> Self {
        Self::new(segments)
    }
}

impl From<Vec<&str>> for Resource {
    fn from(segments: Vec<&str>) -> Self {
        Self::new(segments)
    }
}

impl From<Vec<String>> for Resource {
    fn from(segments: Vec<String>) -> Self {
        Self(segments)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0.join("/"))
    }
}

/// Git-like capability action.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Observe resource contents.
    Read,
    /// Modify resource contents.
    Edit,
    /// Stage a resource.
    Stage,
    /// Remove a resource from the staging area.
    Unstage,
    /// Commit a staged resource, optionally with an exact message.
    Commit {
        /// Commit message. `None` is distinct from an empty message.
        message: Option<String>,
    },
    /// Restore a resource from the repository.
    Checkout,
    /// Stash local resource changes.
    Stash,
    /// Remove a resource from the working tree and stage the removal.
    Delete,
    /// Discard untracked working-tree content at a resource.
    Clean,
    /// Observe resource differences.
    Diff,
    /// Observe resource history.
    History,
}

impl Action {
    /// Creates a commit action with a present message.
    pub fn commit(message: impl Into<String>) -> Self {
        Self::Commit {
            message: Some(message.into()),
        }
    }

    /// Creates a commit action with no message field.
    pub fn commit_without_message() -> Self {
        Self::Commit { message: None }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("read"),
            Self::Edit => formatter.write_str("edit"),
            Self::Stage => formatter.write_str("stage"),
            Self::Unstage => formatter.write_str("unstage"),
            Self::Commit {
                message: Some(message),
            } => write!(formatter, "commit({message:?})"),
            Self::Commit { message: None } => formatter.write_str("commit(<missing message>)"),
            Self::Checkout => formatter.write_str("checkout"),
            Self::Stash => formatter.write_str("stash"),
            Self::Delete => formatter.write_str("delete"),
            Self::Clean => formatter.write_str("clean"),
            Self::Diff => formatter.write_str("diff"),
            Self::History => formatter.write_str("history"),
        }
    }
}

/// Capability-product event matched by heads and tail atoms.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Event {
    /// Actor requesting the capability.
    pub principal: Principal,
    /// Requested operation.
    pub action: Action,
    /// Protected resource.
    pub resource: Resource,
}

impl Event {
    /// Creates an event from values convertible to the owned component types.
    pub fn new(
        principal: impl Into<Principal>,
        action: Action,
        resource: impl Into<Resource>,
    ) -> Self {
        Self {
            principal: principal.into(),
            action,
            resource: resource.into(),
        }
    }
}

/// Capability request with opaque caller metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<M> {
    /// Product event evaluated by the policy.
    pub event: Event,
    /// Opaque value passed through unchanged on grant.
    pub metadata: M,
}

impl<M> Request<M> {
    /// Creates a request from an event and opaque metadata.
    pub fn new(event: Event, metadata: M) -> Self {
        Self { event, metadata }
    }
}

/// Accepted request echoed at the authorization boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant<M> {
    /// Accepted event, also appended to committed history.
    pub event: Event,
    /// Original request metadata, preserved unchanged.
    pub metadata: M,
}
