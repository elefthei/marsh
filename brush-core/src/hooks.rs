//! Hooks into builtin command lifecycles.
//!
//! A builtin runs *inside* the shell process, so an external tracer sees only its syscalls and
//! never the fact that a builtin was invoked at all. An embedder that needs to attribute effects to
//! commands must therefore be told by the shell itself. This module is that interface, and only the
//! interface: brush-core notifies, the embedder decides what a notification means.

use std::path::Path;

/// Notified around every builtin execution.
///
/// Installed with [`crate::ShellBuilder::builtin_hook`]. The hook is shared (`Arc`) and travels
/// into subshell clones, so builtins executed by an owned-shell pipeline element report to the same
/// installation as the parent's.
///
/// Implementations must be cheap and must not block: [`Self::begin`] and [`Self::end`] run on the
/// thread executing the builtin, in its critical path.
pub trait BuiltinHook: Send + Sync {
    /// Called immediately before the builtin named `name` executes with `argv` (including
    /// `argv[0]`) and the shell's logical working directory `cwd`.
    ///
    /// The returned id identifies this invocation; the matching [`Self::end`] echoes it.
    fn begin(&self, name: &str, argv: &[String], cwd: &Path) -> u64;

    /// Called after the invocation identified by `id` finished with exit code `exit`.
    ///
    /// Not called when the builtin panics or when the process is replaced (`exec`); an
    /// unterminated invocation is therefore observable, and meaningful, to the embedder.
    fn end(&self, id: u64, exit: u8);
}
