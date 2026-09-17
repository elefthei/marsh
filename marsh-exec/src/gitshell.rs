//! The shell every command runs in: standard builtins, the `git` builtin, and no forkable git.
//!
//! Shell construction lives here rather than in the executor binary because the embedded-shell
//! test and the executor must run the *same* shell — a builtin set that differed between them
//! would make the in-memory hook log evidence about a shell nobody executes.
//!
//! Neither half of what makes this shell special needs a modified brush. `git` is one builtin from
//! [`brush_builtin::git_builtins`], performed in-process through libgit2; registering the name is
//! what guarantees no `git` process is ever spawned, because PATH search is never reached.
//! Instrumentation is [`brush_instrumentation::instrument`], which wraps each registration's
//! public `execute_func`. Everything else is stock `brush-builtins`.

use std::sync::Arc;

use brush_builtins::BuiltinSet;
use brush_core::Shell;
use brush_core::extensions::DefaultShellExtensions;

use brush_instrumentation::RecordingHook;

/// Builds the shell a command runs in, optionally instrumented by `hook`.
///
/// Profile and rc files are skipped: a command's capability footprint must be the command's, not
/// the host user's shell configuration. The working directory is inherited from the caller.
///
/// # Errors
///
/// Fails when brush-core cannot build a shell from these options.
pub async fn build_shell(
    hook: Option<Arc<RecordingHook>>,
) -> Result<Shell<DefaultShellExtensions>, brush_core::Error> {
    let mut builtins =
        brush_builtins::default_builtins::<DefaultShellExtensions>(BuiltinSet::BashMode);
    // `exec` replaces the process image, which would skip the executor's end-of-run record dump and
    // lose every builtin record of the command. A shell that cannot report is not the shell this
    // project runs commands in.
    builtins.remove("exec");
    builtins.extend(brush_builtin::git_builtins());
    let builtins = match hook {
        Some(hook) => brush_instrumentation::instrument(builtins, hook),
        None => builtins,
    };

    Shell::builder()
        .interactive(false)
        .no_editing(true)
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
        .builtins(builtins)
        .build()
        .await
}
