//! The job-control builtins, registered only in the outer console shell.
//!
//! These are real [`brush_core::builtins::Command`] implementations rather than console-side string
//! handling, so `fg --help` renders brush's own help, argument errors are brush's argument errors,
//! and the registry the prompt completes against contains exactly the commands that exist. They
//! replace the stock `fg`/`bg`/`jobs`/`kill` entries, which act on the *outer* shell's job table —
//! and the outer shell never runs anything, so its table is always empty.
//!
//! They act on the console through [`crate::console::shared`], because a
//! [`brush_core::builtins::Registration`]'s `execute_func` is a plain function pointer with nowhere
//! to put captured state.

mod fg;
mod jobs;
mod kill;
mod sd;
mod stop;

use std::io::Write;

use brush_core::builtins::{self, Registration};
use brush_core::extensions::DefaultShellExtensions;

use crate::console::Console;

/// The console registrations, in the form [`brush_core::ShellBuilder::builtins`] takes.
///
/// `sd` and `stop` are new; `fg`, `jobs` and `kill` shadow same-named stock builtins, and `bg`
/// shadows the stock name with a different meaning: it opens a job rather than resuming one.
/// Registering them last is what makes them win, exactly as `shellmux`'s git builtins do.
pub fn registrations() -> Vec<(String, Registration<DefaultShellExtensions>)> {
    vec![
        (
            "sd".to_string(),
            builtins::builtin::<sd::SdCommand, DefaultShellExtensions>(),
        ),
        (
            "bg".to_string(),
            builtins::builtin::<sd::BgCommand, DefaultShellExtensions>(),
        ),
        (
            "fg".to_string(),
            builtins::builtin::<fg::FgCommand, DefaultShellExtensions>(),
        ),
        (
            "jobs".to_string(),
            builtins::builtin::<jobs::JobsCommand, DefaultShellExtensions>(),
        ),
        (
            "kill".to_string(),
            builtins::builtin::<kill::KillCommand, DefaultShellExtensions>(),
        ),
        (
            "stop".to_string(),
            builtins::builtin::<stop::StopCommand, DefaultShellExtensions>(),
        ),
    ]
}

/// The console's shared half, or `None` once its absence has been reported to `err`.
///
/// The console's own lock is taken for the length of this call and released before it returns, so
/// nothing is held across the awaits the caller then performs.
fn shared(err: &mut dyn Write) -> Option<std::sync::Arc<crate::console::ConsoleShared>> {
    let Some(console) = crate::console::shared() else {
        let _ = writeln!(err, "marsh: no console is running");
        return None;
    };
    let console = console
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Some(console.shared())
}

/// Runs `action` against the installed console under a short lock, reporting its absence to `err`.
///
/// For the synchronous operations only — a job table snapshot, the exit check. Anything that has to
/// await goes through [`shared`] instead.
fn with_console<R>(
    err: &mut dyn Write,
    action: impl FnOnce(&mut Console, &mut dyn Write) -> R,
) -> Option<R> {
    let Some(console) = crate::console::shared() else {
        let _ = writeln!(err, "marsh: no console is running");
        return None;
    };
    let mut console = console
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Some(action(&mut console, err))
}

/// Prints a console operation's diagnostic, if it had one, and returns the builtin's exit code.
fn report(err: &mut dyn Write, outcome: Result<u8, String>) -> u8 {
    match outcome {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(err, "{message}");
            1
        }
    }
}

/// Strips one leading `%` from a job argument, so `fg %1` and `fg 1` mean the same job.
fn job_name(job: &str) -> &str {
    job.strip_prefix('%').unwrap_or(job)
}
