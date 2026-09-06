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

mod bg;
mod close;
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
/// `sd`, `sda`, `stop` and `close` are new; the other four shadow same-named stock builtins.
/// Registering them last is what makes them win, exactly as `shellmux`'s git builtins do.
pub fn registrations() -> Vec<(String, Registration<DefaultShellExtensions>)> {
    vec![
        (
            "sd".to_string(),
            builtins::builtin::<sd::SdCommand, DefaultShellExtensions>(),
        ),
        (
            "sda".to_string(),
            builtins::builtin::<sd::SdaCommand, DefaultShellExtensions>(),
        ),
        (
            "fg".to_string(),
            builtins::builtin::<fg::FgCommand, DefaultShellExtensions>(),
        ),
        (
            "bg".to_string(),
            builtins::builtin::<bg::BgCommand, DefaultShellExtensions>(),
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
        (
            "close".to_string(),
            builtins::builtin::<close::CloseCommand, DefaultShellExtensions>(),
        ),
    ]
}

/// Runs `action` against the installed console, reporting its absence to `err`.
///
/// `action` receives the same `err` the helper reports through, because a console action's
/// diagnostics are the builtin's diagnostics; handing one writer to both is what keeps a builtin
/// from needing two of them.
///
/// `block_in_place` because every one of these actions ends in a blocking syscall — `waitpid`, or a
/// mux call that blocks on the mux's own runtime — and a runtime worker must be told before it is
/// blocked. Nesting is deliberate and supported: the console's own mux calls block in place again.
///
/// The lock is held for the whole action and released before returning, so no console state is ever
/// held across an await.
fn with_console<R>(
    err: &mut dyn Write,
    action: impl FnOnce(&mut Console, &mut dyn Write) -> R,
) -> Option<R> {
    let Some(console) = crate::console::shared() else {
        let _ = writeln!(err, "marsh: no console is running");
        return None;
    };
    Some(tokio::task::block_in_place(|| {
        let mut console = console
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        action(&mut console, err)
    }))
}

/// Strips one leading `%` from a job argument, so `fg %1` and `fg 1` mean the same job.
fn job_name(job: &str) -> &str {
    job.strip_prefix('%').unwrap_or(job)
}
