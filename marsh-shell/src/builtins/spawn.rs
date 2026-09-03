//! `spawn`: start a named background job, which is also a named principal.

use std::io::Write;

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

use crate::repl;

/// Starts `CMD` as a background job named `NAME`.
///
/// `CMD` is one argument, not a trailing vector: the console hands it over as the verbatim
/// remainder of the submitted line, so `spawn foo sh -c 'sleep 1; echo hi'` keeps its quoting. Word
/// splitting it here and re-joining it would change the command the job runs.
#[derive(clap::Parser)]
pub(super) struct SpawnCommand {
    /// The job's name, which is also its principal.
    name: String,
    /// The command line to run, as a single pre-assembled argument.
    cmd: String,
}

impl builtins::Command for SpawnCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        if !repl::valid_name(&self.name) {
            writeln!(
                stderr,
                "spawn: invalid name {:?} (use letters, digits, _ or -; not {:?})",
                self.name,
                repl::FOREGROUND
            )?;
            return Ok(ExecutionResult::new(2));
        }

        let Some(code) = super::with_console(&mut stderr, |console, err| {
            console.spawn(self.name.clone(), self.cmd.clone(), err)
        }) else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::new(code))
    }
}
