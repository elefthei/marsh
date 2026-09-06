//! `jobs`: the open transactions.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Lists the console's jobs, one row per open transaction.
#[derive(clap::Parser)]
pub(super) struct JobsCommand {}

impl builtins::Command for JobsCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stdout = context.stdout();
        let mut stderr = context.stderr();
        let Some(()) = super::with_console(&mut stderr, |console, _| {
            // A wakeup can arrive while this builtin already holds the console, so the table is
            // refreshed by the same call that prints it: a job that finished a moment ago is not
            // "running". The poll is `WNOHANG` and costs nothing.
            console.reap();
            console.print_jobs(&mut stdout);
        }) else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::success())
    }
}
