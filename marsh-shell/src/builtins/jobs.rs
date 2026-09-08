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
        // A cheap synchronous snapshot of the mux's own table: nothing is polled here, because the
        // mux reaps its children itself and a finished job has already left the table.
        let Some(()) = super::with_console(&mut stderr, |console, _| {
            console.print_jobs(&mut stdout);
        }) else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::success())
    }
}
