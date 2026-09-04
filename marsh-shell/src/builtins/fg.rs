//! `fg`: give a job the terminal.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Attaches a job to the terminal and waits for it to exit or stop.
#[derive(clap::Parser)]
pub(super) struct FgCommand {
    /// Job to attach, as `%NAME` or `NAME`; defaults to the most recent one.
    job: Option<String>,
}

impl builtins::Command for FgCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let name = self.job.as_deref().map(super::job_name);
        let Some(code) = super::with_console(&mut stderr, |console, err| console.fg(name, err))
        else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::new(code))
    }
}
