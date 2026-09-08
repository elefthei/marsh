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
        let id = self
            .job
            .as_deref()
            .map(|job| shellmux::ShellId::from(super::job_name(job)));
        let Some(shared) = super::shared(&mut stderr) else {
            return Ok(ExecutionResult::general_error());
        };
        let outcome = shared.fg(id).await;
        Ok(ExecutionResult::new(super::report(&mut stderr, outcome)))
    }
}
