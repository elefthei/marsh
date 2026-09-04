//! `bg`: resume a stopped job in the background.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Resumes a stopped job without giving it the terminal.
#[derive(clap::Parser)]
pub(super) struct BgCommand {
    /// Job to resume, as `%NAME` or `NAME`; defaults to the most recent stopped one.
    job: Option<String>,
}

impl builtins::Command for BgCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let name = self.job.as_deref().map(super::job_name);
        let Some(code) = super::with_console(&mut stderr, |console, err| console.bg(name, err))
        else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::new(code))
    }
}
