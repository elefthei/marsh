//! `stop`: signal a job's process group.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Sends a signal to one job, defaulting to `SIGTERM`.
///
/// Argv is kept verbatim rather than modelled as clap options, for the reason `kill` keeps its own:
/// `stop -9 build` puts the signal in a position clap would read as an unknown flag.
#[derive(clap::Parser)]
pub(super) struct StopCommand {
    /// Optional leading signal (`-9`, `-TERM`, …) followed by the job to signal.
    #[clap(allow_hyphen_values = true, trailing_var_arg = true)]
    args: Vec<String>,
}

impl builtins::Command for StopCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let Some(code) =
            super::with_console(&mut stderr, |console, err| console.stop(&self.args, err))
        else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::new(code))
    }
}
