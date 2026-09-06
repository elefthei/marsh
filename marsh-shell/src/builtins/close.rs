//! `close`: end a job.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Ends one job: its row, its sandbox and its snapshot.
///
/// Argv is kept verbatim rather than modelled as a clap positional, for the reason `stop` keeps its
/// own: a job name may begin with `-`, which clap would read as an unknown flag.
#[derive(clap::Parser)]
pub(super) struct CloseCommand {
    /// The job to end.
    #[clap(allow_hyphen_values = true, trailing_var_arg = true)]
    args: Vec<String>,
}

impl builtins::Command for CloseCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let name = self.args.first().map(String::as_str);
        let Some(code) = super::with_console(&mut stderr, |console, err| console.close(name, err))
        else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(ExecutionResult::new(code))
    }
}
