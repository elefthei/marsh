//! `kill`: signal jobs and process ids.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Sends a signal to jobs (`%NAME`) or process ids, defaulting to `SIGTERM`.
///
/// Argv is kept verbatim rather than modelled as clap options: `kill -9 %1` puts the signal in a
/// position clap would read as an unknown flag, and the grammar — one optional leading
/// `-<NAME|NUMBER>` followed by targets — is small enough to be parsed exactly where it is used.
#[derive(clap::Parser)]
pub(super) struct KillCommand {
    /// Optional leading signal (`-9`, `-TERM`, …) followed by the targets to signal.
    #[clap(allow_hyphen_values = true, trailing_var_arg = true)]
    args: Vec<String>,
}

impl builtins::Command for KillCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let code = shellmux::jobctl::kill(&self.args, &mut stderr);
        Ok(ExecutionResult::new(code))
    }
}
