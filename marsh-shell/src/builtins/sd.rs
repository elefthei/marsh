//! `sd` and `bg`: open a job — a sandbox over one directory in the current job.

use std::io::Write;

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

use shellmux::ShellId;

use crate::repl;

/// Opens job `NAME`, a sandbox rooted at `DIR`, and makes it current.
///
/// The name is also the principal every command of that job requests capabilities as, which is why
/// it is validated here rather than left to the console: two jobs sharing a name would be
/// indistinguishable in the capability history.
#[derive(clap::Parser)]
pub(super) struct SdCommand {
    /// The job's name, which is also its principal.
    name: String,
    /// Directory the sandbox is rooted at: a path in the current job, or /DIR from the seed root.
    dir: String,
}

impl builtins::Command for SdCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        if !repl::valid_name(&self.name) {
            writeln!(
                stderr,
                "sd: invalid name {:?} (use letters, digits, _ or -; not {:?})",
                self.name,
                repl::FOREGROUND
            )?;
            return Ok(ExecutionResult::new(2));
        }
        Ok(open(
            &mut stderr,
            Some(ShellId::from(self.name.clone())),
            &self.dir,
        )
        .await)
    }
}

/// Opens a job named `1`, `2`, … over `DIR`: `sd` with the naming left to the console.
#[derive(clap::Parser)]
pub(super) struct BgCommand {
    /// Directory the sandbox is rooted at: a path in the current job, or /DIR from the seed root.
    dir: String,
}

impl builtins::Command for BgCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        Ok(open(&mut stderr, None, &self.dir).await)
    }
}

/// Opens the sandbox on the installed console, reporting its absence to `err`.
///
/// `id` is `None` for the next name in the `1`, `2`, … series, which the mux's job table draws:
/// asking the console for one first would be a second registry of the same names.
async fn open<W: Write + Send>(err: &mut W, id: Option<ShellId>, dir: &str) -> ExecutionResult {
    let Some(shared) = super::shared(err) else {
        return ExecutionResult::general_error();
    };
    let outcome = shared.open_job(dir, id, None).await.map(|()| 0);
    ExecutionResult::new(super::report(err, outcome))
}
