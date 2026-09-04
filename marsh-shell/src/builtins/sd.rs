//! `sd` and `sda`: open a job — a sandbox over one directory in the current job.

use std::io::Write;

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

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
        Ok(open(&mut stderr, self.name.clone(), &self.dir))
    }
}

/// Opens a job named `1`, `2`, … over `DIR`: `sd` with the naming left to the console.
#[derive(clap::Parser)]
pub(super) struct SdaCommand {
    /// Directory the sandbox is rooted at: a path in the current job, or /DIR from the seed root.
    dir: String,
}

impl builtins::Command for SdaCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let Some(name) = super::with_console(&mut stderr, |console, _| console.next_name()) else {
            return Ok(ExecutionResult::general_error());
        };
        Ok(open(&mut stderr, name, &self.dir))
    }
}

/// Opens the sandbox on the installed console, reporting its absence to `err`.
fn open(err: &mut dyn Write, name: String, dir: &str) -> ExecutionResult {
    let Some(code) = super::with_console(err, |console, err| console.open_sandbox(name, dir, err))
    else {
        return ExecutionResult::general_error();
    };
    ExecutionResult::new(code)
}
