//! `stop`: close a job, once it is idle or straight away.

use brush_core::builtins;
use brush_core::{ExecutionContext, ExecutionResult, ShellExtensions};

/// Closes one job: after its current command concludes, or immediately with `-f`.
///
/// The job is an ordinary positional, and [`crate::repl::stop`] puts a `--` in front of it, so a
/// name that looks like a flag reaches this parser as the name it is. Nothing is re-normalized
/// here: `repl::job_reference` already took the one leading `%` off, and a second strip would make
/// `%%build` mean `build`.
#[derive(clap::Parser)]
pub(super) struct StopCommand {
    /// Kill the job's command now instead of letting it finish.
    #[arg(short = 'f')]
    force: bool,
    /// The job to close.
    job: String,
}

impl builtins::Command for StopCommand {
    type Error = brush_core::Error;

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let mut stderr = context.stderr();
        let Some(shared) = super::shared(&mut stderr) else {
            return Ok(ExecutionResult::general_error());
        };
        let outcome = shared
            .stop(&shellmux::ShellId::from(self.job.clone()), self.force)
            .await
            .map(|()| 0);
        Ok(ExecutionResult::new(super::report(&mut stderr, outcome)))
    }
}

#[allow(
    clippy::panic,
    clippy::panic_in_result_fn,
    reason = "a grammar test that parsed the wrong form has nothing to assert"
)]
#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::StopCommand;
    use crate::repl::{self, Input};

    /// The argv the grammar builds, parsed by the parser that will actually see it.
    fn parsed(line: &str) -> Result<(bool, String), clap::error::ErrorKind> {
        let Input::Stop(args) = repl::parse(line) else {
            panic!("{line:?} is not a stop line");
        };
        let argv = std::iter::once("stop".to_string()).chain(args);
        StopCommand::try_parse_from(argv)
            .map(|command| (command.force, command.job))
            .map_err(|error| error.kind())
    }

    /// The whole point of the two-stage grammar: a leading `-f` is an option, and a job whose name
    /// begins with `-` is still reachable — as a quoted name, or after an explicit `--`.
    #[test]
    fn stop_arguments_preserve_force_and_job_identity() {
        assert_eq!(
            parsed("stop -f %\"a name\""),
            Ok((true, "a name".to_string()))
        );
        assert_eq!(
            parsed("stop \"-f\""),
            Ok((false, "-f".to_string())),
            "a quoted token is a name, so this closes the job called -f"
        );
        assert_eq!(parsed("stop -f -- \"-f\""), Ok((true, "-f".to_string())));
        assert_eq!(
            parsed("stop %%build"),
            Ok((false, "%build".to_string())),
            "one leading % comes off in the grammar and none here"
        );
        assert_eq!(parsed("stop build"), Ok((false, "build".to_string())));

        assert!(parsed("stop").is_err(), "the job is required");
        assert!(parsed("stop -f").is_err(), "-f is not an operand");
        for signal in ["stop -9 build", "stop -TERM build"] {
            assert_eq!(
                parsed(signal),
                Err(clap::error::ErrorKind::UnknownArgument),
                "{signal}: stop no longer signals"
            );
        }
    }
}
