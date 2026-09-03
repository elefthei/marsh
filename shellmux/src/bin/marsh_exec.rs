//! `marsh-exec`: the instrumented brush shell one mux command runs in.
//!
//! One process per mux command. The spawner ([`shellmux`]) sets the working directory (the work
//! snapshot) and the environment (the principal's exported variables plus the deterministic git
//! env), then runs this binary under `strace`.
//!
//! A command produces two instrumentation streams, and this binary is where they are separated:
//!
//! * **Externals are the traced unit.** `touch foo` is a process, and `strace` sees its syscalls.
//!   Execution lives in its own process for exactly this reason: brush performs redirections and
//!   builtins *inside* the calling process, so a shell embedded in the mux would do its filesystem
//!   work where `ptrace` cannot attribute it to a command.
//! * **Builtins are the instrumented unit.** A builtin — including every git variant, which runs
//!   in-process through libgit2 — is invisible as a *command* to any tracer, so the shell reports it
//!   through a hook. The records are collected in memory and dumped once, at exit, to the path given
//!   by `--hook-log`.
//!
//! Losing the dump is a hard failure even when the command itself succeeded: an un-instrumented run
//! must not merge, so the exit code becomes [`SHELL_FAILURE`] and the mux treats it as a failed
//! execution.

use std::process::ExitCode;
use std::sync::Arc;

use shellmux::gitshell;
use shellmux::hooks::RecordingHook;

/// Exit code used when the shell itself could not be built or run, or when its instrumentation
/// could not be recorded — distinct from any exit code the command could produce.
const SHELL_FAILURE: u8 = 125;

/// The command line: `marsh-exec [--hook-log <path>] -c <command>`.
struct Args {
    /// Where to dump the builtin records, when the spawner asked for them.
    hook_log: Option<std::path::PathBuf>,
    /// The command to run.
    command: String,
}

/// Parses the command line, or `None` when it is not one of the two accepted forms.
fn parse_args(mut args: impl Iterator<Item = String>) -> Option<Args> {
    let mut hook_log = None;
    let mut first = args.next()?;
    if first == "--hook-log" {
        hook_log = Some(std::path::PathBuf::from(args.next()?));
        first = args.next()?;
    }
    if first != "-c" {
        return None;
    }
    let command = args.next()?;
    if args.next().is_some() {
        return None;
    }
    Some(Args { hook_log, command })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(args) = parse_args(std::env::args().skip(1)) else {
        eprintln!("usage: marsh-exec [--hook-log <path>] -c <command>");
        return ExitCode::from(SHELL_FAILURE);
    };

    // Without `--hook-log` no hook is installed: a manually spawned executor runs uninstrumented,
    // which is harmless because nothing translates it.
    let hook = args
        .hook_log
        .as_ref()
        .map(|_| Arc::new(RecordingHook::default()));
    let mut shell = match gitshell::build_shell(hook.clone()).await {
        Ok(shell) => shell,
        Err(error) => {
            eprintln!("marsh-exec: cannot build shell: {error}");
            return ExitCode::from(SHELL_FAILURE);
        }
    };

    let result = shell.run_dash_c_command(&args.command).await;

    if let (Some(path), Some(hook)) = (args.hook_log, hook) {
        let dump = serde_json::to_string(&hook.records())
            .map_err(|error| error.to_string())
            .and_then(|text| std::fs::write(&path, text).map_err(|error| error.to_string()));
        if let Err(error) = dump {
            eprintln!(
                "marsh-exec: cannot write builtin records to {}: {error}",
                path.display()
            );
            return ExitCode::from(SHELL_FAILURE);
        }
    }

    match result {
        Ok(result) => {
            let code: u8 = result.exit_code.into();
            ExitCode::from(code)
        }
        Err(error) => {
            eprintln!("marsh-exec: {error}");
            ExitCode::from(SHELL_FAILURE)
        }
    }
}
