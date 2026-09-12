//! The job-control operations every frontend performs identically.
//!
//! A frontend owns its terminal and its input; it does not own what `jobs`, `kill` and the
//! terminal's own signal dispositions *mean*. Those are the same whether the rows are printed at a
//! console prompt or into a full-screen pane, so they live here — beside the job table itself —
//! rather than being reimplemented once per front-end.
//!
//! Jobs are closed through [`crate::ShellMux::stop`], not from here: `kill` is `kill(1)`, and
//! signals a process id as itself.

use std::io::Write;

use crate::{JobView, Sandbox, ShellMux};

/// Signals a frontend must not receive.
///
/// `SIGQUIT` and `SIGTSTP` stay ignored because an interactive session neither core-dumps nor
/// suspends itself, and `SIGTTIN`/`SIGTTOU` because a background process group that reconfigures
/// the terminal would otherwise be stopped by the kernel.
///
/// `SIGINT` is deliberately absent: what a frontend does with an interrupt is its own policy.
const IGNORED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

/// Ignores the terminal signals that must not stop this process.
pub fn ignore_terminal_job_signals() {
    for signal in IGNORED_SIGNALS {
        // SAFETY: `signal` only installs a disposition for a signal number. `SIG_IGN` runs no
        // handler, so there is no async-signal-safety requirement to honor.
        let _ = unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
}

/// Writes `mux`'s job table to `out`, one row per sandbox.
pub fn print_jobs(mux: &ShellMux, out: &mut dyn Write) {
    let current = mux.current_job().map(|job| job.id);
    for job in mux.jobs() {
        let marker = if current.as_ref() == Some(&job.id) {
            "*"
        } else {
            ""
        };
        let dir = dir_label(&job.sandbox);
        let (state, cmd) = job.running.as_ref().map_or_else(
            || (idle_state(mux, &job), ""),
            |running| ("running", running.cmd.as_str()),
        );
        let _ = writeln!(
            out,
            "{}",
            format!(
                "{}{marker} {dir} {} {state} {cmd}",
                job.id.reference(),
                job.sandbox.uid
            )
            .trim_end()
        );
    }
}

/// The word an idle row prints: what it is doing when it is running nothing.
fn idle_state(mux: &ShellMux, job: &JobView) -> &'static str {
    if job.starting {
        // `starting` is a state of its own: the snapshot is being retaken and the tracer spawned,
        // which is neither idle nor a command anyone can signal yet.
        "starting"
    } else if mux.is_merging(&job.id) {
        "merging"
    } else {
        "idle"
    }
}

/// How a sandbox's directory is shown: `.` for the seed root, the path otherwise.
#[must_use]
pub fn dir_label(sandbox: &Sandbox) -> &str {
    if sandbox.dir.is_empty() {
        "."
    } else {
        &sandbox.dir
    }
}

/// Signals process ids, reporting failures to `err` and returning the exit code `kill(1)` would.
pub fn kill(args: &[String], err: &mut dyn Write) -> u8 {
    let (signal, targets) = match args.split_first() {
        Some((first, rest)) if first.starts_with('-') => {
            let Some(signal) = parse_signal(first) else {
                let _ = writeln!(err, "kill: {first}: invalid signal specification");
                return 1;
            };
            (signal, rest)
        }
        _ => (libc::SIGTERM, args),
    };
    if targets.is_empty() {
        let _ = writeln!(err, "kill: usage: kill [-SIGNAL] PID…");
        return 1;
    }

    let mut code = 0;
    for target in targets {
        if let Ok(pid) = target.parse::<libc::pid_t>() {
            // SAFETY: `kill` signals a process by id and has no memory-safety requirements.
            if unsafe { libc::kill(pid, signal) } != 0 {
                let _ = writeln!(
                    err,
                    "kill: ({pid}) - {}",
                    std::io::Error::last_os_error()
                        .to_string()
                        .trim_end_matches('.')
                );
                code = 1;
            }
        } else {
            let _ = writeln!(err, "kill: {target}: arguments must be process ids");
            code = 1;
        }
    }
    code
}

/// The signal a `kill` flag names: `-9`, or `-TERM` and its siblings.
///
/// Only the signals a job control session has any use for are spelled out; anything else has to be
/// given by number, which keeps the table from pretending to be `kill -l`.
fn parse_signal(flag: &str) -> Option<libc::c_int> {
    // Exactly one leading `-`: `--9` and `--` are not signal specifications, and stripping every
    // dash would silently accept the first as `-9`.
    let name = flag.strip_prefix('-').unwrap_or(flag);
    if name.is_empty() {
        return None;
    }
    if let Ok(number) = name.parse::<libc::c_int>() {
        return (number > 0).then_some(number);
    }
    match name.to_ascii_uppercase().as_str() {
        "HUP" => Some(libc::SIGHUP),
        "INT" => Some(libc::SIGINT),
        "QUIT" => Some(libc::SIGQUIT),
        "KILL" => Some(libc::SIGKILL),
        "TERM" => Some(libc::SIGTERM),
        "CONT" => Some(libc::SIGCONT),
        "STOP" => Some(libc::SIGSTOP),
        "USR1" => Some(libc::SIGUSR1),
        "USR2" => Some(libc::SIGUSR2),
        _ => None,
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The signal grammar is the one part of `kill` that is a pure function of its argument, and
    /// getting it wrong would signal the wrong thing rather than fail.
    #[test]
    fn kill_flags_name_signals_by_number_or_name() {
        assert_eq!(parse_signal("-9"), Some(libc::SIGKILL));
        assert_eq!(parse_signal("-KILL"), Some(libc::SIGKILL));
        assert_eq!(parse_signal("-kill"), Some(libc::SIGKILL));
        assert_eq!(parse_signal("-TERM"), Some(libc::SIGTERM));
        assert_eq!(parse_signal("-CONT"), Some(libc::SIGCONT));
        assert_eq!(parse_signal("-USR2"), Some(libc::SIGUSR2));
        for rejected in ["-", "-0", "-SIGKILL", "-nope", "--", "--9"] {
            assert_eq!(parse_signal(rejected), None, "{rejected} is not a signal");
        }
    }
}
