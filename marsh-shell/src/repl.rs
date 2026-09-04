//! The console's line grammar and its report text: everything about a submitted line that is a
//! pure function of the line, and everything about a finished transaction that is a pure function
//! of its outcome.
//!
//! Both halves live here because both are the parts of the front-end that can be *proved*. Job
//! control, terminal handoff and mux calls are all effects; parsing `sd foo ./api` and
//! rendering `%foo denied 1 of 2:` are not, so they are separated out and unit-tested directly.
//!
//! The grammar is deliberately tiny and resolved *before* any brush parsing: the console builtins
//! (`jobs`, `fg`, `bg`, `kill`, `exit`, `sd`, `sda`, and the trailing `&`) never reach the shell as
//! text, because the shell that composes the prompt is not the shell that runs commands — every
//! real command line is handed to a traced job instead.

use shellmux::{Action, CmdOutcome, MuxError};

/// The foreground principal: every line submitted without `&` or `spawn` runs as this one.
///
/// It is also the reserved job name, so `%main` can never mean two different things.
pub const FOREGROUND: &str = "main";

/// What a submitted line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// Nothing was typed.
    Empty,
    /// List the job table.
    Jobs,
    /// End the session.
    Exit,
    /// Attach a job to the terminal; `None` means the most recent one.
    Fg(Option<String>),
    /// Resume a stopped job in the background; `None` means the most recent stopped one.
    Bg(Option<String>),
    /// Signal jobs or process ids; the tokens are passed through verbatim, signal flag included.
    Kill(Vec<String>),
    /// Create a named sandbox rooted at a seed directory.
    SpawnDir {
        /// The job's name, which is also its principal; `None` takes the next number.
        name: Option<String>,
        /// The directory as typed, resolved against the current job by [`job_dir`].
        dir: String,
    },
    /// Start the line in the current job without waiting for it (a trailing `&`), `&` stripped.
    Background(String),
    /// Run the line as the foreground job.
    Foreground(String),
    /// The line named a console builtin but got its arguments wrong; the message is for stderr.
    Invalid(String),
}

/// Parses one submitted line.
///
/// Dispatch is on the first token of the trimmed line, so a console builtin is recognized before
/// anything else can interpret it. Everything else is a command line, taken as the verbatim
/// remainder of the line: a builtin would receive word-split, expansion-processed argv, and
/// rebuilding a command *string* from it would need lossy re-quoting, so
/// `sh -c 'sleep 1; echo hi'` would not survive the round trip.
pub fn parse(line: &str) -> Input {
    let line = line.trim();
    if line.is_empty() {
        return Input::Empty;
    }
    let mut tokens = line.split_whitespace();
    let first = tokens.next().unwrap_or_default();
    let rest: Vec<&str> = tokens.collect();

    match first {
        "jobs" if rest.is_empty() => Input::Jobs,
        // `exit 1` is still an exit: the console has no exit status to pass on.
        "exit" => Input::Exit,
        "fg" | "bg" => match rest.as_slice() {
            [] => job_target(first, None),
            [name] => job_target(first, Some(name)),
            _ => Input::Invalid(format!("{first}: usage: {first} [%NAME]")),
        },
        // `kill` keeps its argv verbatim — the signal flag and every target are the builtin's to
        // interpret, exactly as in bash, where `kill -9 %1 1234` is one invocation.
        "kill" => Input::Kill(rest.iter().map(|token| (*token).to_string()).collect()),
        "sd" => match rest.as_slice() {
            [name, dir] => sd(name, dir),
            _ => Input::Invalid("sd: usage: sd NAME DIR".to_string()),
        },
        "sda" => match rest.as_slice() {
            [dir] => Input::SpawnDir {
                name: None,
                dir: (*dir).to_string(),
            },
            _ => Input::Invalid("sda: usage: sda DIR".to_string()),
        },
        // A trailing `&` is a background job; `&&` is an operator and belongs to the command line.
        _ => {
            if !line.ends_with("&&")
                && let Some(cmd) = line.strip_suffix('&')
            {
                let cmd = cmd.trim_end();
                if !cmd.is_empty() {
                    return Input::Background(cmd.to_string());
                }
            }
            Input::Foreground(line.to_string())
        }
    }
}

/// Builds the `fg`/`bg` variant for an optional job argument, stripping one leading `%`.
fn job_target(verb: &str, name: Option<&str>) -> Input {
    let name = name.map(|name| name.strip_prefix('%').unwrap_or(name).to_string());
    if verb == "fg" {
        Input::Fg(name)
    } else {
        Input::Bg(name)
    }
}

/// Parses `sd NAME DIR`, validating the name a job — hence a principal — will answer to.
fn sd(name: &str, dir: &str) -> Input {
    if !valid_name(name) {
        return Input::Invalid(format!(
            "sd: invalid name {name:?} (use letters, digits, _ or -; not \"{FOREGROUND}\")"
        ));
    }
    Input::SpawnDir {
        name: Some(name.to_string()),
        dir: dir.to_string(),
    }
}

/// Whether `name` can be a job name, hence a principal.
///
/// The character set is the one that survives being printed as `%name` and typed back as `fg
/// %name` without quoting, and [`FOREGROUND`] is reserved so a job can never impersonate the
/// foreground principal.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != FOREGROUND
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

/// Resolves the directory typed at `sd`/`sda` against the job it was typed in.
///
/// Read like a `cd` argument: a relative directory hangs below the current job's, which is what
/// makes `sd api docs` name the `docs` beside the files the prompt is showing rather than one at
/// the top of a seed the session may be deep inside. A leading `/` names the seed root — the only
/// way to reach a sibling of the current job's directory without counting `..`s, and never the
/// filesystem's root, since every path here is seed-relative.
///
/// Only the join is here. Normalizing `.` and `..`, and refusing a path that climbs out of the
/// seed, belong to `ShellMux::open_sandbox`, which is the half that knows where the seed is.
pub fn job_dir(base: &str, dir: &str) -> String {
    if base.is_empty() || dir.starts_with('/') {
        return dir.to_string();
    }
    format!("{base}/{dir}")
}

/// The instrumentation label for an action: the syscall verb, or the git command line that means
/// it.
///
/// The mapping is exact rather than decorative. [`Action::Read`] and [`Action::Edit`] are produced
/// only by the syscall stream, and every other action only by the shell's parse of a recorded git
/// builtin invocation, so each label also names which of the two instrumentation streams observed
/// the capability.
fn action_label(action: &Action) -> String {
    match action {
        Action::Read => "read".to_string(),
        Action::Edit => "edit".to_string(),
        Action::Stage => "git add".to_string(),
        Action::Delete => "git rm".to_string(),
        Action::Unstage => "git restore --staged".to_string(),
        Action::Commit {
            message: Some(message),
        } => format!("git commit -m {message:?}"),
        Action::Commit { message: None } => "git commit".to_string(),
        Action::Checkout => "git checkout HEAD".to_string(),
        Action::Stash => "git stash push".to_string(),
        Action::Clean => "git clean -f".to_string(),
        Action::Diff => "git diff".to_string(),
        Action::History => "git log".to_string(),
    }
}

/// Renders a finished transaction as the lines the console prints in gray.
///
/// The verdict is the point of the console, so every outcome renders the same three things where
/// it has them: the capabilities the command requested, what the authority did with them, and what
/// the user's next move is. A merge names the sequence number it occupies; a denial names every
/// refused capability, the precondition it failed and the fixes that would unblock it; a conflict
/// says plainly that the command must be rerun. Command output is not here: a job writes it
/// straight to the terminal as it runs.
pub fn report_lines(name: &str, outcome: &Result<CmdOutcome, MuxError>) -> Vec<String> {
    let mut lines = Vec::new();
    let push_events = |lines: &mut Vec<String>, events: &[shellmux::Event]| {
        for event in events {
            let label = action_label(&event.action);
            let resource = event.resource.to_string();
            lines.push(format!("%{name}: {label} {resource:?}"));
        }
    };

    match outcome {
        Ok(CmdOutcome::Committed {
            seq,
            exit_code,
            granted,
            ..
        }) => {
            push_events(&mut lines, granted);
            lines.push(format!("%{name} committed seq={seq} exit={exit_code}"));
        }
        Ok(CmdOutcome::DeniedCaps {
            requested, denials, ..
        }) => {
            push_events(&mut lines, requested);
            lines.push(format!(
                "%{name} denied {} of {}:",
                denials.len(),
                requested.len()
            ));
            for denial in denials {
                lines.push(format!(
                    "  - {} {} {}: {}",
                    denial.event.principal,
                    denial.event.action,
                    denial.event.resource,
                    denial.failed_precondition
                ));
                if !denial.allowed_fixes.is_empty() {
                    lines.push(format!("    fix: {}", denial.allowed_fixes.join("; ")));
                }
            }
        }
        Ok(CmdOutcome::StaleSnapshot {
            requested, stale, ..
        }) => {
            push_events(&mut lines, requested);
            lines.push(format!(
                "%{name} stale — rerun (first shell to get caps wins):"
            ));
            for path in stale {
                lines.push(format!(
                    "  - {} merged by seq {}",
                    path.path, path.merged_seq
                ));
            }
        }
        Ok(CmdOutcome::ExecFailed { exit_code, .. }) => {
            lines.push(format!("%{name} failed exit={exit_code} — nothing merged"));
        }
        Ok(CmdOutcome::Unsupported { reason, .. }) => {
            lines.push(format!("%{name} unsupported: {reason}"));
        }
        Err(error) => {
            lines.push(format!("%{name} error: {error}"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use shellmux::{CapDenial, Event, Resource, StalePath};

    #[test]
    fn an_empty_line_asks_for_nothing() {
        assert_eq!(parse(""), Input::Empty);
        assert_eq!(parse("   \t "), Input::Empty);
    }

    #[test]
    fn console_builtins_are_recognized_before_the_shell_sees_them() {
        assert_eq!(parse("jobs"), Input::Jobs);
        assert_eq!(parse("  jobs  "), Input::Jobs);
        assert_eq!(parse("exit"), Input::Exit);
        assert_eq!(parse("exit 1"), Input::Exit);
    }

    #[test]
    fn fg_and_bg_take_one_optional_job_name() {
        assert_eq!(parse("fg"), Input::Fg(None));
        assert_eq!(parse("fg %foo"), Input::Fg(Some("foo".to_string())));
        assert_eq!(parse("fg foo"), Input::Fg(Some("foo".to_string())));
        assert_eq!(parse("bg"), Input::Bg(None));
        assert_eq!(parse("bg %foo"), Input::Bg(Some("foo".to_string())));
        assert_eq!(
            parse("fg a b"),
            Input::Invalid("fg: usage: fg [%NAME]".to_string())
        );
        assert_eq!(
            parse("bg a b"),
            Input::Invalid("bg: usage: bg [%NAME]".to_string())
        );
    }

    /// `kill` is the one console builtin with a real argument grammar, so the grammar stays in the
    /// builtin: the parser only has to keep the tokens — signal flag included — intact and ordered.
    #[test]
    fn kill_passes_its_arguments_through_verbatim() {
        assert_eq!(parse("kill %foo"), Input::Kill(vec!["%foo".to_string()]));
        assert_eq!(
            parse("kill -9 %foo 1234"),
            Input::Kill(vec![
                "-9".to_string(),
                "%foo".to_string(),
                "1234".to_string()
            ])
        );
        assert_eq!(
            parse("kill"),
            Input::Kill(Vec::new()),
            "an argument-less kill is the builtin's usage error to report, not the parser's"
        );
    }

    /// A job name becomes a principal, so the grammar has to refuse the ones that would collide
    /// with the foreground principal or survive a round trip through `%name` badly.
    #[test]
    fn sd_names_a_sandbox_and_sda_numbers_it() {
        assert_eq!(
            parse("sd api ./foo1"),
            Input::SpawnDir {
                name: Some("api".to_string()),
                dir: "./foo1".to_string(),
            }
        );
        assert_eq!(
            parse("sda ./foo1"),
            Input::SpawnDir {
                name: None,
                dir: "./foo1".to_string(),
            }
        );
        for wrong in ["sd", "sd api", "sd api dir extra"] {
            assert_eq!(
                parse(wrong),
                Input::Invalid("sd: usage: sd NAME DIR".to_string()),
                "{wrong}"
            );
        }
        for wrong in ["sda", "sda a b"] {
            assert_eq!(
                parse(wrong),
                Input::Invalid("sda: usage: sda DIR".to_string()),
                "{wrong}"
            );
        }
        assert_eq!(
            parse("sd main ."),
            Input::Invalid(
                "sd: invalid name \"main\" (use letters, digits, _ or -; not \"main\")".to_string()
            ),
            "the foreground principal is reserved"
        );
        assert_eq!(
            parse("sd a/b ."),
            Input::Invalid(
                "sd: invalid name \"a/b\" (use letters, digits, _ or -; not \"main\")".to_string()
            )
        );
    }

    /// The directory typed at `sd` is a path in the job it was typed in. Reading it from the seed
    /// root made `sd api docs` unusable in any session started below the seed root, which is every
    /// session started anywhere but the top of a subvolume.
    #[test]
    fn a_job_directory_hangs_below_the_current_job() {
        assert_eq!(job_dir("marsh", "docs"), "marsh/docs");
        assert_eq!(job_dir("marsh", "docs/how-to"), "marsh/docs/how-to");
        assert_eq!(
            job_dir("marsh", ".."),
            "marsh/..",
            "the mux normalizes; `..` from a job one level down is the seed root"
        );
        assert_eq!(
            job_dir("marsh", "/other"),
            "/other",
            "a leading slash names the seed root, not the current job"
        );
        assert_eq!(
            job_dir("", "docs"),
            "docs",
            "a job at the seed root joins nothing"
        );
    }

    #[test]
    fn a_trailing_ampersand_is_a_job_but_a_double_one_is_an_operator() {
        assert_eq!(parse("sleep 5 &"), Input::Background("sleep 5".to_string()));
        assert_eq!(parse("sleep 5&"), Input::Background("sleep 5".to_string()));
        assert_eq!(parse("a && b"), Input::Foreground("a && b".to_string()));
        assert_eq!(parse("a &&"), Input::Foreground("a &&".to_string()));
        assert_eq!(parse("echo hi"), Input::Foreground("echo hi".to_string()));
        assert_eq!(
            parse("&"),
            Input::Foreground("&".to_string()),
            "an empty command is left for the shell's parser to diagnose"
        );
    }

    /// A commit names the sequence number it occupies and every capability it earned.
    #[test]
    fn a_commit_renders_its_granted_capabilities() {
        let outcome = Ok(CmdOutcome::Committed {
            seq: 7,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            granted: vec![Event::new(
                "main",
                Action::Edit,
                Resource::from(vec!["foo.txt"]),
            )],
            trace_log: PathBuf::from("/tmp/trace.log"),
        });

        assert_eq!(
            report_lines("main", &outcome),
            vec![
                "%main: edit \"foo.txt\"".to_string(),
                "%main committed seq=7 exit=0".to_string(),
            ]
        );
    }

    /// A denial is only actionable if it names the precondition and the way out.
    #[test]
    fn a_denial_renders_its_precondition_and_fixes() {
        let event = Event::new("foo", Action::Stage, Resource::from(vec!["a.txt"]));
        let outcome = Ok(CmdOutcome::DeniedCaps {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            requested: vec![
                Event::new("foo", Action::Edit, Resource::from(vec!["a.txt"])),
                event.clone(),
            ],
            denials: vec![CapDenial {
                event,
                failed_precondition: "no edit precedes the stage".to_string(),
                allowed_fixes: vec!["edit a.txt".to_string(), "git rm a.txt".to_string()],
            }],
            trace_log: PathBuf::from("/tmp/trace.log"),
        });

        assert_eq!(
            report_lines("foo", &outcome),
            vec![
                "%foo: edit \"a.txt\"".to_string(),
                "%foo: git add \"a.txt\"".to_string(),
                "%foo denied 1 of 2:".to_string(),
                "  - foo stage a.txt: no edit precedes the stage".to_string(),
                "    fix: edit a.txt; git rm a.txt".to_string(),
            ]
        );
    }

    /// Losing the race is not an error; the only useful instruction is to rerun.
    #[test]
    fn a_conflict_tells_the_user_to_rerun() {
        let outcome = Ok(CmdOutcome::StaleSnapshot {
            requested: Vec::new(),
            stale: vec![StalePath {
                path: "src/a.txt".to_string(),
                merged_seq: 3,
            }],
            trace_log: PathBuf::from("/tmp/trace.log"),
        });

        assert_eq!(
            report_lines("2", &outcome),
            vec![
                "%2 stale — rerun (first shell to get caps wins):".to_string(),
                "  - src/a.txt merged by seq 3".to_string(),
            ]
        );
    }

    #[test]
    fn other_outcomes_render_distinctly() {
        let failed = Ok(CmdOutcome::ExecFailed {
            exit_code: 130,
            stdout: Vec::new(),
            stderr: Vec::new(),
            trace_log: PathBuf::from("/tmp/trace.log"),
        });
        assert_eq!(
            report_lines("main", &failed),
            vec!["%main failed exit=130 — nothing merged".to_string()]
        );

        let unsupported = Ok(CmdOutcome::Unsupported {
            reason: "git status".to_string(),
            trace_log: PathBuf::from("/tmp/trace.log"),
        });
        assert_eq!(
            report_lines("main", &unsupported),
            vec!["%main unsupported: git status".to_string()]
        );

        let error: Result<CmdOutcome, MuxError> = Err(MuxError::Exec("no strace".to_string()));
        assert_eq!(
            report_lines("foo", &error),
            vec!["%foo error: traced execution failed: no strace".to_string()]
        );
    }

    /// Every git action must name the command line that requested it: the label is the user's only
    /// evidence of *why* a capability was asked for.
    #[test]
    fn every_git_action_names_the_command_that_requested_it() {
        let granted = vec![
            Event::new("1", Action::Delete, Resource::from(vec!["a"])),
            Event::new("1", Action::Unstage, Resource::from(vec!["a"])),
            Event::new(
                "1",
                Action::Commit {
                    message: Some("m".to_string()),
                },
                Resource::from(vec!["a"]),
            ),
            Event::new(
                "1",
                Action::Commit { message: None },
                Resource::from(vec!["a"]),
            ),
            Event::new("1", Action::Checkout, Resource::from(vec!["a"])),
            Event::new("1", Action::Stash, Resource::from(vec!["a"])),
            Event::new("1", Action::Clean, Resource::from(vec!["a"])),
            Event::new("1", Action::Diff, Resource::from(vec!["a"])),
            Event::new("1", Action::History, Resource::from(vec!["a"])),
            Event::new("1", Action::Read, Resource::from(vec!["a"])),
        ];
        let outcome = Ok(CmdOutcome::Committed {
            seq: 1,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            granted,
            trace_log: PathBuf::from("/tmp/trace.log"),
        });

        let lines = report_lines("1", &outcome);
        assert_eq!(
            lines,
            vec![
                "%1: git rm \"a\"".to_string(),
                "%1: git restore --staged \"a\"".to_string(),
                "%1: git commit -m \"m\" \"a\"".to_string(),
                "%1: git commit \"a\"".to_string(),
                "%1: git checkout HEAD \"a\"".to_string(),
                "%1: git stash push \"a\"".to_string(),
                "%1: git clean -f \"a\"".to_string(),
                "%1: git diff \"a\"".to_string(),
                "%1: git log \"a\"".to_string(),
                "%1: read \"a\"".to_string(),
                "%1 committed seq=1 exit=0".to_string(),
            ]
        );
    }
}
