//! The console's line grammar and its report text: everything about a submitted line that is a
//! pure function of the line, and everything about a finished transaction that is a pure function
//! of its outcome.
//!
//! Both halves live here because both are the parts of the front-end that can be *proved*. Job
//! control, terminal handoff and mux calls are all effects; parsing `spawn foo git add x` and
//! rendering `%foo denied 1 of 2:` are not, so they are separated out and unit-tested directly.
//!
//! The grammar is deliberately tiny and resolved *before* any brush parsing: the console builtins
//! (`jobs`, `fg`, `bg`, `kill`, `exit`, `spawn`, and the trailing `&`) never reach the shell as
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
    /// Start a named background job. `cmd` is the raw remainder of the line, quoting intact.
    Spawn {
        /// The job's name, which is also its principal.
        name: String,
        /// The command line to run.
        cmd: String,
    },
    /// Start an auto-named background job (a trailing `&`), with the `&` stripped.
    Background(String),
    /// Run the line as the foreground job.
    Foreground(String),
    /// The line named a console builtin but got its arguments wrong; the message is for stderr.
    Invalid(String),
}

/// Parses one submitted line.
///
/// Dispatch is on the first token of the trimmed line, so a console builtin is recognized before
/// anything else can interpret it. `spawn` is parsed here rather than registered as a brush builtin
/// for one decisive reason: a builtin receives word-split, expansion-processed argv, and rebuilding
/// a command *string* from it would need lossy re-quoting. Taking the raw remainder of the line
/// keeps `spawn foo sh -c 'sleep 1; echo hi'` byte-exact.
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
        "spawn" => spawn(line),
        // A trailing `&` is a background job; `&&` is an operator and belongs to the command line.
        _ => {
            if line.ends_with('&') && !line.ends_with("&&") {
                let cmd = line[..line.len() - 1].trim_end();
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

/// Parses `spawn NAME CMD…`, keeping `CMD…` as the verbatim remainder of `line`.
fn spawn(line: &str) -> Input {
    const USAGE: &str = "spawn: usage: spawn NAME CMD…";
    let after_verb = line["spawn".len()..].trim_start();
    let name_len = after_verb
        .find(char::is_whitespace)
        .unwrap_or(after_verb.len());
    let (name, cmd) = after_verb.split_at(name_len);
    let cmd = cmd.trim_start();
    if name.is_empty() || cmd.is_empty() {
        return Input::Invalid(USAGE.to_string());
    }
    if !valid_name(name) {
        return Input::Invalid(format!(
            "spawn: invalid name {name:?} (use letters, digits, _ or -; not \"{FOREGROUND}\")"
        ));
    }
    Input::Spawn {
        name: name.to_string(),
        cmd: cmd.to_string(),
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
        Ok(CmdOutcome::Merged {
            seq,
            exit_code,
            granted,
            ..
        }) => {
            push_events(&mut lines, granted);
            lines.push(format!("%{name} merged seq={seq} exit={exit_code}"));
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

    #[test]
    fn spawn_keeps_its_command_line_verbatim() {
        assert_eq!(
            parse("spawn foo echo 'a b'"),
            Input::Spawn {
                name: "foo".to_string(),
                cmd: "echo 'a b'".to_string(),
            },
            "quoting survives because the remainder is taken raw, never re-joined from tokens"
        );
        assert_eq!(
            parse("spawn"),
            Input::Invalid("spawn: usage: spawn NAME CMD…".to_string())
        );
        assert_eq!(
            parse("spawn foo"),
            Input::Invalid("spawn: usage: spawn NAME CMD…".to_string())
        );
        assert_eq!(
            parse("spawn main x"),
            Input::Invalid(
                "spawn: invalid name \"main\" (use letters, digits, _ or -; not \"main\")"
                    .to_string()
            ),
            "the foreground principal is reserved"
        );
        assert_eq!(
            parse("spawn a/b x"),
            Input::Invalid(
                "spawn: invalid name \"a/b\" (use letters, digits, _ or -; not \"main\")"
                    .to_string()
            )
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

    /// A merge names the sequence number it occupies and every capability it earned.
    #[test]
    fn a_merge_renders_its_granted_capabilities() {
        let outcome = Ok(CmdOutcome::Merged {
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
                "%main merged seq=7 exit=0".to_string(),
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
        let outcome = Ok(CmdOutcome::Merged {
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
                "%1 merged seq=1 exit=0".to_string(),
            ]
        );
    }
}
