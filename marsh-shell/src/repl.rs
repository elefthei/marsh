//! The console's line grammar and its report text: everything about a submitted line that is a
//! pure function of the line, and everything about a finished transaction that is a pure function
//! of its outcome.
//!
//! Both halves live here because both are the parts of the front-end that can be *proved*. Job
//! control, terminal handoff and mux calls are all effects; parsing `sd foo ./api` and
//! rendering `%foo denied 1 of 2:` are not, so they are separated out and unit-tested directly.
//!
//! The grammar is deliberately tiny and resolved *before* any brush parsing: the console builtins
//! (`jobs`, `fg`, `bg`, `stop`, `close`, `kill`, `exit`, `sd`, `sda`, and the trailing `&`) never
//! reach the text, because the shell that composes the prompt is not the shell that runs commands
//! — every real command line is handed to a traced job instead.

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
    /// Signal process ids; the tokens are passed through verbatim, signal flag included.
    Kill(Vec<String>),
    /// Signal a job's process group; the tokens are the optional signal flag and the job's name.
    Stop(Vec<String>),
    /// End a job; `None` is the builtin's usage error to report.
    Close(Option<String>),
    /// Create a named sandbox rooted at a seed directory.
    SpawnDir {
        /// The job's name, which is also its principal; `None` takes the next number.
        name: Option<String>,
        /// The directory as typed, resolved against the current job by [`job_dir`].
        dir: String,
    },
    /// Start the line in a job of its own, without waiting for it (a trailing `&`), `&` stripped.
    Background {
        /// The command line, with the `&` form removed.
        cmd: String,
        /// The job's name; `None` takes the next number, as `sda` does.
        name: Option<String>,
    },
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
#[allow(
    clippy::string_slice,
    reason = "`first` is a prefix of the trimmed line, so its length is a char boundary in it"
)]
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
        "fg" => Input::Fg(job_reference(&line[first.len()..])),
        "bg" => Input::Bg(job_reference(&line[first.len()..])),
        // `kill` keeps its argv verbatim — the signal flag and every target are the builtin's to
        // interpret, exactly as in bash, where `kill -9 1234 5678` is one invocation. Its tokens
        // stay whitespace-split because a process id never has spaces in it.
        "kill" => Input::Kill(rest.iter().map(|token| (*token).to_string()).collect()),
        "stop" => stop(line[first.len()..].trim()),
        "close" => Input::Close(job_reference(&line[first.len()..])),
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
        // A trailing `&`, `&NAME` or `&"NAME"` opens a job; `&&` is an operator and belongs to the
        // command line.
        _ => background(line).unwrap_or_else(|| Input::Foreground(line.to_string())),
    }
}

/// The `Input` a trailing `&`, `&NAME` or `&"NAME"` asks for, or `None` when the line has neither.
///
/// The `&` that opens a job may not be preceded by another one, so `a && b` and `a &&b` stay whole
/// command lines. A bare `&NAME` is recognized only when `NAME` is a single word of name
/// characters, which is what keeps `echo a & b` — a `&` with a space after it — a command line as
/// well. The quoted form is looked for only when the line *ends* with `"`, takes the last `&"`
/// before it, and is abandoned when what that yields contains a `"` of its own — which is what
/// keeps a command line like `grep -e "&" -f "x"` whole rather than reading `-f "x` as a job name.
#[allow(
    clippy::string_slice,
    reason = "every index here is a byte offset of an ASCII `&` or `\"` this scanner matched, so it is always a char boundary"
)]
fn background(line: &str) -> Option<Input> {
    let (start, name) = if let Some(head) = line.strip_suffix('"') {
        let start = head.rfind("&\"")?;
        let name = &head[start + 2..];
        if name.contains('"') {
            return None;
        }
        (start, Some(name))
    } else if let Some(head) = line.strip_suffix('&') {
        (head.len(), None)
    } else {
        let start = line.rfind('&')?;
        let name = &line[start + 1..];
        if !shellmux::bare_job_name(name) {
            return None;
        }
        (start, Some(name))
    };
    if start == 0 || line.as_bytes()[start - 1] == b'&' {
        return None;
    }
    let cmd = line[..start].trim_end();
    if cmd.is_empty() {
        return None;
    }
    Some(match name {
        None => Input::Background {
            cmd: cmd.to_string(),
            name: None,
        },
        Some(name) => named_background(cmd, name),
    })
}

/// A named background line, or the diagnostic for a name a job may not answer to.
///
/// `%` is how a job is marked inside a line of prose and comes off the front of a typed reference,
/// and `"` is the quote that wraps one, so neither may appear in a name; a control character would
/// corrupt the table the name is printed in; and [`FOREGROUND`] is the one name already taken.
fn named_background(cmd: &str, name: &str) -> Input {
    if name == FOREGROUND {
        return Input::Invalid(format!(
            "&: invalid job name {name:?} ({FOREGROUND:?} is the foreground job)"
        ));
    }
    if name.is_empty() || name.chars().any(|c| c == '%' || c == '"' || c.is_control()) {
        return Input::Invalid(format!(
            "&: invalid job name {name:?} (not empty, and no % or \")"
        ));
    }
    Input::Background {
        cmd: cmd.to_string(),
        name: Some(name.to_string()),
    }
}

/// The job a `fg`, `bg` or `stop` argument names, or `None` when there is no argument.
///
/// The whole rest of the line is the name, because each of those builtins takes exactly one job and
/// a job name may hold spaces: `fg a long name` needs no quoting. `"a long name"` is the one
/// accepted wrapping — what `&"a long name"` opened the job with, and what `jobs` prints it as —
/// and it is the way to reach a name the bare form cannot, one that begins with `-` or ends in a
/// space. One leading `%` comes off as well, so a row copied out of `jobs`, which writes
/// `%"a long name"`, pastes back unchanged.
fn job_reference(text: &str) -> Option<String> {
    let text = text.trim();
    let text = text.strip_prefix('%').unwrap_or(text);
    let name = text
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(text);
    (!name.is_empty()).then(|| name.to_string())
}

/// Parses `stop [-SIGNAL] JOB`.
///
/// The signal comes off the front by its leading `-`, and everything after it is the job — one
/// name, however it was wrapped. A job actually named like a flag is reachable as `stop "-9"`,
/// because the split happens before the unwrapping.
fn stop(text: &str) -> Input {
    let (signal, job) = match text.split_once(char::is_whitespace) {
        Some((flag, rest)) if flag.starts_with('-') => (Some(flag), rest),
        _ => (None, text),
    };
    let mut args: Vec<String> = signal.into_iter().map(str::to_string).collect();
    args.extend(job_reference(job));
    Input::Stop(args)
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

/// Whether `name` can be a job name typed as a single word, hence a principal.
///
/// [`FOREGROUND`] is reserved so a job can never impersonate the foreground principal. A name with
/// spaces is printed `%"like this"` — see [`shellmux::job_ref`] — and is validated where it is
/// created, by the trailing `&`.
pub fn valid_name(name: &str) -> bool {
    shellmux::bare_job_name(name) && name != FOREGROUND
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
/// seed, belong to `ShellMux::spawn`, which is the half that knows where the seed is.
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
    let job = shellmux::job_ref(name);
    let push_events = |lines: &mut Vec<String>, events: &[shellmux::Event]| {
        for event in events {
            let label = action_label(&event.action);
            let resource = event.resource.to_string();
            lines.push(format!("{job}: {label} {resource:?}"));
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
            lines.push(format!("{job} committed seq={seq} exit={exit_code}"));
        }
        Ok(CmdOutcome::DeniedCaps {
            requested, denials, ..
        }) => {
            push_events(&mut lines, requested);
            lines.push(format!(
                "{job} denied {} of {}:",
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
                "{job} stale — rerun (first shell to get caps wins):"
            ));
            for path in stale {
                lines.push(format!(
                    "  - {} merged by seq {}",
                    path.path, path.merged_seq
                ));
            }
        }
        Ok(CmdOutcome::ExecFailed { exit_code, .. }) => {
            lines.push(format!("{job} failed exit={exit_code} — nothing merged"));
        }
        Ok(CmdOutcome::Unsupported { reason, .. }) => {
            lines.push(format!("{job} unsupported: {reason}"));
        }
        Ok(CmdOutcome::Bypassed {
            exit_code, granted, ..
        }) => {
            push_events(&mut lines, granted);
            lines.push(format!(
                "{job} read-only exit={exit_code} — no snapshot, nothing to merge"
            ));
        }
        Ok(CmdOutcome::Escaped {
            exit_code,
            requested,
            wrote,
            ..
        }) => {
            lines.push(format!(
                "{job} escaped exit={exit_code} — vouched for as read-only, but it did more:"
            ));
            if *wrote {
                lines.push(
                    "  - wrote inside the tree it read; nothing reached the seed".to_string(),
                );
            }
            push_events(&mut lines, requested);
            lines.push(format!("{job} will run as a transaction from now on"));
        }
        Err(error) => {
            lines.push(format!("{job} error: {error}"));
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
        assert_eq!(parse("fg foo"), Input::Fg(Some("foo".to_string())));
        assert_eq!(parse("bg"), Input::Bg(None));
        assert_eq!(parse("bg foo"), Input::Bg(Some("foo".to_string())));
        assert_eq!(
            parse("fg a b"),
            Input::Fg(Some("a b".to_string())),
            "the rest of the line is the name: fg takes one job, so nothing else could be meant"
        );
    }

    /// A job name may hold spaces and a builtin that takes one job needs no quoting to find it,
    /// but the quoted form resolves too: it is what `&"…"` opened the job with and what `jobs`
    /// prints, so a row of the table pastes straight back.
    #[test]
    fn a_job_is_named_bare_or_quoted() {
        for text in ["a name", "\"a name\"", "%\"a name\"", "  a name  "] {
            assert_eq!(
                parse(&format!("fg {text}")),
                Input::Fg(Some("a name".to_string())),
                "{text}"
            );
        }
        assert_eq!(
            parse("stop -9 a name"),
            Input::Stop(vec!["-9".to_string(), "a name".to_string()]),
            "the leading flag is the signal; everything after it is the job"
        );
        assert_eq!(
            parse("stop \"-9\""),
            Input::Stop(vec!["-9".to_string()]),
            "and a job named like a flag is reachable, because the split precedes the unwrapping"
        );
        assert_eq!(parse("stop build"), Input::Stop(vec!["build".to_string()]));
        assert_eq!(
            parse("stop"),
            Input::Stop(Vec::new()),
            "an argument-less stop is the builtin's usage error to report, not the parser's"
        );
        assert_eq!(
            parse("close a name"),
            Input::Close(Some("a name".to_string()))
        );
        assert_eq!(
            parse("close %\"a name\""),
            Input::Close(Some("a name".to_string())),
            "a row copied out of the job table pastes back"
        );
        assert_eq!(
            parse("close"),
            Input::Close(None),
            "an argument-less close is the builtin's usage error to report, not the parser's"
        );
        assert_eq!(
            parse("kill -9 1234"),
            Input::Kill(vec!["-9".to_string(), "1234".to_string()]),
            "kill keeps its verbatim tokens, and jobs are stop's now"
        );
    }

    /// `kill` is the one console builtin with a real argument grammar, so the grammar stays in the
    /// builtin: the parser only has to keep the tokens — signal flag included — intact and ordered.
    #[test]
    fn kill_passes_its_arguments_through_verbatim() {
        assert_eq!(parse("kill 1234"), Input::Kill(vec!["1234".to_string()]));
        assert_eq!(
            parse("kill -9 1234 5678"),
            Input::Kill(vec![
                "-9".to_string(),
                "1234".to_string(),
                "5678".to_string()
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
        assert_eq!(
            parse("sleep 5 &"),
            Input::Background {
                cmd: "sleep 5".to_string(),
                name: None,
            }
        );
        assert_eq!(
            parse("sleep 5&"),
            Input::Background {
                cmd: "sleep 5".to_string(),
                name: None,
            }
        );
        assert_eq!(parse("a && b"), Input::Foreground("a && b".to_string()));
        assert_eq!(parse("a &&"), Input::Foreground("a &&".to_string()));
        assert_eq!(parse("echo hi"), Input::Foreground("echo hi".to_string()));
        assert_eq!(
            parse("&"),
            Input::Foreground("&".to_string()),
            "an empty command is left for the shell's parser to diagnose"
        );
    }

    #[test]
    fn an_ampersand_can_name_the_job_it_opens() {
        assert_eq!(
            parse("echo foo &api"),
            Input::Background {
                cmd: "echo foo".to_string(),
                name: Some("api".to_string()),
            }
        );
        assert_eq!(
            parse("echo foo &\"a long name\""),
            Input::Background {
                cmd: "echo foo".to_string(),
                name: Some("a long name".to_string()),
            },
            "quoting is the only way to name a job with spaces in it"
        );
        assert_eq!(
            parse("echo \"x\" &\"parse\""),
            Input::Background {
                cmd: "echo \"x\"".to_string(),
                name: Some("parse".to_string()),
            },
            "the last `&\"` wins, so a command holding quotes of its own survives"
        );
        assert_eq!(
            parse("echo \"a\" &"),
            Input::Background {
                cmd: "echo \"a\"".to_string(),
                name: None,
            },
            "the quoted form is only looked for when the line ends with a quote"
        );
        assert_eq!(
            parse("grep -e \"&\" -f \"x\""),
            Input::Foreground("grep -e \"&\" -f \"x\"".to_string()),
            "a candidate name holding a quote of its own is no name, and the line stays a command"
        );
        assert_eq!(
            parse("echo a & b"),
            Input::Foreground("echo a & b".to_string()),
            "a space after the & is not a job name"
        );
        assert_eq!(
            parse("a &&b"),
            Input::Foreground("a &&b".to_string()),
            "the operator is still an operator with no space after it"
        );
        assert_eq!(
            parse("echo x &\"main\""),
            Input::Invalid(
                "&: invalid job name \"main\" (\"main\" is the foreground job)".to_string()
            )
        );
        assert_eq!(
            parse("echo x &\"\""),
            Input::Invalid("&: invalid job name \"\" (not empty, and no % or \")".to_string())
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

    /// A bypass merges nothing, but its reads did reach the authority and take their read claims,
    /// so the report has to name them — they are what another principal will be held to.
    #[test]
    fn a_bypassed_command_names_the_reads_it_declared() {
        let outcome = Ok(CmdOutcome::Bypassed {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            granted: vec![Event::new(
                "main",
                Action::Read,
                Resource::from(vec!["a.txt"]),
            )],
            trace_log: PathBuf::from("/tmp/trace.log"),
        });
        assert_eq!(
            report_lines("main", &outcome),
            vec![
                "%main: read \"a.txt\"".to_string(),
                "%main read-only exit=0 — no snapshot, nothing to merge".to_string(),
            ]
        );
    }

    /// An escape is contained by the reader tree, but nothing in it was authorized, so the report
    /// has to list the write and every capability the authority never saw.
    #[test]
    fn an_escape_lists_what_the_authority_never_saw() {
        let outcome = Ok(CmdOutcome::Escaped {
            exit_code: 0,
            requested: vec![
                Event::new("main", Action::Edit, Resource::from(vec!["a.txt"])),
                Event::new("main", Action::Read, Resource::from(vec!["b.txt"])),
            ],
            wrote: true,
            trace_log: PathBuf::from("/tmp/trace.log"),
        });
        assert_eq!(
            report_lines("main", &outcome),
            vec![
                "%main escaped exit=0 — vouched for as read-only, but it did more:".to_string(),
                "  - wrote inside the tree it read; nothing reached the seed".to_string(),
                "%main: edit \"a.txt\"".to_string(),
                "%main: read \"b.txt\"".to_string(),
                "%main will run as a transaction from now on".to_string(),
            ]
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
