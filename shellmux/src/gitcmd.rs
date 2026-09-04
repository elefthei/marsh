//! The git command grammar, shared by the builtins and the translator.
//!
//! One grammar, two consumers: [`crate::gitshell`]'s git builtins parse their argv with it to decide
//! what to *do*, and [`crate::translate`] parses the recorded argv of a git builtin invocation with
//! it to decide what capability was *requested*. A second parser would be a second opinion, and the
//! whole point of executing git in-process is that the executed operation and the authorized
//! capability cannot disagree.
//!
//! The parse target is therefore the capability vocabulary itself — [`Action`], not some private
//! variant enum. A subcommand that has no [`Action`] has no capability expression and is rejected
//! here rather than approximated later.

use std::path::{Component, Path, PathBuf};

use rust_validator::Action;

/// A parsed git command line: the capability it requests, and the resources it names.
pub(crate) struct GitInvocation {
    /// The capability action the subcommand maps to.
    pub action: Action,
    /// Literal pathspecs, in command-line order, relative to the caller's working directory.
    pub pathspecs: Vec<String>,
}

/// Resolves `path` against `base` and normalizes it lexically.
///
/// No symlink resolution: a pathspec is resolved the way git resolves it (textually, against the
/// caller's working directory), and syscall paths arrive from the trace already kernel-resolved
/// wherever it matters.
pub(crate) fn resolve(base: &Path, path: &str) -> PathBuf {
    let joined = if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        base.join(path)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// The path components of `path` below `root`, or `None` when `path` is not under `root`.
///
/// Only `Component::Normal` parts survive. Callers apply their own predicate to the result: what
/// counts as "names nothing" differs between a repository (the worktree root and `.git/`) and a
/// snapshot (only the root itself).
pub(crate) fn relative_segments(root: &Path, path: &Path) -> Option<Vec<String>> {
    let relative = path.strip_prefix(root).ok()?;
    Some(
        relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect(),
    )
}

/// Parses a git command line (`argv[0]` included) into the capability it requests.
///
/// The `--` separator is optional: `git add foo` and `git add -- foo` are the same request. What is
/// *not* optional is that the request name resources — a command whose target set is implicit (the
/// whole worktree) or computed (a glob) has no capability expression, and is an error here.
pub(crate) fn parse(argv: &[String]) -> Result<GitInvocation, String> {
    let Some(subcommand) = argv.get(1) else {
        return Err("git without a subcommand is not mappable to capabilities".to_string());
    };
    if subcommand.starts_with('-') {
        return Err("git global flags not supported".to_string());
    }
    let subcommand = subcommand.as_str();
    let rest = &argv[2..];

    // Reserved leading words that are part of the subcommand's grammar rather than its target set.
    let reserved = match subcommand {
        "checkout" => 1, // the revision, which must be HEAD
        "stash" => 1,    // the stash subcommand, which must be push
        _ => 0,
    };

    let (flags, revisions, pathspecs) =
        if let Some(separator) = rest.iter().position(|arg| arg == "--") {
            let (flags, before) = split_flags(&rest[..separator]);
            (flags, before, rest[separator + 1..].to_vec())
        } else {
            let (flags, mut positionals) = split_flags(rest);
            let pathspecs = positionals.split_off(positionals.len().min(reserved));
            (flags, positionals, pathspecs)
        };
    if revisions.len() != reserved {
        return Err(format!(
            "git {subcommand} expects {reserved} leading argument(s), got {revisions:?}"
        ));
    }

    let action = match subcommand {
        "add" | "stage" => Action::Stage,
        "rm" => Action::Delete,
        "commit" => Action::Commit {
            message: commit_message(&flags)?,
        },
        // `git restore --staged` moves HEAD into the index, which is exactly `Action::Unstage`.
        // Without `--staged` it moves the *index* into the worktree, and no capability says that:
        // `Action::Checkout` means HEAD into worktree and index, which is `git checkout HEAD`. One
        // action must have exactly one execution, so the index-sourced form is refused.
        "restore" => {
            if flags.iter().any(|flag| flag == "--staged") {
                Action::Unstage
            } else {
                return Err("git restore without --staged is not a capability; \
                     use git checkout HEAD -- <path>"
                    .to_string());
            }
        }
        "checkout" => {
            if revisions[0] != "HEAD" {
                return Err(format!(
                    "git checkout of {:?} is not mappable to capabilities",
                    revisions[0]
                ));
            }
            Action::Checkout
        }
        "stash" => {
            if revisions[0] != "push" {
                return Err("only `git stash push` is mappable to capabilities".to_string());
            }
            Action::Stash
        }
        "clean" => {
            if !flags.iter().any(|flag| flag == "-f" || flag == "--force") {
                return Err("git clean requires -f".to_string());
            }
            Action::Clean
        }
        "diff" => Action::Diff,
        "log" => Action::History,
        other => return Err(format!("git {other} not mappable to capabilities")),
    };

    if pathspecs.is_empty() {
        return Err(format!("git {subcommand} with an empty pathspec list"));
    }
    for pathspec in &pathspecs {
        if pathspec.contains(['*', '?', '[']) {
            return Err(format!(
                "git pathspec pattern {pathspec:?} is not a resource"
            ));
        }
    }

    Ok(GitInvocation { action, pathspecs })
}

/// Separates flags from positional arguments.
///
/// The value of a `-m`/`--message` flag stays with the flags, immediately after it, so
/// [`commit_message`] can read the pairs regardless of where they appeared on the command line.
fn split_flags(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut flags = Vec::new();
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg.starts_with('-') {
            flags.push(arg.clone());
            if (arg == "-m" || arg == "--message" || arg == "-F" || arg == "--file")
                && let Some(value) = args.get(index + 1)
            {
                flags.push(value.clone());
                index += 2;
                continue;
            }
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }
    (flags, positionals)
}

/// Extracts a commit message from `git commit` flags: `-m`/`--message` values joined by a blank
/// line, exactly as git composes multiple `-m` paragraphs.
fn commit_message(flags: &[String]) -> Result<Option<String>, String> {
    let mut messages: Vec<String> = Vec::new();
    let mut index = 0;
    while index < flags.len() {
        let flag = flags[index].as_str();
        if flag == "-F" || flag == "--file" || flag.starts_with("--file=") {
            return Err("git commit -F/--file is not mappable to capabilities".to_string());
        }
        if flag == "-m" || flag == "--message" {
            let value = flags
                .get(index + 1)
                .ok_or_else(|| "git commit -m without a message".to_string())?;
            messages.push(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = flag.strip_prefix("--message=") {
            messages.push(value.to_string());
        } else if let Some(value) = flag.strip_prefix("-m").filter(|value| !value.is_empty()) {
            messages.push(value.to_string());
        }
        index += 1;
    }
    if messages.is_empty() {
        Ok(None)
    } else {
        Ok(Some(messages.join("\n\n")))
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn parse_argv(argv: &[&str]) -> Result<GitInvocation, String> {
        let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
        parse(&argv)
    }

    /// The three callers differ only in what they reject afterwards, so the split has to be exact.
    #[test]
    fn relative_segments_names_every_normal_component_below_the_root() {
        let root = Path::new("/work");
        assert_eq!(
            relative_segments(root, Path::new("/work/foo1/src/a.txt")),
            Some(vec![
                "foo1".to_string(),
                "src".to_string(),
                "a.txt".to_string()
            ])
        );
        assert_eq!(
            relative_segments(root, Path::new("/work")),
            Some(Vec::new())
        );
        assert_eq!(relative_segments(root, Path::new("/elsewhere/a.txt")), None);
    }

    #[test]
    fn subcommands_map_to_their_capabilities() {
        let cases: [(&[&str], Action); 11] = [
            (&["git", "add", "--", "src/a.txt"], Action::Stage),
            (&["git", "stage", "--", "src/a.txt"], Action::Stage),
            (&["git", "rm", "--", "src/a.txt"], Action::Delete),
            (
                &["git", "commit", "-m", "step 7", "--", "src/a.txt"],
                Action::commit("step 7"),
            ),
            (
                &["git", "restore", "--staged", "--", "src/a.txt"],
                Action::Unstage,
            ),
            (
                &["git", "checkout", "HEAD", "--", "src/a.txt"],
                Action::Checkout,
            ),
            (&["git", "stash", "push", "--", "src/a.txt"], Action::Stash),
            (&["git", "clean", "-f", "--", "src/a.txt"], Action::Clean),
            (&["git", "diff", "--", "src/a.txt"], Action::Diff),
            (&["git", "log", "--", "src/a.txt"], Action::History),
            // The separator is optional; the builtin owns its grammar.
            (&["git", "add", "src/a.txt"], Action::Stage),
        ];
        for (argv, action) in cases {
            let invocation = parse_argv(argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
            assert_eq!(invocation.action, action, "{argv:?}");
            assert_eq!(
                invocation.pathspecs,
                vec!["src/a.txt".to_string()],
                "{argv:?}"
            );
        }
    }

    #[test]
    fn reserved_words_and_flag_values_are_not_pathspecs() {
        let cases: [(&[&str], Action); 4] = [
            (&["git", "checkout", "HEAD", "src/a.txt"], Action::Checkout),
            (&["git", "stash", "push", "src/a.txt"], Action::Stash),
            (
                &["git", "commit", "-m", "step 7", "src/a.txt"],
                Action::commit("step 7"),
            ),
            (&["git", "clean", "-f", "src/a.txt"], Action::Clean),
        ];
        for (argv, action) in cases {
            let invocation = parse_argv(argv).unwrap_or_else(|error| panic!("{argv:?}: {error}"));
            assert_eq!(invocation.action, action, "{argv:?}");
            assert_eq!(
                invocation.pathspecs,
                vec!["src/a.txt".to_string()],
                "{argv:?}"
            );
        }
    }

    #[test]
    fn multiple_pathspecs_and_messages_are_preserved() {
        let invocation = parse_argv(&[
            "git", "commit", "-m", "one", "-m", "two", "--", "a.txt", "b.txt",
        ])
        .expect("parse");
        assert_eq!(invocation.action, Action::commit("one\n\ntwo"));
        assert_eq!(
            invocation.pathspecs,
            vec!["a.txt".to_string(), "b.txt".to_string()]
        );
        assert_eq!(
            parse_argv(&["git", "commit", "-mshort", "--", "a.txt"])
                .expect("parse")
                .action,
            Action::commit("short"),
            "the attached form is the same message"
        );
        assert_eq!(
            parse_argv(&["git", "commit", "--message=long", "--", "a.txt"])
                .expect("parse")
                .action,
            Action::commit("long"),
        );
    }

    #[test]
    fn unmappable_command_lines_are_rejected() {
        let cases: [(&[&str], &str); 12] = [
            (&["git"], "without a subcommand"),
            (&["git", "--version"], "global flags"),
            (&["git", "push", "--", "a.txt"], "not mappable"),
            (&["git", "status", "--", "a.txt"], "not mappable"),
            (&["git", "add"], "empty pathspec list"),
            (&["git", "add", "--"], "empty pathspec list"),
            (&["git", "add", "--", "src/*.txt"], "pathspec pattern"),
            (&["git", "restore", "--", "a.txt"], "use git checkout HEAD"),
            (
                &["git", "checkout", "other-branch", "--", "a.txt"],
                "not mappable",
            ),
            (&["git", "checkout", "--", "a.txt"], "leading argument"),
            (&["git", "stash", "pop", "--", "a.txt"], "stash push"),
            (&["git", "clean", "--", "a.txt"], "requires -f"),
        ];
        for (argv, expected) in cases {
            let error = parse_argv(argv)
                .err()
                .unwrap_or_else(|| panic!("{argv:?} parsed"));
            assert!(error.contains(expected), "{argv:?} reported {error:?}");
        }
    }

    #[test]
    fn a_message_file_is_not_a_message() {
        let error = parse_argv(&["git", "commit", "-F", "msg.txt", "--", "a.txt"])
            .err()
            .expect("rejected");
        assert!(error.contains("-F/--file"), "got {error:?}");
        assert_eq!(
            parse_argv(&["git", "commit", "--", "a.txt"])
                .expect("parse")
                .action,
            Action::commit_without_message(),
            "no -m at all is a missing message, not an error: the builtin refuses it, and the \
             policy distinguishes a missing message from an empty one"
        );
    }
}
