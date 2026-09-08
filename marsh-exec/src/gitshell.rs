//! The shell every command runs in: standard builtins, git builtins, and no forkable git.
//!
//! Shell construction lives here rather than in the executor binary because the embedded-shell test
//! and the executor must run the *same* shell — a builtin set that differed between them would make
//! the in-memory hook log evidence about a shell nobody executes.
//!
//! Git is registered as **builtins**, one per command variant (`"git add"`, `"git commit"`, …),
//! which the vendored two-token lookup resolves before the single-token name. The single-token
//! `"git"` is registered too, as a catch-all that refuses: together they guarantee no `git` process
//! is ever spawned, because PATH search is never reached. Refusing `git status` and the rest of
//! plumbing is the deliberate price of that guarantee.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brush_builtins::BuiltinSet;
use brush_core::builtins::{self, Registration};
use brush_core::extensions::DefaultShellExtensions;
use brush_core::{ExecutionContext, ExecutionResult, Shell, ShellExtensions};

use crate::gitcmd;
use crate::gitexec;
use crate::hooks::RecordingHook;

/// Environment variable naming the job's snapshot root.
///
/// The root is the boundary a git builtin may not search past. The mux sets it per command; a
/// shell built without it (the embedded-shell test) searches ancestors as git itself would.
pub const SNAPSHOT_ROOT_VAR: &str = "MARSH_SNAPSHOT_ROOT";

/// Exit code for a git command line this shell cannot express as a capability.
const UNMAPPABLE: u8 = 2;
/// Exit code git uses for `fatal:` conditions.
const FATAL: u8 = 128;

/// The git command variants that exist as builtins, each a two-token builtin name.
const GIT_VARIANTS: [&str; 10] = [
    "add", "stage", "rm", "commit", "restore", "checkout", "stash", "clean", "diff", "log",
];

/// Builds the shell a command runs in, optionally instrumented by `hook`.
///
/// Profile and rc files are skipped: a command's capability footprint must be the command's, not the
/// host user's shell configuration. The working directory is inherited from the caller.
pub async fn build_shell(
    hook: Option<Arc<RecordingHook>>,
) -> Result<Shell<DefaultShellExtensions>, brush_core::Error> {
    let mut standard =
        brush_builtins::default_builtins::<DefaultShellExtensions>(BuiltinSet::BashMode);
    // `exec` replaces the process image, which would skip the executor's end-of-run record dump and
    // lose every builtin record of the command. A shell that cannot report is not the shell this
    // project runs commands in.
    standard.remove("exec");

    let mut builder = Shell::builder()
        .interactive(false)
        .no_editing(true)
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
        .builtins(standard)
        .builtins(git_builtins());
    if let Some(hook) = hook {
        builder = builder.builtin_hook(hook);
    }
    builder.build().await
}

/// The git registrations: one per supported variant, plus the refusing catch-all.
fn git_builtins() -> Vec<(String, Registration<DefaultShellExtensions>)> {
    let mut registrations: Vec<(String, Registration<DefaultShellExtensions>)> = GIT_VARIANTS
        .iter()
        .map(|variant| {
            (
                format!("git {variant}"),
                builtins::builtin::<GitBuiltin, DefaultShellExtensions>(),
            )
        })
        .collect();
    registrations.push((
        "git".to_string(),
        builtins::builtin::<GitUnsupported, DefaultShellExtensions>(),
    ));
    registrations
}

/// One registered git variant. Argv is kept verbatim and parsed by [`gitcmd`]; clap is bypassed.
#[derive(clap::Parser)]
struct GitBuiltin {
    /// The command's own argument vector, `argv[0]` included.
    #[clap(allow_hyphen_values = true, num_args = 0..)]
    args: Vec<String>,
}

impl builtins::Command for GitBuiltin {
    type Error = brush_core::Error;

    fn new<I>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = String>,
    {
        Ok(Self {
            args: args.into_iter().collect(),
        })
    }

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let invocation = match gitcmd::parse(&self.args) {
            Ok(invocation) => invocation,
            Err(reason) => {
                writeln!(context.stderr(), "git: {reason}")?;
                return Ok(ExecutionResult::new(UNMAPPABLE));
            }
        };

        let cwd = context.shell.working_dir().to_path_buf();
        let boundary = context
            .shell
            .env_str(SNAPSHOT_ROOT_VAR)
            .map_or_else(|| PathBuf::from("/"), |value| PathBuf::from(&*value));
        let Some(repo_root) = repo_root(&cwd, &boundary) else {
            writeln!(
                context.stderr(),
                "fatal: not a git repository (or any of the parent directories): .git"
            )?;
            return Ok(ExecutionResult::new(FATAL));
        };

        let mut resolved = Vec::with_capacity(invocation.pathspecs.len());
        for pathspec in &invocation.pathspecs {
            let absolute = gitcmd::resolve(&cwd, pathspec);
            let Some(relative) = repo_relative(&repo_root, &absolute) else {
                writeln!(
                    context.stderr(),
                    "git: pathspec {pathspec:?} is outside the repository or inside .git/"
                )?;
                return Ok(ExecutionResult::new(UNMAPPABLE));
            };
            resolved.push(relative);
        }

        let identities = ["AUTHOR", "COMMITTER"].map(|who| {
            gitexec::identity_from_env(
                |name| context.shell.env_str(name).map(|value| value.into_owned()),
                who,
            )
        });
        let [author, committer] = match identities {
            [Ok(author), Ok(committer)] => [author, committer],
            [Err(reason), _] | [_, Err(reason)] => {
                writeln!(context.stderr(), "fatal: {reason}")?;
                return Ok(ExecutionResult::new(FATAL));
            }
        };

        let invocation = gitcmd::GitInvocation {
            action: invocation.action,
            pathspecs: resolved,
        };
        let code = gitexec::run(
            &invocation,
            &repo_root,
            &author,
            &committer,
            &mut context.stdout(),
            &mut context.stderr(),
        );
        #[expect(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "git exit codes are 0..=128"
        )]
        Ok(ExecutionResult::new(code as u8))
    }
}

/// The catch-all `git` builtin: every git command line that is not a supported variant.
///
/// Its existence is the no-fork guarantee. Without it, `git status` would fall through to a PATH
/// search and run a real git process whose effects no hook records.
#[derive(clap::Parser)]
struct GitUnsupported {
    /// The command's own argument vector, `argv[0]` included.
    #[clap(allow_hyphen_values = true, num_args = 0..)]
    args: Vec<String>,
}

impl builtins::Command for GitUnsupported {
    type Error = brush_core::Error;

    fn new<I>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = String>,
    {
        Ok(Self {
            args: args.into_iter().collect(),
        })
    }

    async fn execute<SE: ShellExtensions>(
        &self,
        context: ExecutionContext<'_, SE>,
    ) -> Result<ExecutionResult, Self::Error> {
        let subcommand = self.args.get(1).map_or("", String::as_str);
        writeln!(
            context.stderr(),
            "marsh: git {subcommand}: only these git commands are available as builtins: {}",
            GIT_VARIANTS.join(", ")
        )?;
        Ok(ExecutionResult::general_error())
    }
}

/// The nearest ancestor of `start` (inclusive) that contains a `.git` entry, never searching above
/// `boundary`.
///
/// The bound keeps a git command from climbing out of the job's snapshot and opening a repository
/// beside it. The snapshot root carries a repository only when the user's seed does; a seed may
/// hold none, one, or many, at any depth.
pub fn repo_root(start: &Path, boundary: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        if !directory.starts_with(boundary) {
            return None;
        }
        if directory.join(".git").exists() {
            return Some(directory.to_path_buf());
        }
        current = directory.parent();
    }
    None
}

/// The repository-relative, `/`-joined form of `absolute`, or `None` when it is not a resource of
/// this repository: outside the worktree, the worktree root itself, or inside `.git/`.
fn repo_relative(repo_root: &Path, absolute: &Path) -> Option<String> {
    let segments = gitcmd::relative_segments(repo_root, absolute)?;
    if segments.is_empty() || segments[0] == ".git" {
        return None;
    }
    Some(segments.join("/"))
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_relative_names_resources_and_nothing_else() {
        let root = Path::new("/work");
        assert_eq!(
            repo_relative(root, Path::new("/work/src/a.txt")),
            Some("src/a.txt".to_string())
        );
        for outside in [
            "/work",
            "/work/.git",
            "/work/.git/index",
            "/tmp/escape",
            "/",
        ] {
            assert_eq!(
                repo_relative(root, Path::new(outside)),
                None,
                "{outside} is not a resource of the repository"
            );
        }
    }

    #[test]
    fn the_repository_root_is_found_from_a_subdirectory() {
        let directory = tempfile::tempdir().expect("scratch directory");
        let root = directory.path();
        std::fs::create_dir_all(root.join("src/deep")).expect("dirs");
        std::fs::create_dir_all(root.join(".git")).expect("git dir");
        assert_eq!(
            repo_root(&root.join("src/deep"), root).as_deref(),
            Some(root)
        );
        assert_eq!(
            repo_root(root, root).as_deref(),
            Some(root),
            "the root itself is its own repository root"
        );
    }

    /// The boundary is the job's snapshot root. Without it, a git command in a snapshot whose seed
    /// has no repository would climb into marsh's state directory and open one outside every
    /// snapshot.
    #[test]
    fn the_search_stops_at_the_snapshot_root() {
        let directory = tempfile::tempdir().expect("scratch directory");
        let root = directory.path();
        std::fs::create_dir_all(root.join("run/foo1")).expect("dirs");
        std::fs::create_dir_all(root.join(".git")).expect("an outer repository");
        assert_eq!(repo_root(&root.join("run/foo1"), &root.join("run")), None);
    }
}
