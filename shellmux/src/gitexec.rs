//! Git operations, in this process, through libgit2.
//!
//! Every git capability the mux understands is executed here: no `git` binary is ever spawned, so a
//! git operation is a *builtin* invocation the shell can report ([`crate::hooks`]) rather than a
//! subprocess a tracer has to reverse-engineer from argv.
//!
//! The contract is behavioural parity with the git 2.55 command-line for the pathspec-limited forms
//! the capability model names — the same effect on worktree, index and refs, the same exit code, and
//! a message of the same shape. Parity is not asserted from documentation: each refusal below was
//! probed against the real CLI across the states a pooled path can be in (clean, worktree-modified,
//! staged, staged-and-modified, worktree-deleted, staged-new, untracked, never-existed), and where
//! the probe and the model disagreed, the probe won. The mux depends on this: its serializability
//! argument assumes a command git refuses is a command the policy would deny.
//!
//! Everything here is synchronous and runs on the builtin's own thread, between that builtin's
//! `begin` and `end` records. That is what makes the translator's span windows sound: no other task
//! interleaves on the thread while a git operation is in flight.

use std::io::Write;
use std::path::{Path, PathBuf};

use git2::{FileMode, IndexEntry, IndexTime, Oid, Repository, Signature, Tree};
use rust_validator::Action;

use crate::gitcmd::GitInvocation;

/// Exit code git uses for `fatal:` conditions.
const FATAL: i32 = 128;
/// Exit code git uses for `error:` conditions and for "nothing happened".
const REFUSED: i32 = 1;
/// Exit code reserved for a state the parse contract says is unreachable.
const INTERNAL: i32 = 125;

/// The identity and timestamp one side of a commit is made with.
pub(crate) struct GitEnvIdentity {
    /// `GIT_{AUTHOR,COMMITTER}_NAME`.
    pub name: String,
    /// `GIT_{AUTHOR,COMMITTER}_EMAIL`.
    pub email: String,
    /// `GIT_{AUTHOR,COMMITTER}_DATE`, in git's raw `<epoch> <±HHMM>` form.
    pub time: git2::Time,
}

/// Reads one identity out of the environment.
///
/// `who` is `"AUTHOR"` or `"COMMITTER"`. All three variables are required: a commit whose timestamp
/// came from the wall clock would not be reproducible, and reproducible commits are what let a
/// concurrent run be compared against its serial ground truth.
pub(crate) fn identity_from_env(
    get: impl Fn(&str) -> Option<String>,
    who: &str,
) -> Result<GitEnvIdentity, String> {
    let read = |suffix: &str| {
        let name = format!("GIT_{who}_{suffix}");
        get(&name).ok_or_else(|| format!("{name} is not set"))
    };
    let name = read("NAME")?;
    let email = read("EMAIL")?;
    let date = read("DATE")?;
    let (epoch, offset) = date
        .split_once(' ')
        .ok_or_else(|| format!("GIT_{who}_DATE must be `<epoch> <±HHMM>`, got {date:?}"))?;
    let epoch = epoch
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("GIT_{who}_DATE epoch {epoch:?} is not a number"))?;
    let offset = offset.trim();
    let (sign, digits) = if let Some(rest) = offset.strip_prefix('-') {
        (-1, rest)
    } else if let Some(rest) = offset.strip_prefix('+') {
        (1, rest)
    } else {
        (1, offset)
    };
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "GIT_{who}_DATE offset {offset:?} must be four digits with an optional sign"
        ));
    }
    let (hours, minutes) = digits
        .split_at_checked(2)
        .ok_or_else(|| format!("GIT_{who}_DATE offset {offset:?} is not numeric"))?;
    let hours = hours
        .parse::<i32>()
        .map_err(|_| format!("GIT_{who}_DATE offset {offset:?} is not numeric"))?;
    let minutes = minutes
        .parse::<i32>()
        .map_err(|_| format!("GIT_{who}_DATE offset {offset:?} is not numeric"))?;
    Ok(GitEnvIdentity {
        name,
        email,
        time: git2::Time::new(epoch, sign * (hours * 60 + minutes)),
    })
}

/// Runs [`isolate_from_host_config`] exactly once per process.
static ISOLATE_CONFIG: std::sync::Once = std::sync::Once::new();

/// Cuts libgit2 off from every configuration file outside the repository.
///
/// The mux's environment asks the git *CLI* for this with `GIT_CONFIG_NOSYSTEM` and
/// `GIT_CONFIG_GLOBAL=/dev/null`; libgit2 ignores both, and would happily read
/// `~/.gitconfig`. That is not a cosmetic difference: a host `core.autocrlf` rewrites line endings
/// while hashing, so the same worktree file would land in the object database as a different blob
/// than the CLI produces. A command's effect must depend on the seed and the command alone.
///
/// Emptying the search path for the non-repository levels is libgit2's supported way to disable
/// them. It is process-global state, so it is set once, before the first repository is opened.
fn isolate_from_host_config() {
    ISOLATE_CONFIG.call_once(|| {
        for level in [
            git2::ConfigLevel::ProgramData,
            git2::ConfigLevel::System,
            git2::ConfigLevel::XDG,
            git2::ConfigLevel::Global,
        ] {
            // SAFETY: `git_libgit2_opts` mutates library-global state and is not thread-safe;
            // `Once` serializes it, and it runs before any repository exists in this process.
            unsafe {
                let _ = git2::opts::set_search_path(level, "");
            }
        }
    });
}

/// Executes one parsed git invocation in `workdir`, returning the exit code git would return.
///
/// `inv.pathspecs` must already be repo-relative, `/`-joined paths inside `workdir` — the builtin
/// resolves them against the shell's working directory, because only it knows that directory.
pub(crate) fn run(
    inv: &GitInvocation,
    workdir: &Path,
    author: &GitEnvIdentity,
    committer: &GitEnvIdentity,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    isolate_from_host_config();
    let repo = match Repository::open(workdir) {
        Ok(repo) => repo,
        Err(error) => {
            let _ = writeln!(stderr, "fatal: not a git repository: {}", error.message());
            return FATAL;
        }
    };
    let signatures = if let (Ok(author), Ok(committer)) = (
        Signature::new(&author.name, &author.email, &author.time),
        Signature::new(&committer.name, &committer.email, &committer.time),
    ) {
        (author, committer)
    } else {
        let _ = writeln!(stderr, "fatal: invalid author or committer identity");
        return FATAL;
    };

    let outcome = match &inv.action {
        Action::Stage => stage(&repo, workdir, &inv.pathspecs, stderr),
        Action::Delete => delete(&repo, workdir, &inv.pathspecs, stdout, stderr),
        Action::Commit { message } => commit(
            &repo,
            workdir,
            &inv.pathspecs,
            message.as_deref(),
            &signatures.0,
            &signatures.1,
            stdout,
            stderr,
        ),
        Action::Unstage => unstage(&repo, &inv.pathspecs, stderr),
        Action::Checkout => checkout(&repo, workdir, &inv.pathspecs, stderr),
        Action::Stash => stash(
            &repo,
            workdir,
            &inv.pathspecs,
            &signatures.1,
            stdout,
            stderr,
        ),
        Action::Clean => clean(&repo, workdir, &inv.pathspecs, stdout),
        Action::Diff => diff(&repo, &inv.pathspecs, stdout),
        Action::History => history(&repo, &inv.pathspecs, stdout),
        // Unreachable by the parse contract: `gitcmd` never yields these for a git command line.
        Action::Read | Action::Edit => {
            let _ = writeln!(stderr, "internal error: non-git action");
            return INTERNAL;
        }
    };

    match outcome {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(stderr, "fatal: {}", error.message());
            FATAL
        }
    }
}

/// A path's content and mode in one of the three places git tracks it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Blob {
    /// Object id of the content.
    id: Oid,
    /// Git file mode.
    mode: FileMode,
}

/// `git add`: index := worktree, for each pathspec.
fn stage(
    repo: &Repository,
    workdir: &Path,
    pathspecs: &[String],
    stderr: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let mut index = repo.index()?;
    for spec in pathspecs {
        let relative = Path::new(spec);
        if workdir.join(relative).symlink_metadata().is_ok() {
            index.add_path(relative)?;
        } else if index.get_path(relative, 0).is_some() {
            index.remove_path(relative)?;
        } else {
            // Neither in the worktree nor in the index: nothing this pathspec could name.
            let _ = writeln!(stderr, "fatal: pathspec '{spec}' did not match any files");
            return Ok(FATAL);
        }
    }
    index.write()?;
    Ok(0)
}

/// `git rm`: worktree and index entry both go away, unless that would lose work.
///
/// The three refusals are git's own (`builtin/rm.c`, `check_local_mod`), probed: staged content
/// differing from *both* HEAD and the worktree, content merely staged, and content merely modified.
/// A path already absent from the worktree is never refused — git skips the check when `lstat`
/// fails.
fn delete(
    repo: &Repository,
    workdir: &Path,
    pathspecs: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let mut index = repo.index()?;
    let head = head_tree(repo)?;
    for spec in pathspecs {
        let relative = Path::new(spec);
        let Some(staged) = index_blob(&index, relative) else {
            let _ = writeln!(stderr, "fatal: pathspec '{spec}' did not match any files");
            return Ok(FATAL);
        };
        let committed = head.as_ref().and_then(|tree| tree_blob(tree, relative));
        let working = worktree_blob(repo, workdir, relative)?;
        let staged_changes = committed != Some(staged);
        if let Some(working) = working {
            let local_changes = working != staged;
            let refusal = match (staged_changes, local_changes) {
                (true, true) => Some((
                    "the following file has staged content different from both the\nfile and the \
                     HEAD:",
                    "(use -f to force removal)",
                )),
                (true, false) => Some((
                    "the following file has changes staged in the index:",
                    "(use --cached to keep the file, or -f to force removal)",
                )),
                (false, true) => Some((
                    "the following file has local modifications:",
                    "(use --cached to keep the file, or -f to force removal)",
                )),
                (false, false) => None,
            };
            if let Some((reason, hint)) = refusal {
                let _ = writeln!(stderr, "error: {reason}\n    {spec}\n{hint}");
                return Ok(REFUSED);
            }
        }
    }

    for spec in pathspecs {
        let relative = Path::new(spec);
        let absolute = workdir.join(relative);
        if absolute.symlink_metadata().is_ok() {
            std::fs::remove_file(&absolute).map_err(|error| io_error(&error))?;
        }
        index.remove_path(relative)?;
        let _ = writeln!(stdout, "rm '{spec}'");
    }
    index.write()?;
    Ok(0)
}

/// `git commit -- <pathspec>`: commits the *worktree* state of the named paths, nothing else.
#[expect(
    clippy::too_many_arguments,
    reason = "one git command line's inputs; grouping them would only rename them"
)]
fn commit(
    repo: &Repository,
    workdir: &Path,
    pathspecs: &[String],
    message: Option<&str>,
    author: &Signature<'_>,
    committer: &Signature<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let Some(message) = message else {
        // No editor is reachable from a traced command, and a commit whose message came from
        // somewhere other than the command line would not be the capability that was granted.
        let _ = writeln!(stderr, "fatal: no commit message");
        return Ok(FATAL);
    };
    // `git commit -m` stores the message under `--cleanup=whitespace`: trailing whitespace gone,
    // exactly one trailing newline. Without this the commit *bytes* differ from the CLI's, and a
    // merged history would stop being reproducible across engines.
    let message = git2::message_prettify(message, None)?;
    let Some(parent) = head_commit(repo)? else {
        let _ = writeln!(stderr, "fatal: could not resolve 'HEAD'");
        return Ok(FATAL);
    };
    let base = parent.tree()?;
    let mut index = repo.index()?;

    let mut updates = git2::build::TreeUpdateBuilder::new();
    for spec in pathspecs {
        let relative = Path::new(spec);
        let known = index.get_path(relative, 0).is_some() || tree_blob(&base, relative).is_some();
        if !known {
            let _ = writeln!(
                stderr,
                "error: pathspec '{spec}' did not match any file(s) known to git"
            );
            return Ok(REFUSED);
        }
        match worktree_blob(repo, workdir, relative)? {
            Some(blob) => {
                updates.upsert(spec.as_str(), blob.id, blob.mode);
            }
            None => {
                updates.remove(spec.as_str());
            }
        }
    }
    let tree_id = updates.create_updated(repo, &base)?;
    if tree_id == base.id() {
        let _ = writeln!(stdout, "no changes added to commit");
        return Ok(REFUSED);
    }

    let tree = repo.find_tree(tree_id)?;
    let oid = repo.commit(Some("HEAD"), author, committer, &message, &tree, &[&parent])?;

    // A partial commit leaves the index agreeing with what was committed, which for these paths is
    // the worktree state.
    for spec in pathspecs {
        let relative = Path::new(spec);
        if workdir.join(relative).symlink_metadata().is_ok() {
            index.add_path(relative)?;
        } else {
            index.remove_path(relative)?;
        }
    }
    index.write()?;

    let branch = branch_name(repo);
    let subject = message.lines().next().unwrap_or_default();
    let _ = writeln!(stdout, "[{branch} {}] {subject}", short(oid));
    Ok(0)
}

/// `git restore --staged`: index := HEAD, for each pathspec.
fn unstage(
    repo: &Repository,
    pathspecs: &[String],
    stderr: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let mut index = repo.index()?;
    let head = head_tree(repo)?;
    for spec in pathspecs {
        let relative = Path::new(spec);
        match head.as_ref().and_then(|tree| tree_blob(tree, relative)) {
            Some(blob) => index.add(&index_entry(spec, blob))?,
            None => {
                if index.get_path(relative, 0).is_some() {
                    index.remove_path(relative)?;
                } else {
                    let _ = writeln!(
                        stderr,
                        "error: pathspec '{spec}' did not match any file(s) known to git"
                    );
                    return Ok(REFUSED);
                }
            }
        }
    }
    index.write()?;
    Ok(0)
}

/// `git checkout HEAD -- <pathspec>`: worktree and index both := HEAD.
///
/// The named paths are written directly rather than through a libgit2 checkout: the operation is
/// pathspec-limited by definition, and a checkout strategy could touch paths the capability does not
/// name.
fn checkout(
    repo: &Repository,
    workdir: &Path,
    pathspecs: &[String],
    stderr: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let mut index = repo.index()?;
    let head = head_tree(repo)?;
    let mut restorable = Vec::with_capacity(pathspecs.len());
    for spec in pathspecs {
        let relative = Path::new(spec);
        let Some(blob) = head.as_ref().and_then(|tree| tree_blob(tree, relative)) else {
            let _ = writeln!(
                stderr,
                "error: pathspec '{spec}' did not match any file(s) known to git"
            );
            return Ok(REFUSED);
        };
        restorable.push((spec, blob));
    }
    for (spec, blob) in restorable {
        write_blob(repo, workdir, Path::new(spec), blob)?;
        index.add(&index_entry(spec, blob))?;
    }
    index.write()?;
    Ok(0)
}

/// `git stash push -- <pathspec>`: the named paths' worktree and index state moves to `refs/stash`,
/// and the paths themselves go back to HEAD.
fn stash(
    repo: &Repository,
    workdir: &Path,
    pathspecs: &[String],
    committer: &Signature<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let Some(parent) = head_commit(repo)? else {
        let _ = writeln!(stderr, "fatal: could not resolve 'HEAD'");
        return Ok(FATAL);
    };
    let base = parent.tree()?;
    let mut index = repo.index()?;

    let mut states = Vec::with_capacity(pathspecs.len());
    let mut dirty = false;
    for spec in pathspecs {
        let relative = Path::new(spec);
        let Some(staged) = index_blob(&index, relative) else {
            let _ = writeln!(
                stderr,
                "error: pathspec '{spec}' did not match any file(s) known to git\n\
                 Did you forget to 'git add'?"
            );
            return Ok(REFUSED);
        };
        let committed = tree_blob(&base, relative);
        let working = worktree_blob(repo, workdir, relative)?;
        dirty = dirty || committed != Some(staged) || working != Some(staged);
        states.push((spec, staged, working));
    }
    if !dirty {
        let _ = writeln!(stdout, "No local changes to save");
        return Ok(0);
    }

    let branch = branch_name(repo);
    let subject = parent
        .summary()
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_string();
    let label = format!("on {branch}: {} {subject}", short(parent.id()));

    let mut staged_updates = git2::build::TreeUpdateBuilder::new();
    let mut working_updates = git2::build::TreeUpdateBuilder::new();
    for (spec, staged, working) in &states {
        staged_updates.upsert(spec.as_str(), staged.id, staged.mode);
        match working {
            Some(blob) => {
                working_updates.upsert(spec.as_str(), blob.id, blob.mode);
            }
            None => {
                working_updates.remove(spec.as_str());
            }
        }
    }

    let staged_tree = repo.find_tree(staged_updates.create_updated(repo, &base)?)?;
    let staged_commit = repo.commit(
        None,
        committer,
        committer,
        &git2::message_prettify(format!("index {label}"), None)?,
        &staged_tree,
        &[&parent],
    )?;
    let working_tree = repo.find_tree(working_updates.create_updated(repo, &base)?)?;
    let message = git2::message_prettify(format!("WIP {label}"), None)?;
    let working_commit = repo.commit(
        None,
        committer,
        committer,
        &message,
        &working_tree,
        &[&parent, &repo.find_commit(staged_commit)?],
    )?;

    repo.reference("refs/stash", working_commit, true, &message)?;
    // `git stash list` reads the reflog, not the ref; libgit2 only logs reference updates it
    // considers loggable, so the entry is appended when it is missing.
    let mut reflog = repo.reflog("refs/stash")?;
    if reflog.is_empty() {
        reflog.append(working_commit, committer, Some(&message))?;
        reflog.write()?;
    }

    for (spec, _, _) in &states {
        let relative = Path::new(spec);
        if let Some(blob) = tree_blob(&base, relative) {
            write_blob(repo, workdir, relative, blob)?;
            index.add(&index_entry(spec, blob))?;
        } else {
            let absolute = workdir.join(relative);
            if absolute.symlink_metadata().is_ok() {
                std::fs::remove_file(&absolute).map_err(|error| io_error(&error))?;
            }
            index.remove_path(relative)?;
        }
    }
    index.write()?;

    let _ = writeln!(stdout, "Saved working directory and index state {message}");
    Ok(0)
}

/// `git clean -f -- <pathspec>`: untracked content at the named paths is deleted.
fn clean(
    repo: &Repository,
    workdir: &Path,
    pathspecs: &[String],
    stdout: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let index = repo.index()?;
    for spec in pathspecs {
        let relative = Path::new(spec);
        let absolute = workdir.join(relative);
        if index.get_path(relative, 0).is_none() && absolute.symlink_metadata().is_ok() {
            std::fs::remove_file(&absolute).map_err(|error| io_error(&error))?;
            let _ = writeln!(stdout, "Removing {spec}");
        }
    }
    Ok(0)
}

/// `git diff -- <pathspec>`: the index-to-worktree patch, limited to the named paths.
fn diff(
    repo: &Repository,
    pathspecs: &[String],
    stdout: &mut dyn Write,
) -> Result<i32, git2::Error> {
    let index = repo.index()?;
    let mut options = git2::DiffOptions::new();
    for spec in pathspecs {
        options.pathspec(spec.as_str());
    }
    let diff = repo.diff_index_to_workdir(Some(&index), Some(&mut options))?;
    diff.print(git2::DiffFormat::Patch, |_, _, line| {
        match line.origin() {
            '+' | '-' | ' ' => {
                let _ = write!(stdout, "{}", line.origin());
            }
            _ => {}
        }
        let _ = stdout.write_all(line.content());
        true
    })?;
    Ok(0)
}

/// `git log -- <pathspec>`: the commits in which one of the named paths changed.
fn history(
    repo: &Repository,
    pathspecs: &[String],
    stdout: &mut dyn Write,
) -> Result<i32, git2::Error> {
    if head_commit(repo)?.is_none() {
        return Ok(0);
    }
    let mut walk = repo.revwalk()?;
    walk.push_head()?;
    for oid in walk {
        let commit = repo.find_commit(oid?)?;
        let tree = commit.tree()?;
        let parents: Vec<Tree<'_>> = commit
            .parents()
            .map(|parent| parent.tree())
            .collect::<Result<_, _>>()?;
        let touched = pathspecs.iter().any(|spec| {
            let relative = Path::new(spec);
            let here = tree_blob(&tree, relative);
            parents.is_empty() && here.is_some()
                || !parents.is_empty()
                    && parents
                        .iter()
                        .all(|parent| tree_blob(parent, relative) != here)
        });
        if !touched {
            continue;
        }
        let author = commit.author();
        let _ = writeln!(
            stdout,
            "commit {}\nAuthor: {} <{}>\n",
            commit.id(),
            author.name().unwrap_or_default(),
            author.email().unwrap_or_default()
        );
        for line in commit.message().unwrap_or_default().lines() {
            let _ = writeln!(stdout, "    {line}");
        }
        let _ = writeln!(stdout);
    }
    Ok(0)
}

/// The current branch's short name, or `HEAD` when it cannot be named.
fn branch_name(repo: &Repository) -> String {
    repo.head()
        .ok()
        .and_then(|reference| reference.shorthand().map(ToString::to_string).ok())
        .unwrap_or_else(|| "HEAD".to_string())
}

/// The commit `HEAD` names, or `None` when the branch is unborn.
fn head_commit(repo: &Repository) -> Result<Option<git2::Commit<'_>>, git2::Error> {
    match repo.head() {
        Ok(reference) => reference.peel_to_commit().map(Some),
        Err(error)
            if matches!(
                error.code(),
                git2::ErrorCode::UnbornBranch | git2::ErrorCode::NotFound
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The tree `HEAD` names, or `None` when the branch is unborn.
fn head_tree(repo: &Repository) -> Result<Option<Tree<'_>>, git2::Error> {
    match head_commit(repo)? {
        Some(commit) => commit.tree().map(Some),
        None => Ok(None),
    }
}

/// A path's content in a tree.
fn tree_blob(tree: &Tree<'_>, relative: &Path) -> Option<Blob> {
    let entry = tree.get_path(relative).ok()?;
    Some(Blob {
        id: entry.id(),
        mode: file_mode(entry.filemode()),
    })
}

/// A path's content in the index, at stage 0.
fn index_blob(index: &git2::Index, relative: &Path) -> Option<Blob> {
    let entry = index.get_path(relative, 0)?;
    #[expect(
        clippy::cast_possible_wrap,
        reason = "index modes are the same small constants tree filemodes are"
    )]
    Some(Blob {
        id: entry.id,
        mode: file_mode(entry.mode as i32),
    })
}

/// A path's content in the worktree, hashed into the object database, or `None` when the path is
/// absent or is not a file.
fn worktree_blob(
    repo: &Repository,
    workdir: &Path,
    relative: &Path,
) -> Result<Option<Blob>, git2::Error> {
    let absolute = workdir.join(relative);
    let metadata = match absolute.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(&error)),
    };
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(&absolute).map_err(|error| io_error(&error))?;
        let id = repo.blob(path_bytes(&target))?;
        return Ok(Some(Blob {
            id,
            mode: FileMode::Link,
        }));
    }
    if !metadata.is_file() {
        return Ok(None);
    }
    let id = repo.blob_path(&absolute)?;
    Ok(Some(Blob {
        id,
        mode: if is_executable(&metadata) {
            FileMode::BlobExecutable
        } else {
            FileMode::Blob
        },
    }))
}

/// Writes a blob's content to a worktree path, creating parents and honouring its mode.
fn write_blob(
    repo: &Repository,
    workdir: &Path,
    relative: &Path,
    blob: Blob,
) -> Result<(), git2::Error> {
    let absolute = workdir.join(relative);
    if let Some(parent) = absolute.parent() {
        std::fs::create_dir_all(parent).map_err(|error| io_error(&error))?;
    }
    let content = repo.find_blob(blob.id)?;
    if blob.mode == FileMode::Link {
        if absolute.symlink_metadata().is_ok() {
            std::fs::remove_file(&absolute).map_err(|error| io_error(&error))?;
        }
        let target = PathBuf::from(String::from_utf8_lossy(content.content()).into_owned());
        std::os::unix::fs::symlink(target, &absolute).map_err(|error| io_error(&error))?;
        return Ok(());
    }
    std::fs::write(&absolute, content.content()).map_err(|error| io_error(&error))?;
    let permissions = if blob.mode == FileMode::BlobExecutable {
        0o755
    } else {
        0o644
    };
    std::fs::set_permissions(
        &absolute,
        std::os::unix::fs::PermissionsExt::from_mode(permissions),
    )
    .map_err(|error| io_error(&error))?;
    Ok(())
}

/// An index entry naming `blob` at `path`, with the stat cache zeroed.
///
/// Zeroed stat data is what git writes when it puts a committed object into the index without
/// touching the worktree (`git restore --staged`): the entry is "stat dirty", so the next status
/// re-hashes the file instead of trusting a timestamp this process never observed.
fn index_entry(path: &str, blob: Blob) -> IndexEntry {
    #[expect(
        clippy::cast_sign_loss,
        reason = "git file modes are small positive constants"
    )]
    IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: i32::from(blob.mode) as u32,
        uid: 0,
        gid: 0,
        file_size: 0,
        id: blob.id,
        flags: 0,
        flags_extended: 0,
        path: path.as_bytes().to_vec(),
    }
}

/// Classifies a raw git file mode.
const fn file_mode(raw: i32) -> FileMode {
    match raw {
        0o120_000 => FileMode::Link,
        0o100_755 => FileMode::BlobExecutable,
        0o040_000 => FileMode::Tree,
        0o160_000 => FileMode::Commit,
        _ => FileMode::Blob,
    }
}

/// Whether a worktree entry carries any execute bit, which is what git records as mode 100755.
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    std::os::unix::fs::MetadataExt::mode(metadata) & 0o111 != 0
}

/// A path's bytes, for storing a symlink target as blob content.
fn path_bytes(path: &Path) -> &[u8] {
    std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())
}

/// The abbreviated object id git prints.
fn short(oid: Oid) -> String {
    oid.to_string().chars().take(7).collect()
}

/// Wraps an I/O failure as a libgit2 error so one error type reaches the exit-code mapping.
fn io_error(error: &std::io::Error) -> git2::Error {
    git2::Error::new(
        git2::ErrorCode::GenericError,
        git2::ErrorClass::Os,
        error.to_string(),
    )
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Hashes bytes as a blob without writing them, for tests that compare content.
    fn hash_blob(bytes: &[u8]) -> Oid {
        Oid::hash_object(git2::ObjectType::Blob, bytes).expect("hash blob")
    }

    /// The pinned identity every test commits with: the mux's own `git_env`, so a commit produced
    /// here is byte-identical to one the mux would merge.
    fn identity() -> GitEnvIdentity {
        identity_from_env(
            |name| {
                Some(
                    match name {
                        "GIT_AUTHOR_NAME" | "GIT_COMMITTER_NAME" => "agent0",
                        "GIT_AUTHOR_EMAIL" | "GIT_COMMITTER_EMAIL" => "agent0@marsh.local",
                        _ => "1112911993 +0000",
                    }
                    .to_string(),
                )
            },
            "AUTHOR",
        )
        .expect("identity")
    }

    /// A scratch repository with one commit containing `src/p.txt` and `src/.keep`.
    fn scratch(label: &str) -> PathBuf {
        // The same scratch location the snapshot tests use: plain directories, no subvolume needed.
        let root = crate::snapshot::tests::test_root().join(format!("gitexec-{label}"));
        // The helper builds its seed commit with libgit2 directly, so it needs the same isolation
        // `run` installs: a host `core.autocrlf` would otherwise hash the seed files differently.
        isolate_from_host_config();
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("scratch dirs");
        std::fs::write(root.join("src/p.txt"), b"seed\n").expect("seed file");
        std::fs::write(root.join("src/.keep"), b"").expect("keep file");

        let repo = Repository::init_opts(
            &root,
            git2::RepositoryInitOptions::new().initial_head("main"),
        )
        .expect("init");
        {
            let mut index = repo.index().expect("index");
            index.add_path(Path::new("src/p.txt")).expect("add p");
            index.add_path(Path::new("src/.keep")).expect("add keep");
            index.write().expect("write index");
            let tree = repo
                .find_tree(index.write_tree().expect("write tree"))
                .expect("tree");
            let id = identity();
            let signature = Signature::new(&id.name, &id.email, &id.time).expect("signature");
            repo.commit(Some("HEAD"), &signature, &signature, "seed\n", &tree, &[])
                .expect("seed commit");
        }
        root
    }

    #[test]
    fn host_git_configuration_is_invisible() {
        isolate_from_host_config();
        for level in [
            git2::ConfigLevel::System,
            git2::ConfigLevel::XDG,
            git2::ConfigLevel::Global,
        ] {
            // SAFETY: reading library-global state after `Once` has finished writing it.
            let path = unsafe { git2::opts::get_search_path(level).expect("search path") };
            assert_eq!(
                path.to_bytes(),
                b"",
                "{level:?} configuration must be unreachable: a host `core.autocrlf` would change \
                 how worktree files hash"
            );
        }
        // The mechanism is only interesting if it has the intended effect: a repository's effective
        // configuration must contain nothing the host set.
        let root = scratch("config");
        let repo = Repository::open(&root).expect("open");
        let config = repo.config().expect("config");
        for key in [
            "user.name",
            "user.email",
            "core.autocrlf",
            "init.defaultBranch",
        ] {
            assert!(
                config.get_string(key).is_err(),
                "{key} leaked in from the host configuration"
            );
        }
    }

    /// Runs one git command line in `root`, returning `(exit code, stdout, stderr)`.
    fn exec(root: &Path, argv: &[&str]) -> (i32, String, String) {
        let argv: Vec<String> = argv.iter().map(|arg| (*arg).to_string()).collect();
        let invocation = crate::gitcmd::parse(&argv).expect("parse");
        let author = identity();
        let committer = identity();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&invocation, root, &author, &committer, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    /// The state of `src/p.txt` in HEAD, the index and the worktree.
    fn state(root: &Path) -> (Option<Oid>, Option<Oid>, Option<Vec<u8>>) {
        let repo = Repository::open(root).expect("open");
        let relative = Path::new("src/p.txt");
        let head = head_tree(&repo)
            .expect("head")
            .and_then(|tree| tree_blob(&tree, relative))
            .map(|blob| blob.id);
        let index = index_blob(&repo.index().expect("index"), relative).map(|blob| blob.id);
        let worktree = std::fs::read(root.join(relative)).ok();
        (head, index, worktree)
    }

    #[test]
    fn a_raw_epoch_date_becomes_a_git_time() {
        let identity = identity();
        assert_eq!(identity.time.seconds(), 1_112_911_993);
        assert_eq!(identity.time.offset_minutes(), 0);
        let shifted = identity_from_env(
            |name| {
                Some(match name {
                    "GIT_AUTHOR_DATE" => "1112911993 -0530".to_string(),
                    _ => "x".to_string(),
                })
            },
            "AUTHOR",
        )
        .expect("identity");
        assert_eq!(shifted.time.offset_minutes(), -330);
        for bad in ["", "1112911993", "not-a-date +0000", "1112911993 +05"] {
            let error = identity_from_env(
                |name| {
                    Some(if name == "GIT_AUTHOR_DATE" {
                        bad.to_string()
                    } else {
                        "x".to_string()
                    })
                },
                "AUTHOR",
            )
            .err()
            .unwrap_or_else(|| panic!("{bad:?} accepted"));
            assert!(error.contains("GIT_AUTHOR_DATE"), "{bad:?}: {error}");
        }
        assert!(
            identity_from_env(|_| None, "COMMITTER")
                .err()
                .expect("rejected")
                .contains("GIT_COMMITTER_NAME"),
            "a missing identity is refused, never guessed"
        );
    }

    #[test]
    fn staging_moves_the_worktree_into_the_index() {
        let root = scratch("stage");
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify");
        let (code, _, err) = exec(&root, &["git", "add", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        let (head, index, worktree) = state(&root);
        assert_eq!(index, Some(hash_blob(b"seed\nmod\n")));
        assert_ne!(index, head, "the index moved ahead of HEAD");
        assert_eq!(worktree.as_deref(), Some(&b"seed\nmod\n"[..]));

        // A deleted worktree file stages its removal, exactly like the CLI.
        std::fs::remove_file(root.join("src/p.txt")).expect("remove");
        let (code, _, _) = exec(&root, &["git", "add", "--", "src/p.txt"]);
        assert_eq!(code, 0);
        assert_eq!(state(&root).1, None, "the index entry is gone");

        // Absent from both worktree and index: nothing the pathspec could name.
        let (code, _, err) = exec(&root, &["git", "add", "--", "src/p.txt"]);
        assert_eq!(code, FATAL);
        assert!(err.contains("did not match any files"), "{err:?}");
    }

    #[test]
    fn git_rm_refuses_exactly_what_the_cli_refuses() {
        // (state setup, expected exit, expected message fragment)
        let cases: [(&str, i32, &str); 5] = [
            ("clean", 0, ""),
            ("wt-modified", REFUSED, "local modifications"),
            ("staged", REFUSED, "changes staged in the index"),
            (
                "staged-and-modified",
                REFUSED,
                "staged content different from both",
            ),
            ("wt-deleted", 0, ""),
        ];
        for (setup, expected_code, fragment) in cases {
            let root = scratch(setup);
            let path = root.join("src/p.txt");
            match setup {
                "clean" => {}
                "wt-modified" => std::fs::write(&path, b"seed\nmod\n").expect("modify"),
                "staged" => {
                    std::fs::write(&path, b"seed\nmod\n").expect("modify");
                    assert_eq!(exec(&root, &["git", "add", "--", "src/p.txt"]).0, 0);
                }
                "staged-and-modified" => {
                    std::fs::write(&path, b"seed\nmod\n").expect("modify");
                    assert_eq!(exec(&root, &["git", "add", "--", "src/p.txt"]).0, 0);
                    std::fs::write(&path, b"seed\nmod\nmore\n").expect("modify again");
                }
                "wt-deleted" => std::fs::remove_file(&path).expect("remove"),
                other => panic!("unknown setup {other}"),
            }
            let (code, _, err) = exec(&root, &["git", "rm", "--", "src/p.txt"]);
            assert_eq!(code, expected_code, "{setup}: {err}");
            if fragment.is_empty() {
                assert_eq!(state(&root).1, None, "{setup}: the index entry is gone");
                assert!(!path.exists(), "{setup}: the worktree file is gone");
            } else {
                assert!(err.contains(fragment), "{setup} reported {err:?}");
                assert!(
                    state(&root).1.is_some(),
                    "{setup}: a refused removal changes nothing"
                );
            }
        }

        // Untracked, and never-tracked, are both `fatal:` — the pathspec matches no index entry.
        let root = scratch("rm-untracked");
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        let (code, _, err) = exec(&root, &["git", "rm", "--", "src/new.txt"]);
        assert_eq!(code, FATAL);
        assert!(err.contains("did not match any files"), "{err:?}");
    }

    #[test]
    fn a_partial_commit_records_the_worktree_and_updates_the_index() {
        let root = scratch("commit");
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify");
        let (code, out, err) = exec(&root, &["git", "commit", "-m", "step 7", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(out.starts_with("[main "), "got {out:?}");
        let (head, index, worktree) = state(&root);
        assert_eq!(
            head,
            Some(hash_blob(b"seed\nmod\n")),
            "HEAD has the worktree content"
        );
        assert_eq!(index, head, "the index agrees with what was committed");
        assert_eq!(worktree.as_deref(), Some(&b"seed\nmod\n"[..]));

        let repo = Repository::open(&root).expect("open");
        let commit = head_commit(&repo).expect("head").expect("a commit");
        assert_eq!(commit.message().ok(), Some("step 7\n"));
        assert_eq!(commit.author().name().ok(), Some("agent0"));
        assert_eq!(commit.time().seconds(), 1_112_911_993);

        // Nothing left to record for this path.
        let (code, out, _) = exec(&root, &["git", "commit", "-m", "again", "--", "src/p.txt"]);
        assert_eq!(code, REFUSED);
        assert!(out.contains("no changes added to commit"), "{out:?}");

        // A path git knows nothing about cannot be committed, even when it exists.
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        let (code, _, err) = exec(&root, &["git", "commit", "-m", "x", "--", "src/new.txt"]);
        assert_eq!(code, REFUSED);
        assert!(
            err.contains("did not match any file(s) known to git"),
            "{err:?}"
        );

        // A commit with no message is refused rather than opening an editor.
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\nmore\n").expect("modify");
        let (code, _, err) = exec(&root, &["git", "commit", "--", "src/p.txt"]);
        assert_eq!(code, FATAL);
        assert!(err.contains("no commit message"), "{err:?}");
    }

    /// The one hard equality against the real thing: commit *bytes*, not just commit effects.
    ///
    /// Both object ids below were recorded from git 2.55 driving the identical repository with the
    /// mux's pinned environment (`git init -b main`, add `src/p.txt` + `src/.keep`, commit "seed",
    /// rewrite `src/p.txt`, `git commit -m 'step 7' -- src/p.txt`). Reproducing them here proves
    /// that a merged history is byte-identical whether it was produced by this code or by git — the
    /// premise the tests' `rev-parse HEAD` comparisons rest on.
    #[test]
    fn commits_are_byte_identical_to_the_real_cli() {
        const SEED: &str = "681dea4d4d7409e76584280a4fc75572688c51ed";
        const STEP7: &str = "f2a5c42d5bbd80c29d86ff2c44ca798d3d1f424c";

        let root = scratch("oid");
        let repo = Repository::open(&root).expect("open");
        assert_eq!(
            head_commit(&repo).expect("head").expect("a commit").id(),
            Oid::from_str(SEED).expect("seed oid"),
            "the scratch repository's root commit is the CLI's root commit"
        );

        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify");
        assert_eq!(
            exec(&root, &["git", "commit", "-m", "step 7", "--", "src/p.txt"]).0,
            0
        );
        assert_eq!(
            head_commit(&repo).expect("head").expect("a commit").id(),
            Oid::from_str(STEP7).expect("step oid")
        );
    }

    #[test]
    fn a_deletion_can_be_committed() {
        let root = scratch("commit-delete");
        std::fs::remove_file(root.join("src/p.txt")).expect("remove");
        let (code, _, err) = exec(&root, &["git", "commit", "-m", "drop", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        let (head, index, worktree) = state(&root);
        assert_eq!((head, index, worktree), (None, None, None));
    }

    #[test]
    fn unstaging_resets_the_index_to_head() {
        let root = scratch("unstage");
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify");
        assert_eq!(exec(&root, &["git", "add", "--", "src/p.txt"]).0, 0);
        let (code, _, err) = exec(&root, &["git", "restore", "--staged", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        let (head, index, worktree) = state(&root);
        assert_eq!(index, head, "the index is back at HEAD");
        assert_eq!(
            worktree.as_deref(),
            Some(&b"seed\nmod\n"[..]),
            "the worktree is untouched"
        );

        // A path staged but never committed leaves the index entirely.
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        assert_eq!(exec(&root, &["git", "add", "--", "src/new.txt"]).0, 0);
        let (code, _, _) = exec(&root, &["git", "restore", "--staged", "--", "src/new.txt"]);
        assert_eq!(code, 0);
        let repo = Repository::open(&root).expect("open");
        assert!(
            index_blob(&repo.index().expect("index"), Path::new("src/new.txt")).is_none(),
            "the entry is gone, and the file is now untracked"
        );

        // A path in neither HEAD nor the index names nothing.
        let (code, _, err) = exec(&root, &["git", "restore", "--staged", "--", "src/new.txt"]);
        assert_eq!(code, REFUSED);
        assert!(
            err.contains("did not match any file(s) known to git"),
            "{err:?}"
        );
    }

    #[test]
    fn checkout_head_restores_worktree_and_index() {
        let root = scratch("checkout");
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify");
        assert_eq!(exec(&root, &["git", "add", "--", "src/p.txt"]).0, 0);
        let (code, _, err) = exec(&root, &["git", "checkout", "HEAD", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        let (head, index, worktree) = state(&root);
        assert_eq!(index, head);
        assert_eq!(worktree.as_deref(), Some(&b"seed\n"[..]));

        // A deleted file comes back.
        std::fs::remove_file(root.join("src/p.txt")).expect("remove");
        assert_eq!(
            exec(&root, &["git", "checkout", "HEAD", "--", "src/p.txt"]).0,
            0
        );
        assert_eq!(state(&root).2.as_deref(), Some(&b"seed\n"[..]));

        // A path HEAD does not have cannot be restored from it.
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        assert_eq!(exec(&root, &["git", "add", "--", "src/new.txt"]).0, 0);
        let (code, _, err) = exec(&root, &["git", "checkout", "HEAD", "--", "src/new.txt"]);
        assert_eq!(code, REFUSED);
        assert!(
            err.contains("did not match any file(s) known to git"),
            "{err:?}"
        );
    }

    #[test]
    fn stash_push_saves_both_states_and_restores_head() {
        let root = scratch("stash");
        std::fs::write(root.join("src/p.txt"), b"seed\nstaged\n").expect("modify");
        assert_eq!(exec(&root, &["git", "add", "--", "src/p.txt"]).0, 0);
        std::fs::write(root.join("src/p.txt"), b"seed\nstaged\nworking\n").expect("modify again");

        let (code, out, err) = exec(&root, &["git", "stash", "push", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(
            out.contains("Saved working directory and index state WIP on main:"),
            "{out:?}"
        );

        let (head, index, worktree) = state(&root);
        assert_eq!(index, head, "the index is back at HEAD");
        assert_eq!(
            worktree.as_deref(),
            Some(&b"seed\n"[..]),
            "so is the worktree"
        );

        let repo = Repository::open(&root).expect("open");
        let wip = repo
            .find_reference("refs/stash")
            .expect("stash ref")
            .peel_to_commit()
            .expect("stash commit");
        assert_eq!(wip.parent_count(), 2, "WIP commit is (HEAD, index state)");
        assert_eq!(
            tree_blob(&wip.tree().expect("wip tree"), Path::new("src/p.txt")).map(|blob| blob.id),
            Some(hash_blob(b"seed\nstaged\nworking\n")),
            "the WIP commit carries the worktree state"
        );
        let staged = wip.parent(1).expect("index commit");
        assert_eq!(
            tree_blob(&staged.tree().expect("index tree"), Path::new("src/p.txt"))
                .map(|blob| blob.id),
            Some(hash_blob(b"seed\nstaged\n")),
            "its second parent carries the index state"
        );
        assert!(
            staged
                .message()
                .unwrap_or_default()
                .starts_with("index on main:"),
            "got {:?}",
            staged.message()
        );
        assert_eq!(
            repo.reflog("refs/stash").expect("reflog").len(),
            1,
            "`git stash list` reads the reflog"
        );

        // Nothing to save, no ref update.
        let before = wip.id();
        let (code, out, _) = exec(&root, &["git", "stash", "push", "--", "src/p.txt"]);
        assert_eq!(code, 0);
        assert!(out.contains("No local changes to save"), "{out:?}");
        assert_eq!(
            repo.find_reference("refs/stash")
                .expect("stash ref")
                .peel_to_commit()
                .expect("commit")
                .id(),
            before,
            "a clean stash leaves the ref alone"
        );

        // An untracked path is not stashable.
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        let (code, _, err) = exec(&root, &["git", "stash", "push", "--", "src/new.txt"]);
        assert_eq!(code, REFUSED);
        assert!(err.contains("Did you forget to 'git add'?"), "{err:?}");
    }

    #[test]
    fn a_stashed_new_file_is_removed_from_worktree_and_index() {
        let root = scratch("stash-new");
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        assert_eq!(exec(&root, &["git", "add", "--", "src/new.txt"]).0, 0);
        let (code, _, err) = exec(&root, &["git", "stash", "push", "--", "src/new.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(
            !root.join("src/new.txt").exists(),
            "the file went into the stash"
        );
        let repo = Repository::open(&root).expect("open");
        assert!(
            index_blob(&repo.index().expect("index"), Path::new("src/new.txt")).is_none(),
            "and left the index"
        );
    }

    #[test]
    fn clean_deletes_untracked_content_only() {
        let root = scratch("clean");
        std::fs::write(root.join("src/new.txt"), b"new\n").expect("new file");
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify tracked");
        let (code, out, _) = exec(
            &root,
            &["git", "clean", "-f", "--", "src/new.txt", "src/p.txt"],
        );
        assert_eq!(code, 0);
        assert_eq!(
            out, "Removing src/new.txt\n",
            "only the untracked path is named"
        );
        assert!(!root.join("src/new.txt").exists());
        assert_eq!(
            state(&root).2.as_deref(),
            Some(&b"seed\nmod\n"[..]),
            "a tracked file's modifications are not clean's business"
        );
    }

    #[test]
    fn diff_and_log_report_without_changing_anything() {
        let root = scratch("read-only");
        std::fs::write(root.join("src/p.txt"), b"seed\nmod\n").expect("modify");
        let (code, out, err) = exec(&root, &["git", "diff", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(
            out.contains("+mod"),
            "the patch names the added line: {out:?}"
        );
        assert!(out.contains("src/p.txt"), "{out:?}");

        assert_eq!(
            exec(&root, &["git", "commit", "-m", "step 1", "--", "src/p.txt"]).0,
            0
        );
        let (code, out, err) = exec(&root, &["git", "log", "--", "src/p.txt"]);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(
            out.contains("Author: agent0 <agent0@marsh.local>"),
            "{out:?}"
        );
        assert_eq!(
            out.matches("commit ").count(),
            2,
            "the seed commit created the path and the second changed it: {out:?}"
        );

        let (code, out, _) = exec(&root, &["git", "log", "--", "src/.keep"]);
        assert_eq!(code, 0);
        assert_eq!(
            out.matches("commit ").count(),
            1,
            "an untouched path names only its creating commit: {out:?}"
        );
    }
}
