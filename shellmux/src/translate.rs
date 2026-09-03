//! Turning a command's two instrumentation streams into capability events.
//!
//! A traced command produces syscalls ([`crate::strace`]) and builtin invocations
//! ([`crate::hooks`]). Both are stamped with `CLOCK_REALTIME` microseconds, so they merge into one
//! ordered sequence of *items*, each either a syscall or a builtin lifecycle edge. Three rules read
//! that sequence:
//!
//! * **A syscall is a capability** when the thread issuing it is Shell-attributed: the command line
//!   means nothing and the syscall is everything (`> p` opened for writing **is** `Edit p`).
//! * **A builtin invocation is a capability** when it is a git variant: `git add -- p` **is**
//!   `Stage p`, derived from the recorded argv through the one shared grammar ([`crate::gitcmd`]).
//!   Every other builtin is transparent — its syscalls already say what it did.
//! * **A git builtin's own syscalls are not capabilities** but are its *read set*: the paths it
//!   consulted (`.git/index`, `HEAD`, refs, and the worktree files it hashed) are what its decision
//!   depended on, and a command must declare that or it could merge a conclusion drawn from a
//!   repository someone else has since changed.
//!
//! Attribution is inherited across `clone`/`fork`. A raw `execve` of a git binary is *not*
//! instrumentable — nothing recorded its invocation — and makes the whole command unsupported.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use rust_validator::{Action, Event, Principal, Resource};

use crate::gitcmd::{self, resolve};
use crate::hooks::BuiltinRecord;
use crate::strace::{Call, TraceLine, parse_quoted, split_args};

/// What one traced command amounts to, in capability terms.
pub(crate) struct Translation {
    /// Capability events the command requested, in merged-stream order, duplicates collapsed.
    pub events: Vec<Event>,
    /// Set when some part of the command cannot be expressed as capabilities. Such a command is
    /// never merged: the mux refuses to guess at a footprint it cannot name.
    pub unsupported: Option<String>,
    /// Exit status of the traced root process, when the trace recorded it.
    pub exit_code: Option<i32>,
    /// Work-snapshot-relative paths a git builtin actually read, sorted and deduplicated,
    /// `.git/` included.
    ///
    /// A git operation decides from repository state no pathspec names — the index, `HEAD`, refs —
    /// and may write nothing at all (`git diff`, a no-op `git restore --staged`). Its observed reads
    /// are how such a command declares what its answer depended on.
    pub git_reads: Vec<String>,
}

/// How a thread's syscalls are interpreted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attr {
    /// Shell or ordinary program: file syscalls are capabilities.
    Shell,
    /// A thread that `execve`d a git binary directly, bypassing the builtins. Its syscalls are
    /// suppressed, and the command is unsupported: nothing recorded what it was asked to do.
    Git,
}

/// Per-thread tracking: where relative paths resolve from, how syscalls are attributed, and whether
/// a git builtin is currently executing on this thread.
struct TidState {
    cwd: PathBuf,
    attr: Attr,
    span: Option<u64>,
}

/// One element of the merged stream.
enum Item<'a> {
    /// A builtin began executing.
    Begin(&'a BuiltinRecord),
    /// A syscall completed.
    Line(&'a TraceLine),
    /// A builtin finished executing.
    End(&'a BuiltinRecord),
}

impl Item<'_> {
    /// Sort key: timestamp first, then edge rank.
    ///
    /// The rank makes span windows inclusive at both ends — a syscall sharing a microsecond with a
    /// `Begin` or an `End` counts as *inside* the span — which is the conservative choice: a
    /// borderline syscall becomes part of git's read set instead of a capability request the
    /// principal never made.
    fn key(&self) -> (u64, u8) {
        match self {
            Self::Begin(record) => (record.ts(), 0),
            Self::Line(line) => (line.ts_us, 1),
            Self::End(record) => (record.ts(), 2),
        }
    }
}

/// Translates a traced command's two instrumentation streams into the capabilities it requested.
///
/// `work_root` must be the canonical path of the work snapshot; paths outside it, and everything
/// under `.git/`, produce no events.
///
/// # Known limitations
///
/// * **Directory listings are not capabilities.** `getdents64` is not traced, so a command whose
///   result depends on a directory's *contents list* (a glob) declares no dependency on it. Conflict
///   detection therefore covers file reads and writes, not enumeration.
/// * **Out-of-root effects are real.** There is no chroot, by requirement: a command that writes
///   `/tmp/x` really writes it. Such a write is observed and ignored, never merged and never
///   authorized. The mux gates what enters the seed; it does not sandbox the command.
/// * **A git builtin's writes are not observed as capabilities.** The pathspec on its command line
///   is its declared write footprint, and the physical diff of the snapshot is what actually merges;
///   its own `.git/index.lock` churn must not become a dependency of the command.
pub(crate) fn translate(
    lines: &[TraceLine],
    builtins: &[BuiltinRecord],
    principal: &Principal,
    work_root: &Path,
) -> Translation {
    let mut states: HashMap<u32, TidState> = HashMap::new();
    let mut events: Vec<Event> = Vec::new();
    let mut git_reads: Vec<String> = Vec::new();
    let mut unsupported: Option<String> = None;
    let mut exit_code = None;
    // The root `execve` is a syscall, never a record, so the root thread is known before merging.
    let root_tid = lines.first().map(|line| line.tid);
    let mut open_spans: HashMap<u64, &BuiltinRecord> = HashMap::new();

    for item in merge(lines, builtins) {
        match item {
            Item::Begin(record) => {
                let BuiltinRecord::Begin {
                    id, tid, builtin, ..
                } = record
                else {
                    continue;
                };
                if open_spans.insert(*id, record).is_some() {
                    unsupported =
                        unsupported.or_else(|| Some(format!("builtin record {id} began twice")));
                }
                if !is_git_builtin(builtin) {
                    continue;
                }
                let state = state_for(&mut states, *tid, work_root);
                if state.span.is_some() {
                    // Builtins on one thread are sequential, and concurrent pipeline elements run
                    // on different threads; an overlap would mean the span window is meaningless.
                    unsupported = unsupported.or_else(|| {
                        Some("overlapping git builtin spans on one thread".to_string())
                    });
                }
                state.span = Some(*id);
            }
            Item::End(record) => {
                let BuiltinRecord::End { id, exit, .. } = record else {
                    continue;
                };
                let Some(begin) = open_spans.remove(id) else {
                    unsupported = unsupported
                        .or_else(|| Some(format!("builtin record {id} ended without beginning")));
                    continue;
                };
                let BuiltinRecord::Begin {
                    tid,
                    builtin,
                    argv,
                    cwd,
                    ..
                } = begin
                else {
                    continue;
                };
                if !is_git_builtin(builtin) {
                    continue;
                }
                state_for(&mut states, *tid, work_root).span = None;
                if *exit != 0 {
                    // A git builtin that failed obtained nothing, and a command that failed is
                    // rolled back wholesale before policy is consulted.
                    continue;
                }
                match gitcmd::parse(argv) {
                    // The builtin succeeded, so the grammar must agree with it; a disagreement is a
                    // protocol anomaly, not a command to interpret.
                    Err(reason) => unsupported = unsupported.or(Some(reason)),
                    Ok(invocation) => {
                        for pathspec in &invocation.pathspecs {
                            let resolved = resolve(cwd, pathspec);
                            match seed_resource(work_root, &resolved) {
                                Some(resource) => events.push(Event::new(
                                    principal.clone(),
                                    invocation.action.clone(),
                                    resource,
                                )),
                                None => {
                                    unsupported = unsupported.or(Some(format!(
                                        "git pathspec {pathspec:?} is outside the snapshot or \
                                         inside .git/"
                                    )));
                                }
                            }
                        }
                    }
                }
            }
            Item::Line(line) => {
                let state = state_for(&mut states, line.tid, work_root);
                match &line.call {
                    Call::Exited { status } => {
                        if Some(line.tid) == root_tid {
                            exit_code = Some(*status);
                        }
                    }
                    Call::Syscall {
                        name,
                        args,
                        ret,
                        ret_path,
                    } => {
                        let args = split_args(args);
                        match name.as_str() {
                            "chdir" if *ret == 0 => {
                                if let Some(path) = args.first().and_then(|arg| parse_quoted(arg)) {
                                    state.cwd = resolve(&state.cwd, &path);
                                }
                            }
                            "fchdir" if *ret == 0 => {
                                if let Some(dir) = args.first().and_then(|arg| decorated_path(arg))
                                {
                                    state.cwd = dir;
                                }
                            }
                            "clone" | "clone3" | "fork" | "vfork" if *ret > 0 => {
                                let inherited = TidState {
                                    cwd: state.cwd.clone(),
                                    attr: state.attr,
                                    // A span belongs to the thread that opened it: git2 is
                                    // synchronous, so a child does not continue its parent's
                                    // in-flight builtin.
                                    span: None,
                                };
                                #[expect(
                                    clippy::cast_sign_loss,
                                    reason = "guarded by `ret > 0`: the return is a child tid"
                                )]
                                states.insert(*ret as u32, inherited);
                            }
                            "execve" | "execveat" if *ret == 0 => {
                                let (program, argv) = if name == "execve" {
                                    (args.first().copied(), args.get(1).copied())
                                } else {
                                    (args.get(1).copied(), args.get(2).copied())
                                };
                                let program = program.and_then(parse_quoted).unwrap_or_default();
                                let argv = argv.map(argv_strings).unwrap_or_default();
                                let is_git = basename(&program) == "git"
                                    || argv.first().map(|arg| basename(arg) == "git") == Some(true);
                                if is_git {
                                    // Every supported git command is a builtin, and the catch-all
                                    // `git` builtin refuses the rest before PATH search: a git
                                    // *process* means the builtins were bypassed, and nothing
                                    // recorded what it was asked to do.
                                    state.attr = Attr::Git;
                                    unsupported = unsupported.or_else(|| {
                                        Some(
                                            "git invoked outside the git builtin is not \
                                             instrumentable"
                                                .to_string(),
                                        )
                                    });
                                }
                            }
                            _ if *ret < 0 => {}
                            // Inside a raw-git subtree nothing is attributable.
                            _ if state.attr == Attr::Git => {}
                            _ if state.span.is_some() => {
                                // Inside a git builtin: reads are the command's declared
                                // dependencies, writes are the physical diff's business.
                                for (action, path) in
                                    file_effects(name, &args, ret_path.as_deref(), state)
                                {
                                    if action == Action::Read
                                        && let Some(relative) = work_relative(work_root, &path)
                                    {
                                        git_reads.push(relative);
                                    }
                                }
                            }
                            _ => {
                                for (action, path) in
                                    file_effects(name, &args, ret_path.as_deref(), state)
                                {
                                    if let Some(resource) = seed_resource(work_root, &path) {
                                        events.push(Event::new(
                                            principal.clone(),
                                            action,
                                            resource,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if open_spans.values().any(|record| match record {
        BuiltinRecord::Begin { builtin, .. } => is_git_builtin(builtin),
        BuiltinRecord::End { .. } => false,
    }) {
        // The builtin panicked, or the process was replaced or killed mid-git. Either way the
        // record stream is incomplete, and an incomplete stream must not merge.
        unsupported = unsupported.or_else(|| Some("a git builtin span never closed".to_string()));
    }

    dedup_preserving_order(&mut events);
    git_reads.sort();
    git_reads.dedup();
    Translation {
        events,
        unsupported,
        exit_code,
        git_reads,
    }
}

/// Interleaves the syscall stream and the record stream into one ordered item sequence.
///
/// The sort is stable, so within one timestamp and one rank both streams keep their recorded order —
/// and per-thread order, which is program order, is never disturbed.
fn merge<'a>(lines: &'a [TraceLine], builtins: &'a [BuiltinRecord]) -> Vec<Item<'a>> {
    let mut items: Vec<Item<'a>> = Vec::with_capacity(lines.len() + builtins.len());
    items.extend(lines.iter().map(Item::Line));
    items.extend(builtins.iter().map(|record| match record {
        BuiltinRecord::Begin { .. } => Item::Begin(record),
        BuiltinRecord::End { .. } => Item::End(record),
    }));
    items.sort_by_key(Item::key);
    items
}

/// The per-thread state, created on first sight of the thread.
fn state_for<'a>(
    states: &'a mut HashMap<u32, TidState>,
    tid: u32,
    work_root: &Path,
) -> &'a mut TidState {
    states.entry(tid).or_insert_with(|| TidState {
        cwd: work_root.to_path_buf(),
        attr: Attr::Shell,
        span: None,
    })
}

/// Whether a registered builtin name is one of the git variants (or the refusing catch-all).
fn is_git_builtin(name: &str) -> bool {
    name == "git" || name.starts_with("git ")
}

/// The capability effects a single file syscall had, as `(action, absolute path)` pairs.
fn file_effects(
    name: &str,
    args: &[&str],
    ret_path: Option<&str>,
    state: &TidState,
) -> Vec<(Action, PathBuf)> {
    match name {
        "open" => open_effect(
            args.get(1),
            path_at(args.first(), args.first(), state, ret_path),
        ),
        "openat" | "openat2" => open_effect(
            args.get(2),
            path_at(args.first(), args.get(1), state, ret_path),
        ),
        "creat" => path_at(args.first(), args.first(), state, ret_path)
            .map(|path| vec![(Action::Edit, path)])
            .unwrap_or_default(),
        // A path argument with no directory descriptor: resolve against the thread's cwd.
        "unlink" | "rmdir" | "mkdir" | "chmod" | "truncate" => {
            edit_at(path_at(None, args.first(), state, None))
        }
        "unlinkat" | "mkdirat" | "fchmodat" => {
            edit_at(path_at(args.first(), args.get(1), state, None))
        }
        // `symlink(target, linkpath)`: only the link itself is written.
        "symlink" => edit_at(path_at(None, args.get(1), state, None)),
        "symlinkat" => edit_at(path_at(args.get(1), args.get(2), state, None)),
        // `link(old, new)` / `linkat(olddirfd, old, newdirfd, new, flags)`: the new name is written.
        "link" => edit_at(path_at(None, args.get(1), state, None)),
        "linkat" => edit_at(path_at(args.get(2), args.get(3), state, None)),
        // A rename writes both ends: the source disappears, the destination appears.
        "rename" => {
            let mut effects = edit_at(path_at(None, args.first(), state, None));
            effects.extend(edit_at(path_at(None, args.get(1), state, None)));
            effects
        }
        "renameat" | "renameat2" => {
            let mut effects = edit_at(path_at(args.first(), args.get(1), state, None));
            effects.extend(edit_at(path_at(args.get(2), args.get(3), state, None)));
            effects
        }
        _ => Vec::new(),
    }
}

/// Classifies an open by its flags: any write intent is an [`Action::Edit`], otherwise a
/// [`Action::Read`]. Directory opens carry no file capability.
fn open_effect(flags: Option<&&str>, path: Option<PathBuf>) -> Vec<(Action, PathBuf)> {
    let Some(path) = path else {
        return Vec::new();
    };
    let flags = flags.copied().unwrap_or("");
    if flags.contains("O_DIRECTORY") {
        return Vec::new();
    }
    let writing = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]
        .iter()
        .any(|flag| flags.contains(flag));
    let action = if writing { Action::Edit } else { Action::Read };
    vec![(action, path)]
}

/// Wraps an optional path as a single edit effect.
fn edit_at(path: Option<PathBuf>) -> Vec<(Action, PathBuf)> {
    path.map(|path| vec![(Action::Edit, path)])
        .unwrap_or_default()
}

/// Resolves a syscall's path argument to an absolute path.
///
/// `strace -y` decorates a returned descriptor with the path the kernel resolved, which is the most
/// reliable source when it exists. Otherwise the directory descriptor's decoration (including
/// `AT_FDCWD</abs/cwd>`) supplies the base, and the thread's tracked cwd is the last resort.
fn path_at(
    dirfd: Option<&&str>,
    path: Option<&&str>,
    state: &TidState,
    ret_path: Option<&str>,
) -> Option<PathBuf> {
    if let Some(resolved) = ret_path {
        return Some(PathBuf::from(resolved));
    }
    let path = parse_quoted(path.copied()?)?;
    let base = dirfd
        .copied()
        .and_then(decorated_path)
        .unwrap_or_else(|| state.cwd.clone());
    Some(resolve(&base, &path))
}

/// Extracts the `-y` path decoration from a descriptor argument such as `AT_FDCWD</work>` or
/// `5</work/src>`.
fn decorated_path(arg: &str) -> Option<PathBuf> {
    let start = arg.find('<')?;
    let end = arg.rfind('>')?;
    let path = arg.get(start + 1..end)?;
    path.starts_with('/').then(|| PathBuf::from(path))
}

/// Maps an absolute path to the seed-relative resource it names, or `None` when the path is outside
/// the work snapshot, is the snapshot root itself, or lives in git's private `.git/` directory.
fn seed_resource(work_root: &Path, path: &Path) -> Option<Resource> {
    let relative = path.strip_prefix(work_root).ok()?;
    let segments: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if segments.is_empty() || segments[0] == ".git" {
        return None;
    }
    Some(Resource::from(segments))
}

/// The last path component of a program path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Decodes an `execve` argv array argument (`["git", "add", …]`) into owned strings.
fn argv_strings(arg: &str) -> Vec<String> {
    let inner = arg
        .trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(arg);
    split_args(inner)
        .into_iter()
        .filter_map(parse_quoted)
        .collect()
}

/// Removes exact duplicate events, keeping the first occurrence.
///
/// Git re-reads and re-writes the same paths freely, and a shell may open one file twice; the
/// capability requested is the same either way. Distinct actions on one path all survive.
fn dedup_preserving_order(events: &mut Vec<Event>) {
    let mut seen: Vec<Event> = Vec::new();
    events.retain(|event| {
        if seen.contains(event) {
            false
        } else {
            seen.push(event.clone());
            true
        }
    });
}

/// The work-snapshot-relative, `/`-joined form of a path inside the snapshot, `.git/` included.
///
/// Unlike [`seed_resource`], which names *policy resources* and therefore excludes git's private
/// directory, this is the key format the mux's generation map uses: a git builtin's dependency on
/// `.git/index` is exactly the dependency that has to be checked for staleness.
fn work_relative(work_root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(work_root).ok()?;
    let segments: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strace::parse_trace;

    const WORK: &str = "/work";
    /// The thread the executor's shell runs on in every fixture.
    const SHELL_TID: u32 = 10;

    /// Translates one fixture: a syscall log and a record stream, merged by timestamp.
    ///
    /// Fixtures use microsecond stamps 1, 2, 3, … so the interleaving under test stays readable.
    fn run(text: &str, records: Vec<BuiltinRecord>) -> Translation {
        let lines = parse_trace(text).expect("parse fixture");
        translate(
            &lines,
            &records,
            &Principal::from("agent0"),
            Path::new(WORK),
        )
    }

    fn event(action: Action, path: &[&str]) -> Event {
        Event::new("agent0", action, Resource::from(path.to_vec()))
    }

    /// A `-ttt` timestamp for a microsecond count.
    fn at(ts: u64) -> String {
        format!("{}.{:06}", ts / 1_000_000, ts % 1_000_000)
    }

    /// One trace line on `tid` at `ts`.
    fn syscall(ts: u64, tid: u32, rest: &str) -> String {
        format!("{tid}  {} {rest}\n", at(ts))
    }

    /// The root process's `execve` line, as strace prints it for the traced executor.
    fn root(ts: u64, command: &str) -> String {
        syscall(
            ts,
            SHELL_TID,
            &format!(
                "execve(\"/exec/marsh-exec\", [\"marsh-exec\", \"-c\", \"{command}\"], 0x7ffd /* 80 vars */) = 0"
            ),
        )
    }

    /// A child process: the shell clones, the child `execve`s.
    fn spawn_child(ts: u64, tid: u32, program: &str, argv: &[&str]) -> String {
        let argv = argv
            .iter()
            .map(|arg| format!("\"{arg}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{}{}",
            syscall(
                ts,
                SHELL_TID,
                &format!("clone(child_stack=NULL, flags=SIGCHLD) = {tid}")
            ),
            syscall(
                ts,
                tid,
                &format!("execve(\"{program}\", [{argv}], 0x7ffd /* 79 vars */) = 0")
            ),
        )
    }

    fn begin(ts: u64, tid: u32, id: u64, builtin: &str, argv: &[&str], cwd: &str) -> BuiltinRecord {
        BuiltinRecord::Begin {
            id,
            ts,
            tid,
            builtin: builtin.to_string(),
            argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
            cwd: PathBuf::from(cwd),
        }
    }

    fn end(ts: u64, tid: u32, id: u64, exit: u8) -> BuiltinRecord {
        BuiltinRecord::End { id, ts, tid, exit }
    }

    /// A whole git builtin span on the shell thread, with nothing in between.
    fn git_span(argv: &[&str], cwd: &str, exit: u8) -> Vec<BuiltinRecord> {
        let builtin = format!("git {}", argv.get(1).copied().unwrap_or_default());
        vec![
            begin(2, SHELL_TID, 0, &builtin, argv, cwd),
            end(3, SHELL_TID, 0, exit),
        ]
    }

    #[test]
    fn redirection_open_is_an_edit_and_read_open_is_a_read() {
        let text = format!(
            "{}{}{}",
            root(1, "printf x > src/file0.txt; cat -- src/file1.txt"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"/work/src/file0.txt\", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 10</work/src/file0.txt>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"src/file1.txt\", O_RDONLY) = 3</work/src/file1.txt>"
            ),
        );
        let translation = run(&text, Vec::new());
        assert_eq!(translation.unsupported, None);
        assert_eq!(
            translation.events,
            vec![
                event(Action::Edit, &["src", "file0.txt"]),
                event(Action::Read, &["src", "file1.txt"]),
            ]
        );
    }

    #[test]
    fn append_and_removal_syscalls_are_edits() {
        let text = format!(
            "{}{}{}{}",
            root(1, "printf x >> a.txt; rm -- b.txt; mv c.txt d.txt"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"a.txt\", O_WRONLY|O_CREAT|O_APPEND) = 3</work/a.txt>"
            ),
            syscall(3, SHELL_TID, "unlinkat(AT_FDCWD</work>, \"b.txt\", 0) = 0"),
            syscall(
                4,
                SHELL_TID,
                "renameat2(AT_FDCWD</work>, \"c.txt\", AT_FDCWD</work>, \"d.txt\", RENAME_NOREPLACE) = 0"
            ),
        );
        let translation = run(&text, Vec::new());
        assert_eq!(
            translation.events,
            vec![
                event(Action::Edit, &["a.txt"]),
                event(Action::Edit, &["b.txt"]),
                event(Action::Edit, &["c.txt"]),
                event(Action::Edit, &["d.txt"]),
            ],
            "a rename writes both ends"
        );
    }

    #[test]
    fn git_builtin_records_map_to_their_capabilities() {
        let cases: [(&[&str], Action); 11] = [
            (&["git", "add", "--", "src/file0.txt"], Action::Stage),
            // The separator is optional now that the builtin owns its grammar.
            (&["git", "add", "src/file0.txt"], Action::Stage),
            (&["git", "stage", "--", "src/file0.txt"], Action::Stage),
            (
                &["git", "restore", "--staged", "--", "src/file0.txt"],
                Action::Unstage,
            ),
            (
                &["git", "checkout", "HEAD", "--", "src/file0.txt"],
                Action::Checkout,
            ),
            (
                &["git", "stash", "push", "--", "src/file0.txt"],
                Action::Stash,
            ),
            (&["git", "rm", "--", "src/file0.txt"], Action::Delete),
            (
                &["git", "clean", "-f", "--", "src/file0.txt"],
                Action::Clean,
            ),
            (&["git", "diff", "--", "src/file0.txt"], Action::Diff),
            (&["git", "log", "--", "src/file0.txt"], Action::History),
            (
                &["git", "commit", "-m", "step 7", "--", "src/file0.txt"],
                Action::commit("step 7"),
            ),
        ];
        for (argv, action) in cases {
            let translation = run(&root(1, "git …"), git_span(argv, WORK, 0));
            assert_eq!(translation.unsupported, None, "{argv:?}");
            assert_eq!(
                translation.events,
                vec![event(action, &["src", "file0.txt"])],
                "{argv:?}"
            );
        }
    }

    #[test]
    fn pathspecs_resolve_against_the_record_cwd() {
        let translation = run(
            &root(1, "cd src && git add -- file0.txt"),
            git_span(&["git", "add", "--", "file0.txt"], "/work/src", 0),
        );
        assert_eq!(
            translation.events,
            vec![event(Action::Stage, &["src", "file0.txt"])],
            "the shell's logical cwd travels in the record, not in the trace"
        );
    }

    #[test]
    fn cwd_tracking_resolves_undecorated_relative_paths() {
        let text = format!(
            "{}{}{}{}",
            root(1, "cd src && rm -- file0.txt"),
            syscall(2, SHELL_TID, "clone(child_stack=NULL, flags=SIGCHLD) = 11"),
            syscall(3, 11, "chdir(\"src\") = 0"),
            syscall(4, 11, "unlink(\"file0.txt\") = 0"),
        );
        let translation = run(&text, Vec::new());
        assert_eq!(
            translation.events,
            vec![event(Action::Edit, &["src", "file0.txt"])],
            "a relative chdir composes with the inherited cwd"
        );
    }

    #[test]
    fn out_of_root_and_dot_git_paths_produce_no_events() {
        let text = format!(
            "{}{}{}{}{}",
            root(1, "printf x > /tmp/escape; cat /etc/passwd"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"/tmp/escape\", O_WRONLY|O_CREAT) = 3</tmp/escape>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"/etc/passwd\", O_RDONLY|O_CLOEXEC) = 4</etc/passwd>"
            ),
            syscall(
                4,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \".git/config\", O_RDONLY) = 5</work/.git/config>"
            ),
            syscall(
                5,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"src\", O_RDONLY|O_DIRECTORY) = 6</work/src>"
            ),
        );
        let translation = run(&text, Vec::new());
        assert!(
            translation.events.is_empty(),
            "got {:?}",
            translation.events
        );
        assert!(
            translation.git_reads.is_empty(),
            "a `.git/` read outside a git span is nobody's dependency: {:?}",
            translation.git_reads
        );
    }

    #[test]
    fn failed_syscalls_and_duplicates_are_dropped() {
        let text = format!(
            "{}{}{}{}",
            root(1, "cat -- a.txt a.txt; cat -- missing"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"a.txt\", O_RDONLY) = 3</work/a.txt>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"a.txt\", O_RDONLY) = 3</work/a.txt>"
            ),
            syscall(
                4,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"missing\", O_RDONLY) = -1 ENOENT (No such file or directory)"
            ),
        );
        let translation = run(&text, Vec::new());
        assert_eq!(translation.events, vec![event(Action::Read, &["a.txt"])]);
    }

    #[test]
    fn distinct_actions_on_one_path_all_survive() {
        let text = format!(
            "{}{}{}",
            root(1, "cat -- a.txt; printf x >> a.txt"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"a.txt\", O_RDONLY) = 3</work/a.txt>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"a.txt\", O_WRONLY|O_APPEND) = 3</work/a.txt>"
            ),
        );
        let translation = run(&text, Vec::new());
        assert_eq!(
            translation.events,
            vec![
                event(Action::Read, &["a.txt"]),
                event(Action::Edit, &["a.txt"]),
            ]
        );
    }

    #[test]
    fn unmappable_git_command_lines_are_reported_unsupported() {
        let cases: [(&[&str], &str); 6] = [
            (&["git", "add", "--", "src/*.txt"], "pathspec pattern"),
            (&["git", "push", "--", "src/file0.txt"], "not mappable"),
            (
                &["git", "stash", "pop", "--", "src/file0.txt"],
                "stash push",
            ),
            (
                &["git", "checkout", "other-branch", "--", "src/file0.txt"],
                "not mappable",
            ),
            (
                &["git", "restore", "--", "src/file0.txt"],
                "use git checkout HEAD",
            ),
            (&["git", "add", "--", "/tmp/escape"], "outside the snapshot"),
        ];
        for (argv, expected) in cases {
            let translation = run(&root(1, "git …"), git_span(argv, WORK, 0));
            let reason = translation
                .unsupported
                .unwrap_or_else(|| panic!("{argv:?} should be unsupported"));
            assert!(reason.contains(expected), "{argv:?} reported {reason:?}");
        }
    }

    #[test]
    fn root_exit_status_is_recorded() {
        let text = format!(
            "{}{}{}",
            root(1, "false"),
            syscall(2, 11, "+++ exited with 7 +++"),
            syscall(3, SHELL_TID, "+++ exited with 1 +++"),
        );
        let translation = run(&text, Vec::new());
        assert_eq!(
            translation.exit_code,
            Some(1),
            "the traced root process, not a child, determines the command's status"
        );
    }

    /// The acceptance anchor, in synthetic form: `touch foo && git add foo` must show *both* the
    /// creation syscall (from the external `touch`) and the builtin invocation (from the record).
    #[test]
    fn builtin_records_interleave_with_syscalls() {
        let text = format!(
            "{}{}{}{}",
            root(1, "touch foo && git add foo"),
            spawn_child(2, 11, "/usr/bin/touch", &["touch", "foo"]),
            syscall(
                2,
                11,
                "openat(AT_FDCWD</work>, \"foo\", O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666) = 3</work/foo>"
            ),
            syscall(
                4,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \".git/index\", O_RDONLY) = 4</work/.git/index>"
            ),
        );
        let translation = run(
            &text,
            vec![
                begin(3, SHELL_TID, 0, "git add", &["git", "add", "foo"], WORK),
                end(5, SHELL_TID, 0, 0),
            ],
        );
        assert_eq!(translation.unsupported, None);
        assert_eq!(
            translation.events,
            vec![
                event(Action::Edit, &["foo"]),
                event(Action::Stage, &["foo"]),
            ],
            "one stream carried the creation, the other carried the staging"
        );
        assert_eq!(
            translation.git_reads,
            vec![".git/index".to_string()],
            "and the staging declared what it read"
        );
    }

    #[test]
    fn git_span_reads_are_collected_and_writes_are_not() {
        let text = format!(
            "{}{}{}{}",
            root(1, "git add -- src/file0.txt"),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \".git/index\", O_RDONLY) = 4</work/.git/index>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"src/file0.txt\", O_RDONLY) = 5</work/src/file0.txt>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \".git/index.lock\", O_WRONLY|O_CREAT|O_EXCL, 0666) = 6</work/.git/index.lock>"
            ),
        );
        let translation = run(
            &text,
            git_span(&["git", "add", "--", "src/file0.txt"], WORK, 0),
        );
        assert_eq!(
            translation.events,
            vec![event(Action::Stage, &["src", "file0.txt"])],
            "the pathspec is the capability; git's own syscalls are not"
        );
        assert_eq!(
            translation.git_reads,
            vec![".git/index".to_string(), "src/file0.txt".to_string()],
            "reads are dependencies; `.git/index.lock` is not one"
        );
    }

    #[test]
    fn failed_git_span_requests_nothing() {
        let translation = run(
            &root(1, "git rm -- src/file0.txt"),
            git_span(&["git", "rm", "--", "src/file0.txt"], WORK, 1),
        );
        assert_eq!(translation.unsupported, None, "a refusal is not an anomaly");
        assert!(
            translation.events.is_empty(),
            "a git builtin that failed obtained nothing: {:?}",
            translation.events
        );
    }

    #[test]
    fn raw_git_execve_is_unsupported() {
        let text = format!(
            "{}{}{}",
            root(1, "/usr/bin/git add -- src/file0.txt"),
            spawn_child(
                2,
                11,
                "/usr/bin/git",
                &["git", "add", "--", "src/file0.txt"]
            ),
            syscall(
                3,
                11,
                "openat(AT_FDCWD</work>, \"src/file0.txt\", O_RDONLY) = 4</work/src/file0.txt>"
            ),
        );
        let translation = run(&text, Vec::new());
        let reason = translation.unsupported.expect("a bypass is unsupported");
        assert!(reason.contains("outside the git builtin"), "got {reason:?}");
        assert!(
            translation.events.is_empty(),
            "and its syscalls are attributed to nothing: {:?}",
            translation.events
        );
    }

    #[test]
    fn non_git_builtin_records_are_transparent() {
        let text = format!(
            "{}{}",
            root(1, "cd src && printf x > file0.txt"),
            syscall(
                4,
                SHELL_TID,
                "openat(AT_FDCWD</work/src>, \"file0.txt\", O_WRONLY|O_CREAT|O_TRUNC) = 3</work/src/file0.txt>"
            ),
        );
        let translation = run(
            &text,
            vec![
                begin(2, SHELL_TID, 0, "cd", &["cd", "src"], WORK),
                end(3, SHELL_TID, 0, 0),
            ],
        );
        assert_eq!(translation.unsupported, None);
        assert_eq!(
            translation.events,
            vec![event(Action::Edit, &["src", "file0.txt"])],
            "a non-git builtin says nothing; its syscalls still speak"
        );
        assert!(translation.git_reads.is_empty());
    }

    #[test]
    fn unclosed_git_span_is_unsupported() {
        let translation = run(
            &root(1, "git add -- src/file0.txt"),
            vec![begin(
                2,
                SHELL_TID,
                0,
                "git add",
                &["git", "add", "--", "src/file0.txt"],
                WORK,
            )],
        );
        let reason = translation
            .unsupported
            .expect("an open span is unsupported");
        assert!(reason.contains("never closed"), "got {reason:?}");
        assert!(translation.events.is_empty());
    }

    #[test]
    fn same_microsecond_syscall_lands_inside_the_span() {
        let text = format!(
            "{}{}{}",
            root(1, "git add -- src/file0.txt"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \".git/HEAD\", O_RDONLY) = 4</work/.git/HEAD>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"src/file0.txt\", O_RDONLY) = 5</work/src/file0.txt>"
            ),
        );
        let translation = run(
            &text,
            git_span(&["git", "add", "--", "src/file0.txt"], WORK, 0),
        );
        assert_eq!(
            translation.git_reads,
            vec![".git/HEAD".to_string(), "src/file0.txt".to_string()],
            "a syscall sharing a microsecond with `Begin` or `End` is inside the window"
        );
        assert_eq!(
            translation.events,
            vec![event(Action::Stage, &["src", "file0.txt"])],
            "and is therefore not a capability request of its own"
        );
    }
}
