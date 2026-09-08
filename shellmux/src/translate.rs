//! Turning one execution's ordered evidence into capability events.
//!
//! The executor hands over a single [`ExecutionEvidence`]: syscalls and builtin invocations
//! already decoded and already interleaved by timestamp. Three rules read that sequence:
//!
//! * **A syscall is a capability** when the thread issuing it is Shell-attributed: the command line
//!   means nothing and the syscall is everything (`> p` opened for writing **is** `Edit p`).
//! * **A builtin invocation is a capability** when it is a git variant: `git add -- p` **is**
//!   `Stage p`, derived from the recorded argv through the one shared grammar
//!   ([`marsh_exec::gitcmd`]). Every other builtin is transparent — its syscalls already say what
//!   it did.
//! * **A git builtin's own syscalls are not capabilities** but are its *read set*: the paths it
//!   consulted (`.git/index`, `HEAD`, refs, and the worktree files it hashed) are what its decision
//!   depended on, and a command must declare that or it could merge a conclusion drawn from a
//!   repository someone else has since changed.
//!
//! The executor's [`GitAction`] vocabulary is mapped to the policy's [`Action`] here, and nowhere
//! else: the executor reports what git was asked to do, and this is where that becomes a
//! capability request.
//!
//! Attribution is inherited across `clone`/`fork`. A raw `execve` of a git binary is *not*
//! instrumentable — nothing recorded its invocation — and makes the whole command unsupported.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use marsh_exec::evidence::{parse_quoted, split_args};
use marsh_exec::gitcmd::{self, resolve};
use marsh_exec::hooks::BuiltinRecord;
use marsh_exec::{Call, ExecutionEvent, ExecutionEvidence, GitAction, TraceLine};
use rust_validator::{Action, Event, Principal, Resource};

/// What one traced command amounts to, in capability terms.
pub(crate) struct Translation {
    /// Capability events the command requested, in merged-stream order, duplicates collapsed.
    pub events: Vec<Event>,
    /// Set when some part of the command cannot be expressed as capabilities. Such a command is
    /// never merged: the mux refuses to guess at a footprint it cannot name.
    pub unsupported: Option<String>,
    /// Work-snapshot-relative paths a git builtin actually read, sorted and deduplicated,
    /// `.git/` included.
    ///
    /// A git operation decides from repository state no pathspec names — the index, `HEAD`, refs —
    /// and may write nothing at all (`git diff`, a no-op `git restore --staged`). Its observed reads
    /// are how such a command declares what its answer depended on.
    pub git_reads: Vec<String>,
    /// Whether any traced syscall wrote, or opened for writing, a path inside the work root —
    /// `.git/` included, and whether or not it became a capability event.
    ///
    /// This is the diff's precondition: no write inside the root means an empty write set, which
    /// is what lets a conclusion skip the two full tree walks `diff_trees` costs.
    pub wrote_in_root: bool,
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

/// Translates one execution's evidence into the capabilities it requested.
///
/// `work_root` must be the canonical path of the work snapshot, and `cwd` the directory the command
/// itself started in — the sandbox's directory inside that snapshot, which is where a relative path
/// with no descriptor decoration resolves from. Paths outside the snapshot, and everything under
/// any `.git/` inside it, produce no events.
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
    evidence: &ExecutionEvidence,
    principal: &Principal,
    work_root: &Path,
    cwd: &Path,
) -> Translation {
    let mut states: HashMap<u32, TidState> = HashMap::new();
    let mut events: Vec<Event> = Vec::new();
    let mut git_reads: Vec<String> = Vec::new();
    let mut wrote_in_root = false;
    let mut unsupported: Option<String> = None;
    let mut open_spans: HashMap<u64, &BuiltinRecord> = HashMap::new();

    let frame = Frame {
        principal,
        work_root,
        cwd,
    };
    for item in evidence.events() {
        let mut observed = Observed {
            events: &mut events,
            git_reads: &mut git_reads,
            unsupported: &mut unsupported,
            wrote_in_root: &mut wrote_in_root,
        };
        match item {
            ExecutionEvent::Builtin(record @ BuiltinRecord::Begin { .. }) => {
                record_begin(&mut states, &mut open_spans, &mut observed, record, &frame);
            }
            ExecutionEvent::Builtin(record @ BuiltinRecord::End { .. }) => {
                record_end(&mut states, &mut open_spans, &mut observed, record, &frame);
            }
            ExecutionEvent::System(line) => record_line(&mut states, &mut observed, line, &frame),
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
        git_reads,
        wrote_in_root,
    }
}

/// The immutable frame one evidence item is interpreted in.
struct Frame<'ctx> {
    /// Principal every event produced here is attributed to.
    principal: &'ctx Principal,
    /// Canonical path of the work snapshot; the prefix that makes a path seed-relative.
    work_root: &'ctx Path,
    /// Directory the command itself started in, where a thread's cwd begins.
    cwd: &'ctx Path,
}

/// The accumulators one evidence item may append to.
struct Observed<'out> {
    /// Capability events, in observation order.
    events: &'out mut Vec<Event>,
    /// Snapshot-relative paths a git builtin read.
    git_reads: &'out mut Vec<String>,
    /// First anomaly that makes the command untranslatable.
    unsupported: &'out mut Option<String>,
    /// Whether a write inside the work root was observed, `.git/` included.
    wrote_in_root: &'out mut bool,
}

impl Observed<'_> {
    /// Records the first anomaly only.
    ///
    /// The earliest refusal is the most specific one: everything after it is a consequence of a
    /// command the translator has already given up on naming.
    fn refuse(&mut self, reason: impl FnOnce() -> String) {
        if self.unsupported.is_none() {
            *self.unsupported = Some(reason());
        }
    }
}

/// Opens a builtin span: registers the record, and marks its thread as inside a git builtin.
fn record_begin<'trace>(
    states: &mut HashMap<u32, TidState>,
    open_spans: &mut HashMap<u64, &'trace BuiltinRecord>,
    observed: &mut Observed<'_>,
    record: &'trace BuiltinRecord,
    frame: &Frame<'_>,
) {
    let BuiltinRecord::Begin {
        id, tid, builtin, ..
    } = record
    else {
        return;
    };
    if open_spans.insert(*id, record).is_some() {
        observed.refuse(|| format!("builtin record {id} began twice"));
    }
    if !is_git_builtin(builtin) {
        return;
    }
    let state = state_for(states, *tid, frame.cwd);
    if state.span.is_some() {
        // Builtins on one thread are sequential, and concurrent pipeline elements run on different
        // threads; an overlap would mean the span window is meaningless.
        observed.refuse(|| "overlapping git builtin spans on one thread".to_string());
    }
    state.span = Some(*id);
}

/// Closes a builtin span, and turns a successful git builtin's argv into capability events.
///
/// Paths resolve against the *recorded* cwd of the `Begin` edge, not the thread's current one: the
/// pathspec meant what it meant when the builtin was invoked.
fn record_end(
    states: &mut HashMap<u32, TidState>,
    open_spans: &mut HashMap<u64, &BuiltinRecord>,
    observed: &mut Observed<'_>,
    record: &BuiltinRecord,
    frame: &Frame<'_>,
) {
    let BuiltinRecord::End { id, exit, .. } = record else {
        return;
    };
    let Some(BuiltinRecord::Begin {
        tid,
        builtin,
        argv,
        cwd,
        ..
    }) = open_spans.remove(id)
    else {
        observed.refuse(|| format!("builtin record {id} ended without beginning"));
        return;
    };
    if !is_git_builtin(builtin) {
        return;
    }
    state_for(states, *tid, cwd).span = None;
    if *exit != 0 {
        // A git builtin that failed obtained nothing, and a command that failed is rolled back
        // wholesale before policy is consulted.
        return;
    }
    // The builtin succeeded, so the grammar must agree with it; a disagreement is a protocol
    // anomaly, not a command to interpret.
    let invocation = match gitcmd::parse(argv) {
        Err(reason) => {
            observed.refuse(|| reason.to_string());
            return;
        }
        Ok(invocation) => invocation,
    };
    let action = capability_of(invocation.action);
    for pathspec in &invocation.pathspecs {
        let resolved = resolve(cwd, pathspec);
        if let Some(resource) = seed_resource(frame.work_root, &resolved) {
            observed.events.push(Event::new(
                frame.principal.clone(),
                action.clone(),
                resource,
            ));
        } else {
            observed.refuse(|| {
                format!("git pathspec {pathspec:?} is outside the snapshot or inside .git/")
            });
        }
    }
}

/// The capability a git operation requests.
///
/// The one place the executor's execution vocabulary becomes the policy's: exhaustive, so a git
/// operation added to the executor cannot silently reach the authority as something else.
fn capability_of(action: GitAction) -> Action {
    match action {
        GitAction::Stage => Action::Stage,
        GitAction::Delete => Action::Delete,
        // Moved, not copied: the message is the capability's, and the invocation is done with it.
        GitAction::Commit { message } => Action::Commit { message },
        GitAction::Unstage => Action::Unstage,
        GitAction::Checkout => Action::Checkout,
        GitAction::Stash => Action::Stash,
        GitAction::Clean => Action::Clean,
        GitAction::Diff => Action::Diff,
        GitAction::History => Action::History,
    }
}

/// Interprets one syscall: thread bookkeeping first, then the capability it amounts to.
///
/// The syscall arms are ordered by specificity: cwd tracking and attribution inheritance apply to
/// every thread, a failed call means nothing happened, a raw-git subtree is unattributable, and a
/// git builtin's own reads are its declared dependencies rather than the principal's requests.
fn record_line(
    states: &mut HashMap<u32, TidState>,
    observed: &mut Observed<'_>,
    line: &TraceLine,
    frame: &Frame<'_>,
) {
    let state = state_for(states, line.tid, frame.cwd);
    // An exit record carries no path and no capability: the execution's status is the executor's
    // to report, and it already has.
    let Call::Syscall {
        name,
        args,
        ret,
        ret_path,
    } = &line.call
    else {
        return;
    };

    let args = split_args(args);
    match name.as_str() {
        "chdir" if *ret == 0 => {
            if let Some(path) = args.first().and_then(|arg| parse_quoted(arg)) {
                state.cwd = resolve(&state.cwd, &path);
            }
        }
        "fchdir" if *ret == 0 => {
            if let Some(dir) = args.first().and_then(|arg| decorated_path(arg)) {
                state.cwd = dir;
            }
        }
        "clone" | "clone3" | "fork" | "vfork" if *ret > 0 => {
            let inherited = TidState {
                cwd: state.cwd.clone(),
                attr: state.attr,
                // A span belongs to the thread that opened it: git2 is synchronous, so a child
                // does not continue its parent's in-flight builtin.
                span: None,
            };
            if let Ok(child) = u32::try_from(*ret) {
                states.insert(child, inherited);
            }
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
                || argv.first().is_some_and(|arg| basename(arg) == "git");
            if is_git {
                // Every supported git command is a builtin, and the catch-all `git` builtin
                // refuses the rest before PATH search: a git *process* means the builtins were
                // bypassed, and nothing recorded what it was asked to do.
                state.attr = Attr::Git;
                observed.refuse(|| {
                    "git invoked outside the git builtin is not instrumentable".to_string()
                });
            }
        }
        _ if *ret < 0 => {}
        // Inside a raw-git subtree nothing is attributable.
        _ if state.attr == Attr::Git => {}
        _ if state.span.is_some() => {
            // Inside a git builtin: reads are the command's declared dependencies, writes are the
            // physical diff's business — but the diff still has to run, so the write is noted.
            for (action, path) in file_effects(name, &args, ret_path.as_deref(), state) {
                if action != Action::Read && work_relative(frame.work_root, &path).is_some() {
                    *observed.wrote_in_root = true;
                }
                if action == Action::Read
                    && let Some(relative) = work_relative(frame.work_root, &path)
                {
                    observed.git_reads.push(relative);
                }
            }
        }
        _ => {
            for (action, path) in file_effects(name, &args, ret_path.as_deref(), state) {
                // `work_relative`, not `seed_resource`: a write under `.git/` names no policy
                // resource but is exactly what the diff would find.
                if action != Action::Read && work_relative(frame.work_root, &path).is_some() {
                    *observed.wrote_in_root = true;
                }
                if let Some(resource) = seed_resource(frame.work_root, &path) {
                    observed
                        .events
                        .push(Event::new(frame.principal.clone(), action, resource));
                }
            }
        }
    }
}

/// The per-thread state, created on first sight of the thread.
fn state_for<'a>(states: &'a mut HashMap<u32, TidState>, tid: u32, cwd: &Path) -> &'a mut TidState {
    states.entry(tid).or_insert_with(|| TidState {
        cwd: cwd.to_path_buf(),
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

/// Maps an absolute path to the seed-relative resource it names, or `None` when the path is
/// outside the work snapshot or lives inside a git repository's private `.git/` directory.
///
/// The snapshot root is the user's own seed, so a file written there is a real resource
/// (`stray.txt`), and a repository may sit at any depth: `.git` is excluded wherever it appears, so
/// `DeepTest/.git/index` is git's business while `DeepTest/src/a.txt` is a resource.
fn seed_resource(work_root: &Path, path: &Path) -> Option<Resource> {
    let segments = gitcmd::relative_segments(work_root, path)?;
    if segments.is_empty() || segments.iter().any(|segment| segment == ".git") {
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
/// Unlike [`seed_resource`], which names *policy resources* and therefore excludes git's
/// private directory, this is the key format the mux's generation map uses: a git builtin's
/// dependency on `.git/index` is exactly the dependency that has to be checked for staleness.
fn work_relative(work_root: &Path, path: &Path) -> Option<String> {
    let segments = gitcmd::relative_segments(work_root, path)?;
    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The job's snapshot root: the translator's strip prefix, the seed itself, and the directory
    /// every fixture command runs in.
    const WORK: &str = "/work";
    /// The thread the executor's shell runs on in every fixture.
    const SHELL_TID: u32 = 10;

    /// Translates one fixture: a syscall log and a record stream, decoded and interleaved by the
    /// executor exactly as a real run's are.
    ///
    /// Fixtures use microsecond stamps 1, 2, 3, … so the interleaving under test stays readable.
    fn run(text: &str, records: &[BuiltinRecord]) -> Translation {
        let dump = serde_json::to_string(records).expect("serialize fixture records");
        let evidence = ExecutionEvidence::parse(text, &dump).expect("parse fixture");
        translate(
            &evidence,
            &Principal::from("agent0"),
            Path::new(WORK),
            Path::new(WORK),
        )
    }

    /// The event a fixture must produce. Resources are seed-relative, so an expected path is
    /// exactly what the command named.
    fn event(action: Action, path: &[&str]) -> Event {
        let segments: Vec<String> = path.iter().map(|part| (*part).to_string()).collect();
        Event::new("agent0", action, Resource::from(segments))
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
        let translation = run(&text, &[]);
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
        let translation = run(&text, &[]);
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
            let translation = run(&root(1, "git …"), &git_span(argv, WORK, 0));
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
            &git_span(&["git", "add", "--", "file0.txt"], "/work/src", 0),
        );
        assert_eq!(
            translation.events,
            vec![event(Action::Stage, &["src", "file0.txt"])],
            "the shell's logical cwd travels in the record, not in the trace"
        );
    }

    /// The sandbox's own directory is where an undecorated relative path resolves from: a command
    /// that unlinks `file0.txt` after a `cd src` never spells `src`, and the resource still has to
    /// name it.
    #[test]
    fn cwd_tracking_resolves_undecorated_relative_paths() {
        let text = format!(
            "{}{}{}{}",
            root(1, "cd src && rm -- file0.txt"),
            syscall(2, SHELL_TID, "clone(child_stack=NULL, flags=SIGCHLD) = 11"),
            syscall(3, 11, "chdir(\"src\") = 0"),
            syscall(4, 11, "unlink(\"file0.txt\") = 0"),
        );
        let translation = run(&text, &[]);
        assert_eq!(
            translation.events,
            vec![event(Action::Edit, &["src", "file0.txt"])],
            "a relative chdir composes with the inherited cwd"
        );
    }

    /// Nothing outside the snapshot and nothing under any `.git/` is a resource — but a file
    /// written at the snapshot root is one, because that root is the user's own seed.
    #[test]
    fn only_paths_inside_the_snapshot_and_outside_git_are_resources() {
        let text = format!(
            "{}{}{}{}{}{}",
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
            syscall(
                6,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"/work/loose.txt\", O_WRONLY|O_CREAT) = 7</work/loose.txt>"
            ),
        );
        let translation = run(&text, &[]);
        assert_eq!(
            translation.events,
            vec![event(Action::Edit, &["loose.txt"])],
            "only the write at the seed root is a capability"
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
        let translation = run(&text, &[]);
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
        let translation = run(&text, &[]);
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
            let translation = run(&root(1, "git …"), &git_span(argv, WORK, 0));
            let reason = translation
                .unsupported
                .unwrap_or_else(|| panic!("{argv:?} should be unsupported"));
            assert!(reason.contains(expected), "{argv:?} reported {reason:?}");
        }
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
            &[
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
            "and the staging declared what it read, as a seed-relative path"
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
            &git_span(&["git", "add", "--", "src/file0.txt"], WORK, 0),
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

    /// A command's write set is what the diff would find, and the diff covers `.git/`. A git
    /// builtin's `.git/index.lock` is neither an event nor a read — so a conclusion that decided
    /// from the event list alone would skip the diff and lose the merge.
    #[test]
    fn a_git_private_write_is_a_write_even_though_it_is_no_event() {
        let text = format!(
            "{}{}",
            root(1, "git add -- src/file0.txt"),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \".git/index.lock\", O_WRONLY|O_CREAT|O_EXCL, 0666) = 6</work/.git/index.lock>"
            ),
        );
        let translation = run(
            &text,
            &git_span(&["git", "add", "--", "src/file0.txt"], WORK, 0),
        );
        assert!(
            translation.git_reads.is_empty(),
            "the lock is not a dependency: {:?}",
            translation.git_reads
        );
        assert!(
            translation.wrote_in_root,
            "the diff must still run: `.git/index.lock` is inside the snapshot"
        );
    }

    /// The precondition for skipping the diff: a command that listed directories and read files
    /// left the snapshot byte-identical, whatever it wrote outside it.
    #[test]
    fn reads_and_directory_opens_are_not_writes() {
        let text = format!(
            "{}{}{}{}",
            root(1, "ls src; cat -- src/file1.txt; printf x > /tmp/escape"),
            syscall(
                2,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"src\", O_RDONLY|O_DIRECTORY) = 3</work/src>"
            ),
            syscall(
                3,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"src/file1.txt\", O_RDONLY) = 4</work/src/file1.txt>"
            ),
            syscall(
                4,
                SHELL_TID,
                "openat(AT_FDCWD</work>, \"/tmp/escape\", O_WRONLY|O_CREAT) = 5</tmp/escape>"
            ),
        );
        let translation = run(&text, &[]);
        assert!(
            !translation.wrote_in_root,
            "nothing inside the snapshot was opened for writing"
        );
    }

    #[test]
    fn failed_git_span_requests_nothing() {
        let translation = run(
            &root(1, "git rm -- src/file0.txt"),
            &git_span(&["git", "rm", "--", "src/file0.txt"], WORK, 1),
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
        let translation = run(&text, &[]);
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
            &[
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
            &[begin(
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
            &git_span(&["git", "add", "--", "src/file0.txt"], WORK, 0),
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
