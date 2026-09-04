# Jobs

marsh exists so several principals — agents, and the person watching them — can work in one directory tree at
once. That poses two questions an ordinary shell never answers: what did this command actually change, and may it
keep the change. A job is where a principal answers them: a sandbox over the seed in which every submitted line
is one atomic transaction — snapshot, execute, translate, authorize, commit. What follows is why each phase has
the shape it has. [Sessions](session.md) has the layout it runs on.

## A job is a sandbox

Identity comes first, because every later phase has to know who is asking. A `Sandbox` is a `name`, a `dir` and a
`uid`, and the name *is* the capability principal (`Sandbox::principal`) — which is what makes the job table a
picture of contention over the seed, `%foo` and `%bar` competing for paths exactly as two agents would. `dir` is
the seed-relative directory its commands start in, `""` for the seed root; `uid` names its snapshot, drawn from
the seed's path, the name, a counter and the clock, so two sandboxes opened in the same nanosecond still differ.
`ShellMux::open_sandbox` and `close_sandbox` bracket its life, which outlasts any one command: a job is a place
to work. The console joins the directory typed at `sd` onto the current job's before the mux sees it
(`repl::job_dir`), so what a user types is a path in the job they typed it in.

## The snapshot, and the version it copied

Saying what a command changed needs something to compare it against; saying whether it may keep the change needs
the version of the seed it started from. One snapshot carries both. `work` is `snap/<uid>`, where the command
runs and the translator's root: a writable btrfs snapshot of the seed, retaken at the start of every command so
each command starts from the seed as it stands, and left in place afterwards so the job keeps a tree to look at.
The reference the diff is taken against is not a second tree — it is the seed itself, read at the moment the
command concludes.

The obvious alternative — holding the seed still for the duration of a command — is the serialization marsh
exists to avoid: one agent thinking for thirty seconds would stop every other. So the retake happens under the
authority *read* lock, which excludes commits but not other sandboxes: a snapshot never copies a half-applied
transaction, and the sequence number taken alongside it names the version it copied, which is what every later
staleness check rests on. `ShellMux::launch` assembles the snapshot and that number together, resolving binaries
first so a missing executor leaves the previous command's tree alone.

The trade is deliberate, and it is the cost of not keeping a second tree. The seed may have moved on by the time
the command concludes, so every difference a foreign transaction introduced lands in *this* command's write set —
a path it never touched, typically as a *removal* of a file the winner had just created, since this snapshot
predates it. Two commands that touched disjoint paths therefore no longer both commit: the second to conclude is
told its snapshot went stale. Conflicts are whole-seed rather than per-path, and the staleness check is exactly
what stops such a write set from reverting the winner.

## What a command said is not what it did

A command line is a request, not a record. `make` names no file it will write, and `sh -c` names nothing at all. The
only honest account of a footprint is the syscalls that made it, which settles two things at once: the command has to
run where a tracer can see it, and every effect has to be attributable to something.

That rules out the mux's own process. brush performs redirections and builtins *inside* the calling process, so a
command executed in-process would do filesystem work `ptrace` cannot attribute to it. Commands run in a separate
`marsh-exec` process under `strace` instead, taking the command on `-c` and the hook-log path as an argument
(`--hook-log`) rather than through the environment, so a command cannot unset its own instrumentation; a missing dump
fails the run even when the command succeeded, because an un-instrumented run must never commit. The traced child is
its own process group, which lets a timeout kill the group and a front-end hand it the terminal. It also gets a third
standard stream — **fd 3 is instrumentation**, beside stdout and stderr — so a command can report about itself without
polluting its output.

It rules out forking git as well. A git process leaves a plausible trail of reads and writes under `.git/`, and none
of it says what git was *asked* to do — guesswork on the one operation whose intent matters most. So git is not a
process. `gitshell::build_shell` registers one two-token builtin per supported variant (`git add`, `git commit`, …)
plus a single-token `git` catch-all that refuses, and the two-token lookup resolves first, so PATH search is never
reached. Each builtin runs in-process over libgit2 (`gitexec`), inside the boundary named by `MARSH_SNAPSHOT_ROOT`,
which it may not search past for a repository. Refusing the rest of plumbing is what that costs. One grammar,
`gitcmd::parse`, serves the builtin that does the work and the translator that decides what was requested; a second
parser would be a second opinion.

What none of it does is confine. There is no chroot: a command that writes `/tmp/x` really writes it, and marsh only
watches. A filesystem that lied to the toolchains agents run would break the work marsh exists to host, so the
guarantee is the narrower, checkable one: nothing enters the seed without a granted capability, and concurrent
principals see a serializable seed. Two limits come with that. Writes outside the snapshot are observed and ignored,
and `getdents64` is not traced, so a command whose answer depends on a directory's *contents list* declares no
dependency on it.

## Two streams, one clock

Half the evidence is invisible to the tracer. A builtin runs inside the shell process, so `git add foo` reaches
`strace` as a few reads and writes under `.git/` and nothing else. Hence two streams. Syscalls — every call that can
touch a path, plus process lifecycle and `fchdir` — land in `meta/runs/<uid>/trace.log` as `TraceLine` and `Call`
values. Builtin invocations land in `builtins.json` beside it as `BuiltinRecord::Begin`/`End` pairs, collected in
memory by `RecordingHook` and dumped once at executor exit. Both are stamped in `CLOCK_REALTIME` microseconds from the
same clock, which is the only reason they can be merged.

## From syscalls to capabilities

`translate::translate` merges the two by timestamp, ranking a `Begin` before and an `End` after a syscall that shares
its microsecond, so a builtin's span is inclusive at both ends. That is the conservative tie-break: a borderline
syscall lands in git's read set instead of becoming a capability nobody requested. Three rules then read the merged
sequence.

* A syscall **is** a capability when the issuing thread is shell-attributed. The command line means nothing and the
  syscall is everything: `> p` opened for writing *is* `Edit p`.
* A git builtin invocation **is** a capability, derived from its recorded argv through `gitcmd`: `git add -- p` *is*
  `Stage p`. Every other builtin is transparent, because its syscalls already say what it did.
* A git builtin's own syscalls are **not** capabilities but its *read set*. `.git/index`, `HEAD`, refs and the
  worktree files it hashed are what its decision depended on.

Attribution is inherited across `clone` and `fork`. The result is a `Translation`: the capability `events`, the
`git_reads` behind them, and the traced root's `exit_code` — or `unsupported`, set when part of the command cannot be
expressed as capabilities at all, such as a raw `execve` of a git binary or a pathspec resolving outside the snapshot.
Then nothing commits, because a footprint the mux cannot name is one it cannot authorize.

## Deciding, and the two ways to lose

A failed command never reaches the decision: non-zero exit rolls it back wholesale, its partial writes left in the
discarded snapshot, because half of a failed command is not a transaction. Everything else arrives at
`ShellMux::conclude`, which takes the authority *write* lock and makes the write set, staleness, policy and log append
one serialization point. `AuthorityState` holds the committed `history`, the `generations` map — path → sequence
number of the transaction that last wrote it — and the highest `seq`.

Staleness is the concurrency half, optimistic by construction: nothing was held while the command ran, so the only
question left is whether the world moved under it. The write set is computed *inside* that lock, because its
reference is the live seed and a commit renaming into the seed mid-walk would surface as `ENOENT`. `stale_paths` then
takes the union of that **write set**, the **event resources** and the **git read set**; any path in it whose last
writer committed after this command's base sequence invalidates the command, which is told which path moved and who
won. Counting reads is what makes a `git diff` that wrote nothing lose a race on `.git/index`; counting a write set
the seed's own drift put there is what makes any commit since the snapshot invalidate the command wholesale.

Policy is the authorization half. `check_events` decides each event against the history with a fresh `GitPolicy` per
transaction, appending granted events as it goes so later events in the same command see earlier ones —
`printf x > p; git add -- p` has to see its own edit. Every refusal is collected, not only the first, and each
`CapDenial` carries the precondition it failed and the fixes that would unblock it, because a denial the caller cannot
act on is just a failure. If anything was refused the history is truncated back: a partially granted command leaves no
trace.

## Landing it: the seed

One copy stands between a granted command and the user's files, and it is synchronous, because the next command's
snapshot has to contain it — and because the seed *is* the user's directory, there is nothing after it.
`diff::diff_trees` compares the seed against the snapshot and emits `CommitOp::Write` and `CommitOp::Remove` in a
total order — removals deepest-first, then writes shallowest-first — so replaying the list is deterministic.

`commit::apply` frames that list in the one write-ahead log, `meta/wal.jsonl`. The order is the protocol: a
`Begin` carrying the sequence number, the job's uid, the principal, the command line and the granted events, then
one `Move` or `Delete` per operation, all fsynced as one batch *before* anything touches the seed; then each
record applied; then `End`. Every `Move` carries the SHA-1 of the content it moves, so a replay can tell an
applied record from an interrupted one after the snapshot it came from was swept. Records land through a
parent-local temporary and a rename (`wal::apply_write`), because a rename cannot cross the snapshot's subvolume
boundary and each destination must change atomically.

## A crash between two writes

One transaction ends in two writes — the seed, then the history — and a crash between them leaves a session
disagreeing with itself. `ShellMux::record_commit` performs them in that order, which is what makes the
disagreement repairable: a written seed whose history entry never landed is re-derived from the log's `Begin`.

`commit::recover` does both jobs in one pass over `meta/wal.jsonl`, at startup and before the snapshot sweep —
an unfinished transaction's content lives in `snap/<uid>`, which the sweep reclaims. It groups records into
transactions by `Begin`…`End`; one lacking `End` is re-applied and closed, and one whose sequence number the
history does not carry gets its entry appended from the same `Begin`. Both logs are append-only JSON Lines
written one batch per fsync, so the only corruption possible is a torn final line, truncated on read; a torn line
anywhere else is a hard error.

## What the caller is told

| `CmdOutcome` | What happened | The seed |
| --- | --- | --- |
| `Committed` | every capability granted, diff applied | carries the changes, at the sequence taken |
| `DeniedCaps` | the command ran; only the commit was refused, and every refusal is reported | unchanged |
| `StaleSnapshot` | someone committed since it snapshotted; rerun it | unchanged |
| `ExecFailed` | non-zero exit, rolled back wholesale | unchanged |
| `Unsupported` | not expressible as capabilities, so there is nothing to authorize | unchanged |

`DeniedCaps` is the one worth dwelling on: the command *ran*, and its work sits in the job's snapshot until the next
retake discards it. Denying at the commit, not at the command, is the trade — the principal sees what it wanted, the
seed sees nothing.

## Two front-ends

A terminal needs something `run_cmd` cannot give it. `ShellMux::run_cmd` runs the whole transaction and captures the
output, which suits a batch or library caller and not a job the user is watching; and only the caller's own `waitpid`
can tell a job that *stopped* from one that exited. So the transaction splits at the wait: `start_cmd` does snapshot
and execute and hands back a `StartedCmd` (taking the descriptor to install on fd 3, where `run_cmd` uses
`/dev/null`), the caller waits, and `conclude_cmd` does the rest. `marsh-shell`'s `Console` is that front-end — one
`Job` per sandbox, the current one named by the prompt, the terminal handed to the foreground job's process group with
`tcsetpgrp`, and every verdict rendered by `repl::report_lines` onto the fd-3 stream.
