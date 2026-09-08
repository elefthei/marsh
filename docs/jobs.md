# Jobs

marsh exists so several principals — agents, and the person watching them — can work in one directory tree at
once. That poses two questions an ordinary shell never answers: what did this command actually change, and may it
keep the change. A job is where a principal answers them: a sandbox over the seed in which every submitted line
is one atomic transaction — snapshot, execute, translate, authorize, commit. What follows is why each phase has
the shape it has. [Sessions](session.md) has the layout it runs on.

## A job is a sandbox

Identity comes first, because every later phase has to know who is asking. A `Sandbox` is an `id`, a `dir` and a
`uid`, and the id *is* the capability principal (`Sandbox::principal`) — which is what makes the job table a
picture of contention over the seed, `%foo` and `%bar` competing for paths exactly as two agents would. That id
is a `ShellId`, and it is the one identity type there is: the name a front-end prints, the handle `fg` resolves,
the principal the policy decides about, and what `JobView`, `Spawned` and every job-shaped `MuxError` carry. It
is a typed handle over a `String` rather than an enforced invariant, because job-name *grammar* is a front-end's
rule — the CLI refuses `main` and free-form names in `repl::valid_name`, a library caller need not — while the
rules the mux can enforce are the ones it keeps: a live duplicate is refused, and an unknown name is an error.
`dir` is the seed-relative directory its commands start in, `""` for the seed root; `uid` names its snapshot,
drawn from the seed's path, the id, a counter and the clock, so two sandboxes opened in the same nanosecond still
differ. `ShellMux::spawn` and `ShellMux::stop` bracket its life, which outlasts any one command: a job is a place
to work. Opening one takes no snapshot — it only checks that `dir` resolves inside the seed and exists there, so
`sd api nope` fails at the prompt; the first command that needs a tree is what copies the seed. The console joins
the directory typed at `sd` onto the current job's before the mux sees it (`repl::job_dir`), so what a user types
is a path in the job they typed it in.

The table of open jobs is the mux's, beside its per-principal shells, because a job's name and a principal's name
are one identity and two registries of it would drift. `spawn` is the only way in — `sd NAME DIR`, `bg DIR`,
`CMD &` and `CMD &NAME` are all one call — and it draws the `1`, `2`, … series, refuses a name a live job already
holds, and reserves what it opened for a command by marking it `starting`. It does not run that command on the
caller's future: an initial command is launched by a task the mux itself owns, because a launch retakes the
snapshot, builds the principal's shell and spawns a tracer, which on a large seed takes seconds — a front-end
that awaited all of it would hold the prompt for the whole launch, which is what `CMD &NAME` used to do. `spawn`
returns once the job's terminal and shell exist; a launch that fails after that reports itself as
`%NAME did not start: …` and the job is reclaimed. No lock is held across a launch or a wait, so `jobs` answers
while a command is starting and while another is running. A name that is not one word is printed `%"like this"`
(`ShellId::reference`), because a row of the job table is also what a reader types back at `fg` and `stop`
— and the console's prompt names the current job in that same word.

`ShellMux::stop(id, force)` is the way out, and deliberately not the mirror of `spawn`. It is asynchronous and
returns on *acceptance*, not on the end of whatever is running. A plain stop records that the job closes and
sends nothing; `stop -f` kills the running command's process group and takes the row out of public view at once,
while the private row keeps its tracer, its conclusion and its name until teardown. In neither case is a tree
deleted there: a conclusion may still be diffing that tree against the seed, so the sandbox is reclaimed by
whichever of the stop and the conclusion finds the job idle last — both check under the same pair of locks, in
the same order, so neither can decide the other will do it. A forcibly stopped transaction never translates,
authorizes or merges — it reports 137 — and its snapshot is only reclaimed once
`MarshExecutor::terminate_owner` has proven every process carrying that job's `MARSH_JOB_UID` marker is gone. A
job whose name came from the series for a bare `CMD &` closes itself (`JobCloseMode::Automatic`) when that
command's transaction concludes, since a number nobody chose is no handle to come back to; `sd`, `bg` and
`&NAME` jobs persist, and `fg` clears that mark (`ShellMux::keep`) on any job a reader takes an interest in. A
reader's own stop is not a mark `keep` may clear, and `ShellMux::switch` refuses a job that is closing.

## One terminal per job, one size for all of them

A job owns a pseudoterminal and an instrumentation pipe from the moment `spawn` creates it, and its shell is
built with that terminal on fds 0, 1 and 2. It is what lets a full-screen program — `less`, `vim`, an agent's own
TUI — see a real tty whatever the front-end is doing with the process's own terminal, and it is what makes a job
readable as *bytes*: `ShellMux::read_output` drains the master side and `ShellMux::write_input` feeds it, both
preserving escape sequences, non-UTF-8 output and a final line with no newline. Nothing is ever handed the real
terminal.

The geometry, though, is the mux's and not the job's. One `(rows, cols)` lives in the job table, every
pseudoterminal is opened at it, and `ShellMux::resize` changes it for all of them at once — the inactive jobs
included. Per-job sizes are the obvious alternative and they are wrong: a job whose terminal disagrees with the
window redraws into the wrong shape the moment it is selected, so a reader would find a correct prompt over a
mangled screen and nothing to blame for it. A resize is therefore a session-wide fact. Every existing terminal is
attempted and the first I/O error is reported after the pass rather than during it, so one dead terminal does not
silently skip the rest; a job opened afterwards inherits the new pair; and a repeated resize reapplies the same
pair, because a command may have changed the terminal underneath. A zero dimension is
`MuxError::InvalidTerminalSize` and changes nothing at all — not the stored size, not one terminal — since a
geometry no job could be given must not be half-applied. `ShellMux::new` refuses it first of all, before it
materializes storage or recovers anything.

## The stream beside the output

fd 3 is instrumentation, beside stdout and stderr, so a command can report about itself without polluting what it
printed. It belongs to the job rather than to the process: the mux creates one pipe per job, every command that
job runs writes into that pipe, and `ShellMux::read_instrumentation` drains it. One descriptor shared by the
whole session could not answer the question a reader actually has — several jobs report at once, and a line
arriving on a shared pipe does not say which of them wrote it. The writer end blocks, because a command writing
to its third standard stream cannot be told to try again. `ShellMux::run_cmd`, which has no job and no reader,
gives it `/dev/null` instead.

## The snapshot, and the version it copied

Saying what a command changed needs something to compare it against; saying whether it may keep the change needs
the version of the seed it started from. One snapshot carries both. `work` is `snap/<uid>`, where the command
runs and the translator's root: a writable btrfs snapshot of the seed, retaken at the start of every
transactional command so each starts from the seed as it stands, and left in place afterwards so the job keeps a
tree to look at. A command the mux runs as a bypass ([below](#commands-that-only-read)) gets no tree of its own:
it shares the reader snapshot of the version it started at. The reference the diff is taken against is not a
second tree — it is the seed itself, read at the moment the command concludes.

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
fails the run even when the command succeeded, because an un-instrumented run must never commit. A captured run is
its own process group, so a timeout can kill the whole group; a job's run instead becomes a session of its own
with `setsid` and takes its job's pseudoterminal as its controlling terminal, which is what makes its own line
discipline — and therefore its Ctrl-C — the job's rather than the console's.

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
total order — removals deepest-first, then writes shallowest-first — so replaying the list is deterministic. It
runs only when the trace saw a write inside the snapshot (`Translation::wrote_in_root`, `.git/` included): a
command that opened nothing for writing there cannot have a write set, and two full tree walks over a seed of any
size is the whole cost of its transaction.

`commit::apply` frames that list in the one write-ahead log, `meta/wal.jsonl`. The order is the protocol: a
`Begin` carrying the sequence number, the job's uid, the principal, the command line, the granted events and the
exact operation count, then one `Move` or `Delete` per operation, all fsynced as one batch *before* anything
touches the seed; then each record applied; then `End`. Every `Move` carries the SHA-1 of the content it moves,
so a replay can tell an applied record from an interrupted one after the snapshot it came from was swept. Records
land through a parent-local temporary and a rename (`wal::apply_write`), because a rename cannot cross the
snapshot's subvolume boundary and each destination must change atomically.

## A crash between two writes

One transaction ends in two writes — the seed, then the history — and a crash between them leaves a session
disagreeing with itself. `ShellMux::record_commit` performs them in that order, which is what makes the
disagreement repairable: a written seed whose history entry never landed is re-derived from the log's `Begin`.

`commit::recover` runs at startup before snapshot reclamation. A counted intent with every operation present is
replayed and closed; a prefix shorter than its declared count is abandoned without touching the seed or history.
A count mismatch on a finished intent is corruption. Completed legacy records remain readable, while an
unfinished legacy record has no proof that its intent was complete and therefore fails startup without deleting
its sources. A final byte suffix without `\n` is an incomplete append and is truncated even when it happens to be
valid JSON; malformed newline-terminated records remain hard errors.

## Commands that only read

A transaction costs a copy-on-write snapshot *per command* and a walk of two trees. A read-only
command has nothing for either to do: it produces no write set, so there is nothing to diff and
nothing to merge, and it does not need a tree of its own because it will not dirty one. Willingness
is not proof, though, and exactly two things count as one: the command's own syntax, or a trace of
it having run.

`shellmux::purity` holds both, and one mux has one `PurityChecker` in one mode.
`PurityCheckerBuilder::new()` is static, `.static_checks()` says so and `.learned()` selects the
other, the last setter wins, and `build` is infallible and opens no file. `ShellMux::plan_for` asks
the checker once — `PurityChecker::check`, given the job's own shell and a `CommandKey` — and turns
`Verdict::Pure` into `Plan::Bypass` and `Verdict::Sandboxed` into `Plan::Transaction`. One question,
one answer, one reason for it: there is no list of sources to iterate and no first answer to win.

**Static** mode proves purity from the command's own syntax and learns nothing. It parses the whole
program with the *shell's* `parser_options()` — never the parser's defaults, which enable extended
globbing whatever the shell says, so a job that has extglob off would otherwise be judged against a
grammar it does not have — and walks the result. Separators must be sequential, because a
backgrounded command outlives the transaction that would have contained it; a timed or negated
pipeline is refused, and every stage of a pipeline must pass. The only command accepted is a
`Command::Simple` with an empty prefix — a prefix is where an assignment and a redirection live, and
either is an effect — whose name is one raw literal in `:`, `true`, `false`, `echo` or `pwd`, those
being the bodies that only return a status, write standard output or report the working directory.
Every suffix item must be a plain literal word. Unredirected brace groups and subshells pass when
their lists recursively pass; function definitions, loops, conditionals, arithmetic and test
constructs and coprocesses do not, because what they run is decided while they run.

Two details of that walk carry the weight. Unquoted text is refused when
`pattern::pattern_has_glob_metacharacters` says it holds a metacharacter *or* when it holds a raw
`{`, `}`, `~`, `(` or `)`. The second check is not a restatement of the first: the detector answers
`false` on its own translation errors, so an extglob it failed to translate would otherwise pass for
literal text and carry a proof out with it. And the proof is taken against the job's real shell,
because a function or an enabled alias with a builtin's name is a genuine shadowing definition — an
ancestor process's exported `BASH_FUNC_echo%%` is one — so `echo x` means different things in
different jobs. Nothing is executed and nothing is expanded to establish any of it.

**Learned** mode approves a command only once a traced run has shown it read-only, and a bypassed run
is traced too, which is how a verdict that has gone wrong is caught instead of trusted. What it is
keyed on is the `CommandKey`: the command line and the job's seed-relative directory, because
`./build.sh` names a different program in a different directory. What it is kept in is
`meta/purity.jsonl` — last record wins, a record appended only when the verdict changed — restored by
`ShellMux::new` after recovery has repaired that log, which is safe precisely because the executor
already holds the session's lease. A static checker never reads or writes it.

`Read` is the only action that qualifies a run (`mux::verdict_of`), and `Translation::wrote_in_root`
is checked beside the event list because a write under `.git/` produces no event at all. Everything
else either changes the tree or is refusable, and neither survives having no diff behind it. Only a
learned checker records that answer; a static one ignores it, its reason being the syntax, which no
run can change.

### What a bypass still owes

**It reads a snapshot, not the live seed.** `commit::apply` moves files into the seed one at a time
under the write lock, so a command reading the seed directly could straddle a commit and see half of
it — the very tearing a transaction is immune to because its snapshot was taken under the *read*
lock. So a bypass gets a snapshot too, just not its own: `snap/read-<seq>`, one per committed seed
version, created under the read lock by the first read-only command to want it and shared by every
one that starts while that version is current (`ShellMux::acquire_reader`). Naming it by version is
what makes that safe under concurrency — a commit landing mid-read gives the *next* command a new
tree instead of deleting the one a running command is in. A tree is reclaimed when the seed has moved on and its
last reader has left; any remainder belongs to startup reclamation.

**It declares its reads.** They go to the authority under the write lock exactly as a merge's do
(`ShellMux::conclude_bypass`), and that is not bookkeeping. A `Read` can never be refused — the git
policy has no rule for one — but a read is what *takes the read claim* on a resource, and rules
19-23 forbid another principal's `edit`, `delete`, `clean`, `checkout` or `stash` while someone else
holds it, with "must read it before editing it" as the fix. A principal whose reads stopped being
recorded could never take a claim back, and would be denied for a read it had actually performed.
No sequence number is taken: `seq` names a version of the seed, `generations` and `base_seq` read it
as one, and a read changes no version. What is appended to `meta/history.jsonl` is the events, in
order, with no paths — and nothing at all is appended to the write-ahead log.

**An escape costs the tree, not the seed.** A command vouched for as read-only that writes anyway
writes into the reader tree, which is a snapshot: nothing reaches the seed, and nothing is merged or
authorized. `Escaped` reports it, the tree is discarded so no later command inherits the dirt, and the verdict is
withdrawn so the next run is a transaction — the diagnostic names the mode it was withdrawn from, `static` or
`learned`, because those are two different mistakes and the analysis is not rerun to tell them apart. The one
thing this cannot quarantine is another bypass already running in the same tree, which keeps it alive; that
command is read-only, merges nothing, and the next commit supersedes the version.

## What the caller is told

| `CmdOutcome` | What happened | The seed |
| --- | --- | --- |
| `Committed` | every capability granted, diff applied | carries the changes, at the sequence taken |
| `DeniedCaps` | the command ran; only the commit was refused, and every refusal is reported | unchanged |
| `StaleSnapshot` | someone committed since it snapshotted; rerun it | unchanged |
| `ExecFailed` | non-zero exit, rolled back wholesale | unchanged |
| `Unsupported` | not expressible as capabilities, so there is nothing to authorize | unchanged |
| `Bypassed` | vouched for as read-only; ran in the shared reader tree, and its reads were granted and recorded | unchanged |
| `Escaped` | vouched for as read-only, but it did more; contained by the reader tree | unchanged |

`DeniedCaps` is the one worth dwelling on: the command *ran*, and its work sits in the job's snapshot until the next
retake discards it. Denying at the commit, not at the command, is the trade — the principal sees what it wanted, the
seed sees nothing.

## Two front-ends

A terminal needs something `run_cmd` cannot give it. `ShellMux::run_cmd` runs the whole transaction and captures
the output, which suits a batch or library caller and not a job a user is watching. A job takes the other path —
`spawn`, `start_in`, `read_output`, `write_input`, `wait_for_job` — and everything between the launch and the
verdict stays with the mux, deliberately. A child has exactly one reaper, so the mux owns the wait: one
`SIGCHLD` watcher task, doing targeted non-blocking waits over its own jobs' pids, reaping and updating a row
under the same short table lock a forced stop takes — which is what stops a stop from signalling a pid that has
already been reaped and whose number the kernel may have handed out again. And only one conclusion may merge, so
the mux owns the conclusion too. Nothing half-finished leaves it: there is no open transaction in the public
API, and a front-end observes through `wait_for_job`, which yields a `Reaped` whose shared `outcome` it renders.
`marsh-shell` renders it through `repl::report_lines`, exactly as it did when it concluded transactions itself.

Concluding is also why it must not run on the caller's future. It walks the seed and the snapshot, which on a
large seed takes seconds, and a caller awaiting that would stop answering for the length of a merge it does not
need. So a reaped command is *submitted*: one conclusion task takes them in order, `jobs` reports a job whose
merge is in flight as `merging` instead of waiting for it, and the next command in that job waits for its
predecessor's conclusion before starting. `shutdown` closes that queue rather than draining it — it admits
nothing new, terminates outstanding commands, joins the tasks the mux owns, and reclaims nothing persistent,
since startup is the only place that can tell an unfinished transaction from a live one.

A launch runs on a task of its own for the same reason, and one task per launch rather than a queue, because a
launch holds only the authority's *read* lock and two jobs are meant to snapshot at once. `switch` waits for a
pending launch, since a job whose launch is in flight has no command to show yet, while the console's `exit`
counts a starting job as live for its one-warning UX and never waits for that launch after exit is accepted.
Every tracer is spawned by one stable launcher thread with `--kill-on-exit` and a parent-death signal, so process
death — not an exit sweep — terminates traced descendants.

What is left for the console is bytes and words. It keeps the real terminal, puts it in raw mode while a command
is in the foreground and pumps between it and that job's pseudoterminal; the terminal itself is never handed to a
child, so Ctrl-C arrives as a byte on the job's own line discipline rather than as a signal to this process. It
reads the selected job back out of the mux (`current_job`) instead of keeping a second registry of one, and
prints a job's instrumentation as gray lines through the same printer its own builtins write to.
