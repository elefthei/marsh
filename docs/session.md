# Sessions

A session is one seed and the state directory beside it. The seed is the btrfs subvolume marsh commits into; it
is the user's own directory, not a copy of it. One type carries all of it — `Session`, in
`shellmux/src/session.rs`.

## Discovery

`Session::discover(start)` canonicalizes `start`, then walks it and its ancestors, nearest first, and takes the
first btrfs subvolume it finds (`find_seed`, with `snapshot::is_subvolume` as its predicate — a `stat`/`statfs`
check that needs no privilege). No subvolume above the current directory is a hard error: marsh cannot snapshot
what is not a subvolume.

A seed that is the root of its own mount is refused too (`snapshot::is_mount_root`). It is the check that stops a
plain directory under a btrfs `/home` from resolving to `$SEED = /home` with its state at `/.marsh`: marsh needs a
directory *beside* the seed, so the seed must have a real parent inside the same filesystem.

## Layout

`root` is `<seed>/../.marsh/<seed basename>`. Namespacing by the seed's own name is what keeps two sibling
subvolumes under one parent from sharing one history.

```
<seed>/                   the user's own subvolume: what every transaction commits into
<seed>/../.marsh/<name>/
  snap/                   job snapshots (<uid>, taken by the first command that needs one) and the
                          shared reader trees read-only commands run in (read-<seq>)
  meta/                   wal.jsonl, history.jsonl, purity.jsonl, console.history
    runs/<uid>/           trace.log, builtins.json — the retained instrumentation
```

The accessors are `snap()`, `meta()` and `work(uid)`; nothing outside the module joins those names by hand. Of the
files under `meta/`: `wal.jsonl` is the write-ahead log every transaction is framed in, `history.jsonl` the
capability history the policy decides from, `purity.jsonl` what earlier traced runs showed about which commands
change nothing, and `console.history` the front-end's line history.

`default_dir(cwd)` is the seed-relative form of `cwd`, `""` at the seed root. It is what roots the default job
where marsh was started rather than at the top of the seed.

## Materializing

`Session::materialize` creates `root`, `snap/` and `meta/runs/` — plain directories, no subvolume: the seed
already exists and marsh creates only snapshots of it. Between the create and the rest it asserts that the state
directory is on btrfs and mounted `user_subvol_rm_allowed` (`snapshot::assert_btrfs`,
`snapshot::assert_user_subvol_rm_allowed`), which is what guarantees snapshots can be taken beside the seed and
reclaimed unprivileged. Both checks need the path to exist, hence the order.

It is idempotent: an existing state directory is adopted as it stands. Something that is not a directory in that
place is `MuxError::StateNotDirectory`, checked before the create so the message names the real problem.

## The path vocabulary

Every path marsh reports, logs or commits is seed-relative and `/`-joined: `src/a.txt`, `DeepTest/.git/index`.
That single convention is what lets a capability `Resource`, a staleness generation key and a write-ahead log
destination all be the same string.

Two consequences are worth stating. A file written at the snapshot root *is* a resource, because that root is the
user's own directory — there is nowhere for a write inside the seed to be dropped. And a sandbox's directory is
normalized lexically (`mux::seed_relative`), so a `..` that climbs past the seed is refused before any path is
built from it.

A seed may hold zero, one or many git repositories, at any depth. marsh never initializes one: a git command
finds the nearest `.git` between its own directory and the snapshot root, and is refused when there is none.
Everything under any `.git/` is git's business and never a capability resource, which is what keeps two nested
repositories from colliding in one history.

## Opening a session

`ShellMux::open` runs a fixed sequence, and the order is the point: `materialize`, then `commit::recover`, then
the snapshot sweep, then the temporary sweep, then `history::load`.

Recovery precedes the sweep because an unfinished transaction's content lives in `snap/<uid>`, which the sweep
reclaims. The sweep then deletes every leftover tree there: a snapshot is durable within a session and belongs to
nobody after it — sandboxes live in the front-end, so a crash leaves trees nobody will ever refresh.
[Jobs](jobs.md) states the transaction contract in full.
