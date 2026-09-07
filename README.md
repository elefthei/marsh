<div align="center">
  <img src="docs/extras/marsh-logo.png" alt="marsh — multi-agent Rust shell" width="320"/>
</div>

# marsh

`marsh` is a multi-agent Rust shell for concurrent work in one project. It runs shell commands in
btrfs snapshots of your project's **seed** subvolume, tracks filesystem activity, and merges fully
granted transactions back into that same working tree.

## How it works

- **Named jobs:** give independent tasks their own job names and directories. Start a new background
  job with `CMD &NAME`, inspect jobs with `jobs`, and attach to one with `fg NAME`.
- **Capability-gated transactions:** a command must exit successfully, receive a full capability
  grant, and pass the staleness check before marsh merges it into the seed. Failed, denied, or
  stale transactions are not merged.
- **Recorded execution:** commands run through `marsh-exec` under `strace`. Per-run traces and
  builtin records stay in marsh's state directory.
- **Read-only reuse:** a command learned as read-only can reuse a snapshot at the current seed
  version instead of taking its own snapshot and merging. Reads are still recorded. If it writes
  inside that snapshot, nothing is merged and future runs return to the transactional path.

Conflicts are conservative: concurrent writes can invalidate one another even when they touch
different files. A job reported as stale must be rerun against the new seed.

> Filesystem transactions are not a security sandbox. Writes outside the snapshot are not
> contained or rolled back.

## Build from source

marsh runs on Linux; CI builds and tests x86_64 and aarch64. Install Rust **1.94.0 or newer** with
Cargo and a native build toolchain.

On Ubuntu/Debian, install the build libraries, tracer, and btrfs setup tools:

```sh
sudo apt-get update
sudo apt-get install -y libbtrfsutil-dev libclang-dev btrfs-progs strace
strace --kill-on-exit --version
```

`strace` must support `--kill-on-exit` (6.6 or newer). `btrfs-progs` supplies the workspace setup
commands shown below.

From this repository's root, using Cargo's default target directory:

```sh
cargo build --release --locked -p marsh-shell -p shellmux
export PATH="$PWD/target/release:$PATH"
marsh --help
```

This builds **both** runtime binaries: `marsh` from `marsh-shell`, and `marsh-exec` from `shellmux`.
Keep them in the same directory: marsh finds its executor beside itself, not by searching PATH.
A bare `cargo build` selects only `marsh-shell` and does not build the complete runtime.

The PATH change applies to the current shell; make it before changing to your seed directory.
`marsh --help` works without a seed, but starting a session requires the setup below.

## Setting up marsh

Start marsh at or below a btrfs subvolume that is **not the root of its own mount**. Walking up from
the current directory, the first subvolume is the **seed**: marsh snapshots it for transactional
commands and applies granted changes directly to it. There is no import and no separate copy-back
directory — the seed is your own working tree.

Keep the seed and its writable sibling state directory, `<seed>/../.marsh/<seed name>/`, on the
same btrfs filesystem. The mount containing the state directory must include
`user_subvol_rm_allowed`. marsh checks the filesystem and mount option on that state directory:
it creates and deletes snapshots as your user, not as root.

Common filesystem setup errors report these diagnostic prefixes:

| Condition | Diagnostic prefix |
| --- | --- |
| No subvolume contains the launch directory | `no btrfs subvolume contains <dir>` |
| The seed is its mount's root | `<seed> is the root of its mount` |
| The sibling state directory is not on btrfs | `<state> is not on a btrfs filesystem` |
| The state directory's mount lacks the required option | ``<state> is on a btrfs mount without `user_subvol_rm_allowed` `` |

Starting at the seed's root is fine, as is starting in an ordinary directory below it. Merely
being on btrfs is not enough: if the nearest containing subvolume is a mount root, marsh refuses
to start.

Run these checks from the intended **seed root**, not from an ordinary directory inside it.
Inode 256 identifies a subvolume root:

```sh
cd ~/src/api
stat -f -c %T .                  # expect: btrfs
stat -c %i .                     # expect: 256 at the seed root
stat -f -c %T ..                 # expect: btrfs for sibling state
findmnt -no OPTIONS -T ..        # must include user_subvol_rm_allowed
findmnt -no TARGET -T .          # must NOT be the seed itself
```

If `../.marsh/api` already exists, also check that actual state directory with
`stat -f -c %T ../.marsh/api` and `findmnt -no OPTIONS -T ../.marsh/api`.

If the mount option is missing, add `user_subvol_rm_allowed` to that filesystem's options in
`/etc/fstab`, or remount it for the current boot. For example, when the seed's parent is on `/home`:

```sh
sudo mount -o remount,user_subvol_rm_allowed /home
```

Use the actual mountpoint containing the seed's parent, not necessarily `/home`.

To create a new seed, use a destination that does not already exist under a writable parent on
the same btrfs filesystem:

```sh
btrfs subvolume create ~/src/api
```

This creates an empty subvolume; it does not convert an existing ordinary directory or move your
files. An existing directory below a suitable seed already works without creating another one.

marsh keeps its state beside the seed:

```text
.marsh/<seed name>/
  snap/            job snapshots (<uid>) and shared reader snapshots (read-<seq>)
  meta/            wal.jsonl, history.jsonl, purity.jsonl, console.history, session.lock
    runs/<uid>/    trace.log, builtins.json — retained instrumentation
```

Only one marsh session can own a seed at a time. Use named jobs within that session for concurrent
tasks; another session reports that the seed already has an active marsh session.

### When your working area is not btrfs

Put a btrfs image on a loop device and work inside it. Use a new image file and an unused mountpoint
for this example:

```sh
truncate -s 20G ~/marsh.img
mkfs.btrfs -q ~/marsh.img
sudo mkdir -p /mnt/work
sudo mount -o loop,user_subvol_rm_allowed ~/marsh.img /mnt/work
sudo chown "$(id -u):$(id -g)" /mnt/work
btrfs subvolume create /mnt/work/api
```

To mount the image on every boot, add to `/etc/fstab`, using your actual image path:

```text
/home/you/marsh.img  /mnt/work  btrfs  loop,user_subvol_rm_allowed  0  0
```

## Working with jobs

Start marsh from your seed, or a directory inside it. At the seed root, startup identifies the
seed and state directories:

```console
$ cd ~/src/api
$ marsh
marsh: seed /home/you/src/api
  state /home/you/src/.marsh/api
```

The prompt is `<name>@<seed-relative-directory>$ `: `main@.$ ` when starting at the seed root, or
`main@src$ ` when starting in its `src` directory. Give each agent's task a named job in the same
session; marsh runs the commands you submit, rather than provisioning AI agents.

| Command | Effect |
| --- | --- |
| `sd NAME DIR` | Create a job and make it current. `DIR` is relative to the current job, or seed-relative when it starts with `/`. |
| `sda DIR` | Create and select a job with an automatically assigned name. |
| `CMD &` | Run a command in a new, automatically named background job rooted where you are. |
| `CMD &NAME` | Run a command in a new named background job without changing the current job. |
| `jobs` | List jobs, their directories, and their current states. |
| `fg NAME` | Make a job current; attach to its running command or resume its stopped command. An idle job runs nothing. |
| `bg NAME` | Resume a stopped job in the background. |
| `stop [-SIGNAL] NAME` | Signal a job's process group; the default signal is `SIGTERM`. |
| `close NAME` | End an idle job and reclaim its snapshot. Stop a running job first; the `main` job cannot be closed. |
| `kill [-SIGNAL] PID` | Signal a process id, not a job name. |

`CMD &"a long name"` gives a background job a name with spaces. A name passed to `&NAME` must be
unused: this creates a job rather than submitting work into an existing one. A bare `&` creates a
transient job that closes after its transaction concludes, unless you keep it by attaching with `fg`.

In a fresh session at the root of a disposable seed, try the following. This example creates
`agent-a.txt`, `agent-b.txt`, and `agent-c.txt`:

```sh
sd agent-a .
printf 'from agent a\n' > agent-a.txt
fg main

printf 'from agent b\n' > agent-b.txt &agent-b
printf 'from agent c\n' > agent-c.txt &agent-c
jobs
fg agent-a
```

The first write runs in `agent-a`; the two background lines each open a different job. Their
completion order is not fixed, and racing writes can be reported stale even though they use
different files. Rerun any stale command against the updated seed before expecting its changes
to appear. `fg agent-a` returns to the first job without starting another command.

## Documentation

- [Sessions and workspace layout](docs/session.md)
- [Jobs, transactions, and capability checks](docs/jobs.md)

Issues and pull requests are welcome in this repository. For bug reports, include the command,
observed result, and relevant marsh diagnostics.

---

Licensed under the [MIT license](LICENSE).
