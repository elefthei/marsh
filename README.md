<div align="center">
  <img src="https://github.com/user-attachments/assets/266b83a6-bacb-408c-afb7-2a2ddf37b272"/>
</div>

<br/>

<!-- Primary badges -->
<p align="center">
  <!-- crates.io version badge -->
  <a href="https://crates.io/crates/brush-shell"><img src="https://img.shields.io/crates/v/brush-shell?style=flat-square"/></a>
  <!-- msrv badge -->
  <img src="https://img.shields.io/crates/msrv/brush-shell"/>
  <!-- license badge -->
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
  <br/>
  <!-- crates.io download badge -->
  <a href="https://crates.io/crates/brush-shell"><img src="https://img.shields.io/crates/d/brush-shell?style=flat-square"/></a>
  <!-- compat tests badge -->
  <img src="https://img.shields.io/badge/compat_tests-1389-brightgreen?style=flat-square" alt="1389 compatibility tests"/>
  <!-- Packaging badges -->
  <a href="https://repology.org/project/brush/versions">
    <img src="https://repology.org/badge/tiny-repos/brush.svg" alt="Packaging status"/>
  </a>
  <!-- Social badges -->
  <a href="https://discord.gg/kPRgC9j3Tj">
    <img src="https://dcbadge.limes.pink/api/server/https://discord.gg/kPRgC9j3Tj?compact=true&style=flat" alt="Discord invite"/>
  </a>
</p>

<a href="https://repology.org/project/brush/versions">
</a>

</p>

<hr/>

`brush` (**B**o(u)rn(e) **RU**sty **SH**ell) is a modern [bash-](https://www.gnu.org/software/bash/) and [POSIX-](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html) compatible shell written in Rust. Run your existing scripts and `.bashrc` unchanged -- with syntax highlighting and auto-suggestions built in.

## At a glance

✅ Your existing `.bashrc` just works—aliases, functions, completions, all of it.<br/>
✨ Syntax highlighting and auto-suggestions built in.<br/>
🧩 Easily embeddable in your Rust apps using `brush_core::Shell`.<br/>

<p align="center">
  <img src="https://github.com/user-attachments/assets/0e64d1b9-7e4e-43be-8593-6c1b9607ac52" width="80%"/>
</p>

> ⚠️ **Not everything works yet:** `select` and some edge cases aren't supported. See the [Compatibility Reference](docs/reference/compatibility.md) for details.

## Setting up marsh

**marsh must be started inside a btrfs subvolume that is mounted with `user_subvol_rm_allowed` and
is not the root of its own mount.** Walking up from the current directory, the first subvolume it
finds is the **seed**: the directory marsh snapshots per command and writes granted changes straight
back into. There is no import and no copy back — the seed is your own directory.

marsh refuses to start otherwise, and says which of the three it was:

| If | marsh says |
| --- | --- |
| nothing at or above the current directory is a subvolume | `no btrfs subvolume contains <dir>; marsh snapshots the subvolume it runs in` |
| the seed is its mount's root, so there is nowhere beside it for `.marsh` | `<seed> is the root of its mount … run marsh inside a nested subvolume` |
| the filesystem lacks the mount option | `<dir> is on a btrfs mount without user_subvol_rm_allowed; marsh creates and deletes subvolumes as your user` |

The mount option is required because marsh creates and deletes subvolumes as your own user, not as
root: every job snapshot is one, and reclaiming it goes through the unprivileged ioctl.

Starting *at* the seed's own root is fine; so is any directory below it. What is not fine is a plain
directory that happens to sit on btrfs — `/home/you/src` under a btrfs `/home` has no subvolume of
its own, and marsh will find `/home`, which is that mount's root, and refuse.

Check all three from the directory you mean to work in. Inode 256 is what marks a subvolume root —
it is the same test marsh itself makes, and unlike `btrfs subvolume show` it needs no privileges:

```sh
cd ~/src/api
stat -f -c %T .                                     # expect: btrfs
stat -c %i .                                        # expect: 256, this directory is a subvolume
findmnt -no OPTIONS -T . | tr , '\n' | grep user_subvol_rm_allowed
findmnt -no TARGET -T .                             # must NOT be the subvolume itself
```

If the mount option is missing, add `user_subvol_rm_allowed` to that filesystem's options in
`/etc/fstab`, or set it for the current boot:

```sh
sudo mount -o remount,user_subvol_rm_allowed /home
```

If the directory is not a subvolume, make it one — unprivileged, and it needs a parent directory on
the same filesystem so marsh has somewhere to put `.marsh`:

```sh
btrfs subvolume create ~/src/api
```

marsh keeps its own state beside the seed, in `<seed>/../.marsh/<seed name>/`:

```
.marsh/<seed name>/
  snap/            job snapshots (<uid>) and the reader trees read-only commands share (read-<seq>)
  meta/            wal.jsonl, history.jsonl, purity.jsonl, console.history
    runs/<uid>/    trace.log, builtins.json — the retained instrumentation
```

### When your working area is not btrfs

Put a btrfs image on a loop device and work inside it:

```sh
truncate -s 20G ~/marsh.img
mkfs.btrfs -q ~/marsh.img
sudo mkdir -p /mnt/work
sudo mount -o loop,user_subvol_rm_allowed ~/marsh.img /mnt/work
sudo chown "$(id -u):$(id -g)" /mnt/work
btrfs subvolume create /mnt/work/api
```

To mount the image on every boot, add to `/etc/fstab`:

```
/home/you/marsh.img  /mnt/work  btrfs  loop,user_subvol_rm_allowed  0  0
```

### Working in a seed

```console
$ cd ~/src/api
$ marsh
marsh: seed /home/you/src/api
  state /home/you/src/.marsh/api
```

Inside the session, `sd NAME DIR` opens a job — a sandbox over the seed — rooted at `DIR`, read the
way `cd` reads it: relative to the current job's directory, or from the seed root when it starts
with `/`. `sda DIR` names it for you. Every line you submit is one transaction in the current job:
on a full grant it lands in the seed, which is your own directory, at once. A line that an earlier
traced run showed to be read-only — `ls`, `cat`, `grep` — skips the per-command snapshot and the
merge: it reads a snapshot shared by every read-only command at the same seed version, and only its
reads are recorded. If it turns out to write anyway, the snapshot contains it, marsh says so, and it
never runs that way again.

The prompt is the current job: `<name>@<directory>$ `, `main@.$ ` in a fresh session, so which
sandbox the next line runs in is never a guess. `fg NAME` moves it without running anything.

A trailing `&` runs a line beside what you are doing: it opens a job of its own, rooted where you
are, and leaves the current one where it was. `CMD &NAME` names that job, `CMD &"a long name"`
gives it a name with spaces, and `jobs` lists them all. `stop [-SIGNAL] NAME` signals a job's
process group; `close NAME` ends the job itself — its sandbox and its snapshot — while a job a bare
`&` numbered closes itself once its line has merged, because a number nobody chose is nothing to
come back to. `kill` is `kill(1)` and takes process ids.

### Quick start:

```console
$ cargo binstall brush-shell         # using cargo-binstall
$ brew install brush                 # using Homebrew
$ pacman -S brush                    # Arch Linux
$ cargo install --locked brush-shell # Build from sources
```

`brush` is ready for use as a daily driver. We test every change against `bash` to keep it that way.

More detailed installation instructions are available below.

## ✨ Features

### 🐚 `bash` Compatibility

| | Feature | Description |
|--|---------|-------------|
| ✅ | **50+ builtins** | `echo`, `declare`, `read`, `complete`, `trap`, `ulimit`, ... |
| ✅ | **Full expansions** | brace, parameter, arithmetic, command/process substitution, globs, `extglob`, `globstar` |
| ✅ | **Control flow** | `if`/`for`/`while`/`until`/`case`, `&&`/`\|\|`, subshells, pipelines, etc. |
| ✅ | **Redirection** | here docs, here strings, fd duplication, process substitution redirects |
| ✅ | **Arrays & variables** | indexed/associative arrays, dynamic variables, standard well-known variables, etc. |
| ✅ | **Programmable completion** | Works with [bash-completion](https://github.com/scop/bash-completion) out of the box |
| ✅ | **Job control** | background jobs, suspend/resume, `fg`/`bg`/`jobs` |
| 🔷 | **Traps & options** | `DEBUG`/`ERR`/`EXIT` traps work; signal traps and options in progress |

### ⌨️ User Experience

| | Feature | Description |
|--|---------|-------------|
| ✅ | **Syntax highlighting** | Real-time as you type ([reedline](https://github.com/nushell/reedline)) |
| ✅ | **Auto-suggestions** | History-based hints as you type ([reedline](https://github.com/nushell/reedline)) |
| ✅ | **Rich prompts** | `PS1`/`PROMPT_COMMAND`, right prompts, [starship](https://starship.rs) compatible |
| ✅ | **TOML config** | `~/.config/brush/config.toml` for persistent settings |
| 🧪 | **Extras** | `fzf`/`atuin` support, zsh-style `precmd`/`preexec` hooks (experimental), VS Code terminal integration |

## Installation

_When you run `brush`, it should look exactly as `bash` does on your system: it processes your `.bashrc` and
other standard configuration. If you'd like to distinguish the look of `brush` from the other shells
on your system, you may author a `~/.brushrc` file._

<details>
<summary>🍺 <b>Installing using Homebrew</b> (macOS/Linux)</summary>

Homebrew users can install using [the `brush` formula](https://formulae.brew.sh/formula/brush):

```bash
brew install brush
```

</details>

<details>
<summary><img src="https://archlinux.org/favicon.ico" width="16" height="16" style="vertical-align: middle;"> <b>Installing on Arch Linux</b></summary>

Arch Linux users can install `brush` from the official [extra repository](https://archlinux.org/packages/extra/x86_64/brush/):

```bash
pacman -S brush
```

</details>

<details>
<summary><img src="https://packages.msys2.org/static/images/logo.svg" alt="icon" width="20" height="20" style="vertical-align: middle;"> <b>Installing on MSYS2</b></summary>

MSYS2 users can install `brush` from the [repository](https://packages.msys2.org/base/mingw-w64-brush):

```bash
pacman -S mingw-w64-ucrt-x86_64-brush # or mingw-w64-clang-x86_64-brush or mingw-w64-clang-aarch64-brush
```

</details>

<details>
<summary>🚀 <b>Installing prebuilt binaries via `cargo binstall`</b></summary>

You may use [cargo binstall](https://github.com/cargo-bins/cargo-binstall) to install pre-built `brush` binaries. Once you've installed `cargo-binstall` you can run:

```bash
cargo binstall brush-shell
```

</details>

<details>
<summary>🚀 <b>Installing prebuilt binaries from GitHub</b></summary>

We publish prebuilt binaries of `brush` for Linux (x86_64, aarch64) and macOS (aarch64) to GitHub for official [releases](https://github.com/reubeno/brush/releases). You can manually download and extract the `brush` binary from one of the archives published there, or otherwise use the GitHub CLI to download it, e.g.:

```bash
gh release download --repo reubeno/brush --pattern "brush-x86_64-unknown-linux-gnu.*"
```

After downloading the archive for your platform, you may verify its authenticity using the [GitHub CLI](https://cli.github.com/), e.g.:

```bash
gh attestation verify brush-x86_64-unknown-linux-gnu.tar.gz --repo reubeno/brush
```

</details>

<details>
<summary>🐧 <b>Installing using Nix</b></summary>

If you are a Nix user, you can use the registered version:

```bash
nix run 'github:NixOS/nixpkgs/nixpkgs-unstable#brush' -- --version
```

</details>

<details>
<summary>📦 <b>Installing on Fedora (community package)</b></summary>

`brush` isn't packaged in Fedora's official repositories, but a community-maintained `brush-shell` package is available from [Terra](https://terrapkg.com/), a separately maintained, third-party repository for Fedora and its derivatives.

Once you've enabled the Terra repository:

```bash
dnf install brush-shell
```

</details>

<details>
<summary> 🔨 <b>Building from sources</b></summary>

To build from sources, first install a working (and recent) `rust` toolchain; we recommend installing it via [`rustup`](https://rustup.rs/). Then run:

```bash
cargo install --locked brush-shell
```

</details>

## Community & Contributing

This project started out of curiosity and a desire to learn—we're keeping that attitude. If something doesn't work the way you'd expect, [let us know](https://github.com/reubeno/brush/issues)!

* [Discord server](https://discord.gg/kPRgC9j3Tj) — chat with the community
* [Building from source](docs/how-to/build.md) — development workflow
* [Contribution guidelines](CONTRIBUTING.md) — how to submit changes
* [Technical docs](docs/README.md) — architecture and reference

## Related Projects

Other POSIX-ish shells implemented in non-C/C++ languages:

* [`nushell`](https://www.nushell.sh/) — modern Rust shell (provides `reedline`)
* [`fish`](https://fishshell.com) — user-friendly shell ([Rust port in 4.0](https://fishshell.com/blog/rustport/))
* [`Oils`](https://github.com/oils-for-unix/oils) — bash-compatible with new Oil language
* [`mvdan/sh`](https://github.com/mvdan/sh) — Go implementation
* [`rusty_bash`](https://github.com/shellgei/rusty_bash) — another Rust bash-like shell

<details>
<summary><b>🙏 Credits</b></summary>

This project relies on many excellent OSS crates:

* [`reedline`](https://github.com/nushell/reedline) — readline-like input and interactive features
* [`clap`](https://github.com/clap-rs/clap) — command-line parsing
* [`fancy-regex`](https://github.com/fancy-regex/fancy-regex) — regex support
* [`tokio`](https://github.com/tokio-rs/tokio) — async runtime
* [`nix`](https://github.com/nix-rust/nix) — Unix/POSIX APIs
* [`criterion.rs`](https://github.com/bheisler/criterion.rs) — benchmarking
* [`bash-completion`](https://github.com/scop/bash-completion) — completion test suite

</details>

---

Licensed under the [MIT license](LICENSE).
