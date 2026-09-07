# `^` opens a job and hands it the terminal

## Context

marsh's console recognizes `CMD &`, `CMD &NAME` and `CMD &"a long name"` with a hand-rolled scanner
over the raw line (`marsh-shell/src/repl.rs::background`, line 118). The ask: a second operator,
`^`, `^NAME`, `^"a long name"`, that opens a job exactly as `&` does but hands the new job the
terminal for as long as its command runs — and the recognition of both operators pushed down into
`brush-parser`, so the shell's own quoting rules decide what is an operator. `grep '^foo'` is then a
search, unambiguously, while `grep ^foo` is a job named `foo` — an accepted ambiguity, the same one
`echo a &b` already has.

End state: `brush-parser` tokenizes `^` as a control operator when asked to, exposes
`brush_parser::job::parse_job_suffix` which splits a submitted line at the `&`/`^` that ends it, the
console's `background` scanner is deleted in favour of it, and `Console::spawn_attached` gives the
new job the terminal. A consequence worth naming: `echo hi 2>&1` stops being read as a job named `1`
running `echo hi 2>`, which is what today's scanner does (traced below in step 2).

## Approach

Four steps, in order. The tree builds and `cargo test --workspace` passes after each. Step 2 depends
on step 1; step 4 depends on steps 2 and 3; step 3 depends on nothing.

`brush-parser` and `marsh-shell` are both library crates, so a `pub` item that nothing calls yet is
not dead code and steps 1–3 compile clean on their own.

### 1. `^` is a control operator when the caller asks for it

`^` is an ordinary word character in POSIX shells and in bash — `echo ^` prints `^` — so making it
an operator is gated. One flag, off by default, set by exactly one caller (step 2).

**`brush-parser/src/tokenizer.rs`**, `TokenizerOptions` (line 226) gains a field, after `sh_mode`:

```rust
    /// MARSH: whether `^` is a control operator — the marsh console's "open a job and hand it the
    /// terminal" sibling of `&`. Off everywhere else, because `^` is an ordinary word character in
    /// POSIX shells and in bash, where `echo ^` prints a caret.
    pub enable_attach_operator: bool,
```

`impl Default for TokenizerOptions` (line 235) gains `enable_attach_operator: false,`.

`can_start_operator` (line 1260) reads the options, so it stops being an associated `const fn`:

```rust
    fn can_start_operator(&self, c: char) -> bool {
        matches!(c, '&' | '(' | ')' | ';' | '\n' | '|' | '<' | '>')
            || (self.options.enable_attach_operator && c == '^')
    }
```

Its one callsite, line 1125, becomes `self.can_start_operator(c)` (it reads `Self::can_start_operator(c)`
today). The immutable borrow ends before the `self.consume_char()?` on the next line, so this
borrow-checks as written.

`is_operator` (line 1264) gains, as its first statement:

```rust
        // MARSH: the attach operator, when the caller asked for it.
        if self.options.enable_attach_operator && s == "^" {
            return true;
        }
```

Nothing else is needed for `^foo` to split: `is_operator("^f")` is false, so the operator token is
delimited at `^` and `foo` follows as an ordinary word — the same machinery that already splits
`a>>b` and `2>&1`.

**`brush-parser/src/parser/mod.rs`**, `ParserOptions::tokenizer_options()` (line 55) gains
`enable_attach_operator: false,`. That is the only other `TokenizerOptions` struct literal in the
workspace (`grep -rn "TokenizerOptions {" --include=*.rs .` returns exactly `tokenizer.rs:226`,
`tokenizer.rs:235` and `parser/mod.rs:56`), and `ParserOptions` itself is untouched, so
`brush-core/src/shell/parsing.rs:37` — which builds a `ParserOptions` literal field by field — does
not change. There is no schema to regenerate: `schemas/config.schema.json` is the shell's TOML
config, unrelated to parser options.

**Test**, in `tokenizer.rs`'s `mod tests` (line 1366), in the local style — `-> Result<()>` with
`?`, `pretty_assertions::assert_eq` is already imported:

```rust
    /// MARSH: `^` is a word character in every shell but the marsh console, which asks for it by
    /// name; a caret that silently became an operator would break `echo ^` everywhere else.
    #[test]
    fn caret_is_an_operator_only_when_the_attach_operator_is_enabled() -> Result<()> {
        let plain = tokenize_str("echo ^x")?;
        assert_eq!(
            plain.iter().map(Token::to_str).collect::<Vec<_>>(),
            ["echo", "^x"]
        );

        let marsh = tokenize_str_with_options(
            "echo ^x",
            &TokenizerOptions {
                enable_attach_operator: true,
                ..TokenizerOptions::default()
            },
        )?;
        assert_eq!(
            marsh.iter().map(Token::to_str).collect::<Vec<_>>(),
            ["echo", "^", "x"]
        );
        Ok(())
    }
```

### 2. `brush_parser::job` splits a line at the operator that ends it

New file **`brush-parser/src/job.rs`**, and `pub mod job;` in `brush-parser/src/lib.rs` between
`pub mod ast;` and `pub mod pattern;` (line 7–8).

Tokenizer-level, not grammar-level, and that is the load-bearing choice: the console hands the
command on *verbatim* to the shell that will actually run it, so what it needs is the text before
the operator, not an AST — and an AST cannot give it back without lossy re-quoting. It also means a
line the parser would reject (an unclosed `if`, a stray `)`) still gets its job suffix read, and a
line the *tokenizer* cannot read is left whole for the job's own shell to diagnose. Nothing is added
to `ast::SeparatorOperator`: "hand the job the terminal" has no meaning in a shell without a job
table over sandboxes, and a variant `brush-core/src/interp.rs:280` had to invent a semantics for
would be a lie.

```rust
//! MARSH: the job operator a console line may end with.
//!
//! A marsh console line can end in an operator that runs it in a job of its own: `&` leaves the
//! console holding the terminal, `^` hands it to the job. Either may carry the job's name, with
//! nothing between operator and name — `&api`, `^"a long name"`.
//!
//! Tokenizing is what answers the only hard question here — whether a `^` is an operator or part of
//! a word — with the shell's own quoting rules, which is why `grep '^foo'` searches for a line
//! beginning `foo` and `grep ^foo` opens a job named `foo`.

use crate::tokenizer::{Token, TokenizerOptions, tokenize_str_with_options};

/// What the operator that ends a line asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobDisposition {
    /// `&`: the job runs beside the console, which keeps the terminal.
    Detached,
    /// `^`: the job is handed the terminal for as long as its command runs.
    Attached,
}

/// A line split at the job operator that ends it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobSuffix {
    /// The command, verbatim, with the operator and the blanks before it removed.
    pub command: String,
    /// Which operator ended the line.
    pub disposition: JobDisposition,
    /// The word that followed the operator with nothing between them, exactly as it was written —
    /// quotes and all. `None` when the operator ended the line.
    pub name: Option<String>,
}

/// Splits `line` at the job operator that ends it, or returns `None` when it ends in neither.
///
/// `None` is every line that is not a job: an ordinary command, one ending in `&&`, one ending in a
/// redirection like `2>&1` — whose `&` belongs to the redirection operator, not to a job — and one
/// the tokenizer cannot read at all, which is left whole for the shell that runs it to diagnose.
///
/// The name comes back as written, because what makes a name acceptable is the caller's business: a
/// job name is a capability principal in marsh, and this crate has no opinion about principals.
/// [`crate::unquote_str`] removes its quoting.
#[allow(
    clippy::string_slice,
    reason = "`end` is a byte offset produced by `char_indices`, so it is a char boundary in `line`"
)]
pub fn parse_job_suffix(line: &str) -> Option<JobSuffix> {
    let tokens = tokenize_str_with_options(
        line,
        &TokenizerOptions {
            enable_attach_operator: true,
            ..TokenizerOptions::default()
        },
    )
    .ok()?;

    let (operator, operator_span, name) = match tokens.as_slice() {
        // `CMD &NAME` / `CMD ^NAME`. The name has to touch the operator: a space between them is
        // the next command instead, which is what keeps `echo a & b` a command line.
        [.., Token::Operator(operator, operator_span), Token::Word(name, name_span)]
            if operator_span.end.index == name_span.start.index =>
        {
            (operator.as_str(), operator_span, Some(name.clone()))
        }
        [.., Token::Operator(operator, operator_span)] => (operator.as_str(), operator_span, None),
        _ => return None,
    };

    let disposition = match operator {
        "&" => JobDisposition::Detached,
        "^" => JobDisposition::Attached,
        _ => return None,
    };

    // A source position counts characters, and a slice of `line` counts bytes.
    let end = line
        .char_indices()
        .nth(operator_span.start.index)
        .map_or(line.len(), |(byte, _)| byte);
    let command = line[..end].trim_end();
    if command.is_empty() {
        // A line that is nothing but the operator names no command to run, so it is not a job.
        return None;
    }

    Some(JobSuffix {
        command: command.to_string(),
        disposition,
        name,
    })
}
```

`command` and `name` are owned rather than borrowed from `line`: `tokenize_str_with_options` hands
back a `Vec<Token>` that dies with this call, so a borrowed name would not outlive it, and the
caller turns both into `String`s anyway.

Guarded slice patterns fall through to the following arm when the guard fails, so a two-token tail
that is not contiguous, or is not `operator`-then-`word`, correctly reaches the bare-operator arm and
then `None`.

**Tests**, in a `#[cfg(test)] mod tests` at the end of the file (`tests_outside_test_module` is
denied workspace-wide):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn suffix(line: &str) -> Option<(String, JobDisposition, Option<String>)> {
        parse_job_suffix(line).map(|s| (s.command, s.disposition, s.name))
    }

    /// The operator that ends a line opens a job; every other `&` in the language keeps its own
    /// meaning, and `2>&1` is the one that used to be read as a job named `1`.
    #[test]
    fn a_trailing_operator_opens_a_job_and_no_other_ampersand_does() {
        assert_eq!(
            suffix("sleep 5 &"),
            Some(("sleep 5".to_string(), JobDisposition::Detached, None))
        );
        assert_eq!(
            suffix("sleep 5&"),
            Some(("sleep 5".to_string(), JobDisposition::Detached, None))
        );
        assert_eq!(
            suffix("sleep 5 ^"),
            Some(("sleep 5".to_string(), JobDisposition::Attached, None))
        );
        assert_eq!(suffix("a && b"), None);
        assert_eq!(suffix("a &&"), None);
        assert_eq!(suffix("&"), None, "no command to run is no job");
        assert_eq!(suffix("^foo"), None);
        assert_eq!(
            suffix("echo hi 2>&1"),
            None,
            "the & belongs to the redirection operator, not to a job"
        );
        assert_eq!(suffix("echo hi >&2"), None);
    }

    /// A name touches its operator, and comes back exactly as it was written.
    #[test]
    fn a_name_touches_the_operator_and_is_returned_verbatim() {
        assert_eq!(
            suffix("echo foo &api"),
            Some((
                "echo foo".to_string(),
                JobDisposition::Detached,
                Some("api".to_string())
            ))
        );
        assert_eq!(
            suffix("echo foo ^api"),
            Some((
                "echo foo".to_string(),
                JobDisposition::Attached,
                Some("api".to_string())
            ))
        );
        assert_eq!(
            suffix("echo foo ^\"a long name\""),
            Some((
                "echo foo".to_string(),
                JobDisposition::Attached,
                Some("\"a long name\"".to_string())
            )),
            "quoting is the caller's to remove, because the name policy is the caller's too"
        );
        assert_eq!(suffix("echo a & b"), None, "a space is the next command");
        assert_eq!(suffix("echo foo &api extra"), None);
    }

    /// The whole point of tokenizing rather than scanning: quoting decides.
    #[test]
    fn quoting_decides_whether_a_caret_is_an_operator() {
        assert_eq!(suffix("grep '^foo'"), None);
        assert_eq!(suffix("grep \"^foo\""), None);
        assert_eq!(
            suffix("grep ^foo"),
            Some((
                "grep".to_string(),
                JobDisposition::Attached,
                Some("foo".to_string())
            )),
            "unquoted, it is an operator — the same ambiguity `echo a &b` already has"
        );
        assert_eq!(suffix("echo \"a &\""), None);
    }
}
```

### 3. The console opens a job that takes the terminal

**`marsh-shell/src/console.rs`.** `Console::spawn` (line 703) has its job-opening half extracted so
two callers share it. Replace `spawn`'s body and add the two neighbours; `attach` (line 1025) and
`dir_label` already exist and are reused unchanged.

```rust
    /// Opens a job over `dir` — a path in the current job, or seed-rooted when it starts with `/` —
    /// and either makes it current or starts `cmd` in it.
    ///
    /// `sd NAME DIR` is `spawn(dir, Some(name), None)`, `sda DIR` is `spawn(dir, None, None)`,
    /// `CMD &` is `spawn(".", None, Some(cmd))` and `CMD &NAME` is `spawn(".", Some(name),
    /// Some(cmd))`. `CMD ^` is [`Self::spawn_attached`], which differs in exactly one thing.
    ///
    /// A job opened without a command becomes current, because that is what `sd` is for. One opened
    /// with a command does not: `&` runs a line *beside* what is being worked on, so the prompt,
    /// completion and the next typed line all stay where they were.
    pub fn spawn(
        &mut self,
        dir: &str,
        name: Option<String>,
        cmd: Option<String>,
        err: &mut dyn Write,
    ) -> u8 {
        let Some(opened) = self.open(dir, name, cmd.as_deref(), err) else {
            return 1;
        };
        match cmd {
            None => self.current = opened,
            Some(cmd) => gray(&format!("{} $ {cmd}", shellmux::job_ref(&opened))),
        }
        0
    }

    /// Opens a job for `cmd` and hands it the terminal for as long as that command runs.
    ///
    /// `CMD ^` and `CMD ^NAME`. `^` differs from `&` in exactly one thing — who owns the terminal
    /// while the command runs — so the job is no more current afterwards than a `&` job is, and an
    /// unnamed one still closes itself once its transaction concludes. The exit code is the
    /// command's, because from the console's side this line was synchronous.
    pub fn spawn_attached(&self, name: Option<String>, cmd: &str, err: &mut dyn Write) -> u8 {
        let Some(opened) = self.open(".", name, Some(cmd), err) else {
            return 1;
        };
        gray(&format!("{} $ {cmd}", shellmux::job_ref(&opened)));
        self.attach(&opened, false)
    }

    /// Opens a job over `dir`, reports where it landed, and returns the name it answers to.
    fn open(
        &self,
        dir: &str,
        name: Option<String>,
        cmd: Option<&str>,
        err: &mut dyn Write,
    ) -> Option<String> {
        let dir = repl::job_dir(
            &self
                .mux
                .job(&self.current)
                .map_or_else(String::new, |job| job.sandbox.dir),
            dir,
        );
        let spawned = match tokio::task::block_in_place(|| {
            self.mux.spawn(&dir, name, cmd, Some(INSTRUMENTATION_FD))
        }) {
            Ok(spawned) => spawned,
            Err(error) => {
                let _ = writeln!(err, "marsh: {error}");
                return None;
            }
        };
        gray(&format!(
            "{} -> {}",
            shellmux::job_ref(&spawned.name),
            dir_label(&spawned.sandbox)
        ));
        Some(spawned.name)
    }
```

No merge barrier is needed before `attach`: `Console::foreground` waits on `merges.wait_for` because
it reuses an existing job's snapshot, while this opens a fresh sandbox that owes nothing.
`ShellMux::spawn` already marks an unnamed job with a command `transient`, so a `^` job with no name
self-closes after its merge exactly as a `&` one does.

The terminal handoff itself needs nothing new: `Console::attach` does `tcsetpgrp` to the job's
process group and waits, `shellmux::strace`'s `child_setup` already resets `SIGINT`, `SIGQUIT`,
`SIGTSTP`, `SIGTTIN` and `SIGTTOU` to `SIG_DFL` in every job it spawns, and both `&` and `^` jobs
inherit the console's stdio (`TraceIo::Terminal`). The difference between them is precisely which
process group the terminal belongs to while the command runs.

### 4. The line grammar reads both operators through the parser

**`marsh-shell/Cargo.toml`** gains, beside `brush-core`:

```toml
brush-parser = { version = "^0.4.0", path = "../brush-parser" }
```

**`marsh-shell/src/repl.rs`.** Delete `background` (line 118, with its `#[allow(clippy::string_slice…)]`)
and `named_background` (line 157) outright — no scanner survives beside the parser. Add at the top,
beside `use shellmux::{Action, CmdOutcome, MuxError};`:

```rust
use brush_parser::job::{JobSuffix, parse_job_suffix};

pub use brush_parser::job::JobDisposition;
```

The `Input` variant `Background` (line 45) becomes:

```rust
    /// Start the line in a job of its own — a trailing `&` or `^` — with the operator removed.
    Job {
        /// The command line, with the operator and any name it carried removed.
        cmd: String,
        /// The job's name; `None` takes the next number, as `sda` does.
        name: Option<String>,
        /// Whether the job is handed the terminal while its command runs (`^`) or runs beside the
        /// console (`&`).
        disposition: JobDisposition,
    },
```

`parse`'s fallthrough arm (line 102 today, `_ => background(line).unwrap_or_else(…)`) becomes:

```rust
        // A trailing `&` or `^`, with or without a name, opens a job; anything else is a command
        // line, handed on verbatim.
        _ => parse_job_suffix(line).map_or_else(
            || Input::Foreground(line.to_string()),
            |suffix| job(line, suffix),
        ),
```

and three functions replace the deleted pair:

```rust
/// The `Input` a job operator asks for, or the whole line as a command when what followed the
/// operator turns out not to be a job name.
///
/// A bare word that is not a name means the operator was never a job operator at all: `grep ^[a-z]`
/// is a search, and reading it as a job would swallow the pattern. Quoting is how a name the bare
/// form will not take — one with spaces, or one beginning with `-` — is reached.
fn job(line: &str, suffix: JobSuffix) -> Input {
    let name = match suffix.name.as_deref() {
        None => None,
        Some(word) => match job_name(word) {
            None => return Input::Foreground(line.to_string()),
            Some(name) => Some(name),
        },
    };
    let Some(name) = name else {
        return Input::Job {
            cmd: suffix.command,
            name: None,
            disposition: suffix.disposition,
        };
    };
    named_job(suffix.command, &name, suffix.disposition)
}

/// The job name a word carries, or `None` when the word is not a name at all.
fn job_name(word: &str) -> Option<String> {
    if shellmux::bare_job_name(word) {
        return Some(word.to_string());
    }
    // Anything else has to be quoted, which is also how `jobs` writes such a name back.
    word.starts_with(['"', '\''])
        .then(|| brush_parser::unquote_str(word))
}

/// A named job, or the diagnostic for a name a job may not answer to.
///
/// `%` is how a job is marked inside a line of prose and comes off the front of a typed reference,
/// and `"` is the quote that wraps one, so neither may appear in a name; a control character would
/// corrupt the table the name is printed in; and [`FOREGROUND`] is the one name already taken.
fn named_job(cmd: String, name: &str, disposition: JobDisposition) -> Input {
    let operator = match disposition {
        JobDisposition::Detached => "&",
        JobDisposition::Attached => "^",
    };
    if name == FOREGROUND {
        return Input::Invalid(format!(
            "{operator}: invalid job name {name:?} ({FOREGROUND:?} is the foreground job)"
        ));
    }
    if name.is_empty() || name.chars().any(|c| c == '%' || c == '"' || c.is_control()) {
        return Input::Invalid(format!(
            "{operator}: invalid job name {name:?} (not empty, and no % or \")"
        ));
    }
    Input::Job {
        cmd,
        name: Some(name.to_string()),
        disposition,
    }
}
```

`shellmux::bare_job_name` stays the one definition of what a name needs no quoting to be — it is the
other half of `shellmux::job_ref`'s invariant, and a second copy in the parser would let a `jobs` row
print a name that cannot be typed back.

The module doc (line 10) lists the console forms: `and the trailing `&` or `^``.

**`marsh-shell/src/entry.rs`.** `use crate::repl::{self, Input};` (line 29) becomes
`use crate::repl::{self, Input, JobDisposition};`, and the `Input::Background` arm (line 406)
becomes:

```rust
                Input::Job {
                    cmd,
                    name,
                    disposition,
                } => with_console(&self.console, |console| {
                    executed(match disposition {
                        JobDisposition::Detached => {
                            console.spawn(".", name, Some(cmd), &mut std::io::stderr())
                        }
                        JobDisposition::Attached => {
                            console.spawn_attached(name, &cmd, &mut std::io::stderr())
                        }
                    })
                }),
```

`LONG_ABOUT` (line 85) gains two rows after `CMD &NAME`, first column padded to 25 characters like
its neighbours:

```
  CMD ^                  the same, but the job holds the terminal until CMD ends
  CMD ^NAME              the same, as job NAME — ^"NAME" for a name with spaces
```

and the banner (line 234) becomes:

```rust
    console::gray(
        "builtins: sd NAME DIR · sda DIR · CMD &[NAME] · CMD ^[NAME] · jobs · fg [JOB] · \
         bg [JOB] · stop [-SIG] JOB · close JOB · kill [-SIG] PID · exit",
    );
```

**Tests**, `marsh-shell/src/repl.rs`'s `mod tests`. `a_trailing_ampersand_is_a_job_but_a_double_one_is_an_operator`
(line 554) and `an_ampersand_can_name_the_job_it_opens` (line 580) construct `Input::Background`
in eight places; each becomes `Input::Job { …, disposition: JobDisposition::Detached }`. Two
assertions in the second test are about the old scanner's rules rather than about job naming and are
deleted rather than re-pinned:

* `parse("echo \"a\" &")` with the note *"the quoted form is only looked for when the line ends with
  a quote"* — the tokenizer has no such rule. Keep the case, drop the note.
* `parse("grep -e \"&\" -f \"x\"")` with the note *"a candidate name holding a quote of its own is no
  name"* — keep the case, renote it *"a quoted `&` is not an operator"*, which is now why it holds.

Add to `a_trailing_ampersand_is_a_job_but_a_double_one_is_an_operator`:

```rust
        assert_eq!(
            parse("sleep 5 ^"),
            Input::Job {
                cmd: "sleep 5".to_string(),
                name: None,
                disposition: JobDisposition::Attached,
            }
        );
        assert_eq!(
            parse("echo hi 2>&1"),
            Input::Foreground("echo hi 2>&1".to_string()),
            "the & of a redirection is not a job operator"
        );
```

and add a test of its own:

```rust
    /// `^` is `&` plus the terminal, and quoting is what tells an operator from a pattern.
    #[test]
    fn a_caret_opens_a_job_that_takes_the_terminal() {
        assert_eq!(
            parse("make test ^build"),
            Input::Job {
                cmd: "make test".to_string(),
                name: Some("build".to_string()),
                disposition: JobDisposition::Attached,
            }
        );
        assert_eq!(
            parse("make test ^\"a long name\""),
            Input::Job {
                cmd: "make test".to_string(),
                name: Some("a long name".to_string()),
                disposition: JobDisposition::Attached,
            }
        );
        assert_eq!(
            parse("grep '^foo' notes"),
            Input::Foreground("grep '^foo' notes".to_string()),
            "quoted, a caret is a pattern"
        );
        assert_eq!(
            parse("grep ^[a-z]"),
            Input::Foreground("grep ^[a-z]".to_string()),
            "a bare word that is not a name means the caret was no operator either"
        );
        assert_eq!(
            parse("echo x ^\"main\""),
            Input::Invalid(
                "^: invalid job name \"main\" (\"main\" is the foreground job)".to_string()
            )
        );
    }
```

## Critical files & anchors

| Path | Anchor | Why |
| --- | --- | --- |
| `brush-parser/src/tokenizer.rs` | `TokenizerOptions` (226), `Default` (235), operator branch (1125), `can_start_operator` (1260), `is_operator` (1264), `mod tests` (1366) | Every edit of step 1, and the branch at 1125 is the only `can_start_operator` callsite. |
| `brush-parser/src/parser/peg.rs` | `locations_are_contiguous` (765), `io_number` (706) | The precedent step 2 copies: `io_number` already decides adjacency from token spans, which is how `&NAME` is told from `& NAME`. |
| `marsh-shell/src/repl.rs` | `Input` (23), `parse` (69), `background` (118), `named_background` (157), `job_reference` (182), tests (554, 580) | Everything deleted and everything added in step 4; `job_reference` stays as it is — it reads `fg`/`bg`/`stop`/`close` arguments, not job operators. |
| `marsh-shell/src/console.rs` | `spawn` (703), `foreground` (743), `attach` (1025) | `foreground` is the model for step 3's tail (start, then attach) and the one place that must *not* be copied: its `merges.wait_for` is for reusing a job, not opening one. |
| `shellmux/src/strace.rs` | `child_setup` (216) | Confirms the terminal semantics `^` relies on: dispositions are reset in the job, so a detached job stops on `SIGTTIN` and an attached one does not. |

## Verification

Run from `/home/eioannidis/git/marsh`. `target/` is on a btrfs mount with `user_subvol_rm_allowed`.

```sh
cargo test -p brush-parser --lib          # step 1 and 2 tests
cargo test -p marsh-shell --lib           # step 4 tests
cargo test --workspace                    # 25 `test result: ok` lines, as today
cargo build --workspace
cargo fmt --check --all
cargo clippy --workspace --all-features --all-targets
```

### One session: the two operators side by side

`/tmp/marsh_pty.py` is the pty driver (recreate it if absent):

```sh
S="$PWD/target/check"; rm -rf "$S"; mkdir -p "$S"
btrfs subvolume create "$S/seed"
cat > /tmp/marsh_pty.py <<'PY'
"""Drive marsh under a pty. Args: SEED BIN [key|wait:SECONDS ...]."""
import os, pty, select, signal, sys, time
SEED, BIN, SCRIPT = sys.argv[1], sys.argv[2], sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(SEED)
    os.environ["TERM"] = "xterm-256color"
    os.execv(BIN, [BIN])
out, step, started = bytearray(), 0, time.time()
idle_since, hold_until, deadline = started, 0.0, started + 180
alive = True
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.2)
    if ready:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            alive = False; break
        if not chunk:
            alive = False; break
        out += chunk
        idle_since = time.time()
        if b"\x1b[6n" in chunk:          # reedline asks where the cursor is
            os.write(fd, b"\x1b[1;1R")   # a real terminal answers; script(1) does not
        continue
    if step >= len(SCRIPT) or time.time() < hold_until or time.time() - idle_since < 0.6:
        continue
    item = SCRIPT[step]; step += 1
    out += f"\n[+{time.time() - started:.1f}s SENT {item!r}]\n".encode()
    if item.startswith("wait:"):
        hold_until = time.time() + float(item[5:])
    else:
        os.write(fd, item.encode())
    idle_since = time.time()
if alive:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(bytes(out))
code = os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else f"signal {os.WTERMSIG(status)}"
print(f"\n--- sent {step}/{len(SCRIPT)}; hung={alive}; exit={code}")
PY
python3 /tmp/marsh_pty.py "$S/seed" "$PWD/target/debug/marsh" \
  $'echo hi 2>&1\n' wait:8 \
  $'jobs\n' wait:2 \
  $'head -n 1 &\n' wait:5 \
  $'jobs\n' wait:2 \
  $'head -n 1 ^\n' wait:2 $'hello\n' wait:8 \
  $'jobs\n' wait:2 \
  $'grep -c . /dev/null ^keep\n' wait:8 \
  $'jobs\n' wait:2 \
  $'exit\n' wait:3 $'exit\n' > /tmp/caret.log 2>&1
```

Each check, with what it proves:

```sh
grep -a '^hi$' /tmp/caret.log                    # 2>&1 ran as a command
grep -ac '%1' /tmp/caret.log                     # and opened no job named 1
grep -a 'stopped — fg' /tmp/caret.log            # `head -n 1 &` read the tty in the background
grep -a 'got\|^hello$' /tmp/caret.log            # `head -n 1 ^` read the line we typed
grep -a '%keep \$ grep -c . /dev/null' /tmp/caret.log
grep -a '%keep' /tmp/caret.log
tail -1 /tmp/caret.log                           # ends hung=False
```

Expected exactly:

* `echo hi 2>&1` prints `hi` under `%main` and the first `jobs` table has one row, `%main* . <uid>
  idle` — today's scanner instead opens a job named `1` running `echo hi 2>`, which is the
  regression step 2 removes;
* `head -n 1 &` opens a numbered job that reports `%N stopped — fg %N to resume` when it reads the
  terminal it does not own, and the second `jobs` table shows that job `stopped` — the detached half;
* `head -n 1 ^` takes the terminal instead: the `hello` typed after it is echoed by `head`, a verdict
  line for that job follows, and the third `jobs` table has no row for it, because a job the series
  named closes itself once its transaction concludes — the attached half;
* `grep -c . /dev/null ^keep` prints `%keep -> .`, `%keep $ grep -c . /dev/null`, `0`, then its
  verdict, and the last `jobs` table still carries `%keep … idle`: a named job persists whichever
  operator opened it;
* the log ends `hung=False`, and `"$S/.marsh/seed/snap"` is empty afterwards.

Clean up:

```sh
btrfs subvolume delete "$S"/.marsh/seed/snap/* 2>/dev/null
btrfs subvolume delete "$S/seed"
rm -rf "$S" /tmp/marsh_pty.py /tmp/caret.log
```

## Assumptions & contingencies

* **`grep ^foo` is a job named `foo`.** The bare form stays ambiguous, exactly as `echo a &b` is
  today, and quoting (`grep '^foo'`) is the way out. If that ambiguity turns out to be intolerable in
  use, the narrowing is one line in `repl::job_name`: drop the `shellmux::bare_job_name` branch, so
  only a quoted word can name a job and `^` alone stays the unnamed form. Nothing else in the plan
  changes.
* **`^` is gated in the tokenizer rather than always on.** A shell that has not asked for the flag
  keeps `echo ^` printing a caret, which is what every bash-compatibility test in the workspace
  expects. If a future caller wants marsh syntax through the full parser, the follow-on is a
  `separator_op()` rule in `peg.rs` under the same flag — deliberately not built now, because
  `brush-core`'s interpreter would have to invent a meaning for "hand the job the terminal" in a
  shell that has no job table over sandboxes.
* **`head -n 1 &` stops on `SIGTTIN`.** `shellmux/src/strace.rs:216-236` resets that disposition in
  every job it spawns, so a background read stops the job. If the verification session shows the
  read succeeding instead (no `stopped — fg` line), the detached half of the proof becomes
  `sh -c 'sleep 5' &` — prompt returns at once, `jobs` shows `running` — against `sh -c 'sleep 5' ^`,
  whose next `[+Ns SENT …]` stamp in the log is five seconds later because the console was blocked in
  `attach`. Do not "fix" it by making `spawn_attached` wait differently; the timing difference is the
  same proof.
