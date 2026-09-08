//! Which commands may skip the sandbox, and what the mux learns about them.
//!
//! A transaction costs a copy-on-write snapshot of the seed and a walk of two trees. A command that
//! writes nothing and requests no capability has nothing for either to do, so the mux is willing to
//! run it in a shared reader tree instead. Willingness needs a reason, and there are exactly two
//! kinds:
//!
//! * **Static** — the command's own syntax proves it. A conservative walk of the parsed program
//!   accepts a handful of builtin bodies that only return a status, write standard output or read
//!   the working directory, with literal arguments and nothing else. Nothing is executed, nothing
//!   is expanded, and anything unrecognized is refused.
//! * **Learned** — a previous traced run showed it. The only evidence marsh accepts for this is a
//!   trace, and a bypassed run is traced too, which is how a verdict that has gone wrong is
//!   withdrawn instead of trusted.
//!
//! One mux has one checker in one mode. A static checker never reads or writes the learned cache,
//! and a learned checker never proves anything from syntax: a command is approved because it was
//! observed, or it takes the transaction.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use brush_core::parser::ast;
use brush_core::parser::word::{WordPiece, WordPieceWithSource};
use marsh_exec::PersistenceLayer;
use serde::{Deserialize, Serialize};

use crate::error::MuxError;
use crate::wal::JsonLog;

/// Log file name under the session's `meta/` directory.
const PURITY_FILE: &str = "purity.jsonl";

/// The builtin command names a static proof will accept.
///
/// Every one of these has a body that only returns a status, writes its arguments to standard
/// output, or reports the working directory. `printf`, `eval`, `source`, `git` and every `PATH`
/// program are deliberately absent: their effects are their arguments' to decide.
const PROVABLE_BUILTINS: [&str; 5] = [":", "true", "false", "echo", "pwd"];

/// Characters a static proof refuses in unquoted text even when the glob detector does not.
///
/// Brace expansion, tilde expansion and every parenthesized construct produce a word the parser
/// alone cannot bound. The detector answers `false` on its own translation errors, so an extglob it
/// failed to translate would otherwise become a literal proof.
const UNSAFE_RAW: [char; 5] = ['{', '}', '~', '(', ')'];

/// What the checker knows about one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Requested no capability and wrote nothing: it may run in a shared reader tree, with no
    /// snapshot and no merge.
    Pure,
    /// Writes, requests capabilities, or could not be shown to do neither: it needs the full
    /// transaction.
    Sandboxed,
}

/// The command a verdict is about.
///
/// The job directory is part of the key because a relative command (`./build.sh`) names a different
/// program in a different directory, so a verdict earned in one job directory says nothing about
/// another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandKey<'a> {
    /// The submitted command line, verbatim.
    pub cmd: &'a str,
    /// The sandbox's seed-relative directory; `""` is the seed root.
    pub dir: &'a str,
}

/// Builds the one purity checker a mux owns.
///
/// Static by default. The two mode setters are exclusive and the last one wins, so a builder is
/// always in exactly one mode and there is no combination to reason about.
#[derive(Debug, Default)]
pub struct PurityCheckerBuilder {
    /// Whether the built checker learns from traced runs instead of proving from syntax.
    learned: bool,
}

impl PurityCheckerBuilder {
    /// A builder in the default static mode.
    #[must_use]
    pub const fn new() -> Self {
        Self { learned: false }
    }

    /// Proves purity from the command's own syntax, learning nothing. The default, stated.
    #[must_use]
    pub const fn static_checks(mut self) -> Self {
        self.learned = false;
        self
    }

    /// Approves a command only once a traced run has shown it read-only.
    #[must_use]
    pub const fn learned(mut self) -> Self {
        self.learned = true;
        self
    }

    /// Builds the checker.
    ///
    /// Infallible and free of filesystem I/O: a static checker is immediately usable, and a learned
    /// one starts with an empty in-memory cache that [`ShellMux::new`](crate::ShellMux::new)
    /// replaces from persistent state under the executor's lease.
    #[must_use]
    pub fn build(self) -> PurityChecker {
        PurityChecker {
            mode: if self.learned {
                Mode::Learned(LearnedPurity::empty())
            } else {
                Mode::Static
            },
        }
    }
}

/// Decides whether a command may skip the sandbox.
pub struct PurityChecker {
    /// The one mode this checker is in.
    mode: Mode,
}

/// The two kinds of reason a command may be approved for.
enum Mode {
    /// The command's own syntax proves it.
    Static,
    /// A previous traced run showed it.
    Learned(LearnedPurity),
}

impl PurityChecker {
    /// The verdict for `key`, proved against `shell`.
    ///
    /// `shell` is the context the static proof needs and cannot invent: a function or an enabled
    /// alias with a familiar builtin's name is a real shadowing definition — an ancestor process's
    /// exported `BASH_FUNC_echo%%` is one — so the same spelling means different things in
    /// different jobs. Nothing here executes or expands the command.
    #[must_use]
    pub fn check(&self, shell: &brush_core::Shell, key: CommandKey<'_>) -> Verdict {
        match &self.mode {
            Mode::Static => {
                if statically_pure(shell, key.cmd) {
                    Verdict::Pure
                } else {
                    Verdict::Sandboxed
                }
            }
            Mode::Learned(learned) => learned.verdict(key),
        }
    }

    /// The word a diagnostic uses for this checker: `static` or `learned`.
    pub(crate) const fn mode(&self) -> &'static str {
        match self.mode {
            Mode::Static => "static",
            Mode::Learned(_) => "learned",
        }
    }

    /// Loads this checker's persistent state and attaches its append log.
    ///
    /// Called once, from [`ShellMux::new`](crate::ShellMux::new), under the executor's lease and
    /// after recovery: reading the log repairs a torn final line, so a competing owner must already
    /// have failed. A static checker has no persistent state and does nothing here.
    ///
    /// # Errors
    ///
    /// Fails when the cache cannot be read or opened for appending. A missing cache is empty, not
    /// an error; a complete but corrupt record is.
    pub(crate) fn restore(&mut self, persistence: &PersistenceLayer) -> Result<(), MuxError> {
        match &mut self.mode {
            Mode::Static => Ok(()),
            Mode::Learned(learned) => learned.restore(persistence),
        }
    }

    /// Records what a traced run turned out to do.
    ///
    /// A static checker ignores it: its reason is the command's syntax, which a run cannot change.
    pub(crate) fn observe(&self, key: CommandKey<'_>, verdict: Verdict) {
        match &self.mode {
            Mode::Static => {}
            Mode::Learned(learned) => learned.observe(key, verdict),
        }
    }
}

/// One command's verdict, as a line of `meta/purity.jsonl`.
#[derive(Debug, Serialize, Deserialize)]
struct PurityRecord {
    /// The submitted command line.
    cmd: String,
    /// The sandbox's seed-relative directory.
    dir: String,
    /// Whether the command was observed requesting nothing and writing nothing.
    pure: bool,
}

/// What earlier traced runs showed, kept in `meta/purity.jsonl` beside the other logs.
///
/// Keyed directory-first so a lookup borrows the command line rather than copying it: the decision
/// is on the path of every submitted command.
struct LearnedPurity {
    /// Seed-relative directory to command line to verdict.
    known: Mutex<HashMap<String, HashMap<String, Verdict>>>,
    /// The append-only log the map is rebuilt from, once it has been attached.
    log: Mutex<Option<JsonLog<PurityRecord>>>,
}

impl LearnedPurity {
    /// An empty, usable cache with nothing to append to yet.
    fn empty() -> Self {
        Self {
            known: Mutex::new(HashMap::new()),
            log: Mutex::new(None),
        }
    }

    /// Replaces the cache from `persistence` and attaches its append log.
    fn restore(&mut self, persistence: &PersistenceLayer) -> Result<(), MuxError> {
        let path = persistence.meta().join(PURITY_FILE);
        let mut known: HashMap<String, HashMap<String, Verdict>> = HashMap::new();
        // File order, so the last record for a key is the one that stands.
        for record in JsonLog::<PurityRecord>::read(&path)? {
            let verdict = if record.pure {
                Verdict::Pure
            } else {
                Verdict::Sandboxed
            };
            known
                .entry(record.dir)
                .or_default()
                .insert(record.cmd, verdict);
        }
        // Exclusive access, so no lock is taken: restoration happens once, before the checker is
        // shared with anything.
        *self.known.get_mut().unwrap_or_else(PoisonError::into_inner) = known;
        *self.log.get_mut().unwrap_or_else(PoisonError::into_inner) = Some(JsonLog::open(&path)?);
        Ok(())
    }

    /// The verdict map, recovering a poisoned lock: the map is a cache, and refusing to serve it
    /// would cost snapshots rather than protect anything.
    fn known(&self) -> MutexGuard<'_, HashMap<String, HashMap<String, Verdict>>> {
        self.known.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The append handle, with the same poisoning recovery as [`Self::known`].
    fn log(&self) -> MutexGuard<'_, Option<JsonLog<PurityRecord>>> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What earlier runs showed about `key`; a command nothing has been observed about is not one
    /// this checker will vouch for.
    fn verdict(&self, key: CommandKey<'_>) -> Verdict {
        self.known()
            .get(key.dir)
            .and_then(|commands| commands.get(key.cmd))
            .copied()
            .unwrap_or(Verdict::Sandboxed)
    }

    /// Records what a run turned out to do, appending only when the answer changed.
    fn observe(&self, key: CommandKey<'_>, verdict: Verdict) {
        {
            let mut known = self.known();
            // Absent counts as `Sandboxed`: the file gains a line when a command is first found
            // pure, and another when a pure command is demoted, and nothing for the ordinary case.
            let stored = known
                .get(key.dir)
                .and_then(|commands| commands.get(key.cmd))
                .copied()
                .unwrap_or(Verdict::Sandboxed);
            if stored == verdict {
                return;
            }
            known
                .entry(key.dir.to_string())
                .or_default()
                .insert(key.cmd.to_string(), verdict);
        }

        let record = PurityRecord {
            cmd: key.cmd.to_string(),
            dir: key.dir.to_string(),
            pure: verdict == Verdict::Pure,
        };
        // Losing a cache line costs a snapshot, never correctness: the next session simply has to
        // learn the command again.
        let appended = self
            .log()
            .as_mut()
            .map(|log| log.append(std::slice::from_ref(&record)));
        if let Some(Err(error)) = appended {
            eprintln!("marsh: cannot record the purity of {:?}: {error}", key.cmd);
        }
    }
}

/// Whether `cmd`'s own syntax proves it requests no capability and writes nothing.
///
/// The whole command is parsed with the shell's own parser options — never the parser's defaults,
/// which enable extended globbing whatever the shell says — and a parse failure is a refusal, not
/// a fallback.
fn statically_pure(shell: &brush_core::Shell, cmd: &str) -> bool {
    let options = shell.parser_options();
    let Ok(program) = brush_core::parser::Parser::new(cmd.as_bytes(), &options).parse_program()
    else {
        return false;
    };
    program
        .complete_commands
        .iter()
        .all(|list| pure_list(shell, &options, list))
}

/// Whether every item of a list is sequential and provable.
///
/// An `Async` separator backgrounds its command, and a backgrounded command outlives the
/// transaction that would have contained it.
fn pure_list(
    shell: &brush_core::Shell,
    options: &brush_core::parser::ParserOptions,
    list: &ast::CompoundList,
) -> bool {
    list.0.iter().all(|item| {
        matches!(item.1, ast::SeparatorOperator::Sequence) && pure_and_or(shell, options, &item.0)
    })
}

/// Whether every branch of an and-or list is provable. Both branches are checked, because which one
/// runs is a runtime fact.
fn pure_and_or(
    shell: &brush_core::Shell,
    options: &brush_core::parser::ParserOptions,
    and_or: &ast::AndOrList,
) -> bool {
    pure_pipeline(shell, options, &and_or.first)
        && and_or.additional.iter().all(|branch| match branch {
            ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => {
                pure_pipeline(shell, options, pipeline)
            }
        })
}

/// Whether a pipeline is provable: untimed, unnegated, and provable in every stage.
fn pure_pipeline(
    shell: &brush_core::Shell,
    options: &brush_core::parser::ParserOptions,
    pipeline: &ast::Pipeline,
) -> bool {
    pipeline.timed.is_none()
        && !pipeline.bang
        && pipeline
            .seq
            .iter()
            .all(|command| pure_command(shell, options, command))
}

/// Whether one command is provable.
///
/// Only a simple command and an unredirected grouping are recognized at all; a function definition,
/// a loop, a conditional, an arithmetic or test construct and a coprocess are all refused, because
/// what they run is decided while they run.
fn pure_command(
    shell: &brush_core::Shell,
    options: &brush_core::parser::ParserOptions,
    command: &ast::Command,
) -> bool {
    match command {
        ast::Command::Simple(simple) => pure_simple(shell, options, simple),
        ast::Command::Compound(compound, redirects) => {
            redirects.is_none()
                && match compound {
                    ast::CompoundCommand::BraceGroup(group) => {
                        pure_list(shell, options, &group.list)
                    }
                    ast::CompoundCommand::Subshell(subshell) => {
                        pure_list(shell, options, &subshell.list)
                    }
                    _ => false,
                }
        }
        ast::Command::Function(_) => false,
    }
}

/// Whether a simple command is provable: a known builtin name nothing shadows, no prefix, and
/// literal words for arguments.
///
/// The prefix is where an assignment and a redirection live, and either is an effect. A suffix item
/// that is not a plain word is one too.
fn pure_simple(
    shell: &brush_core::Shell,
    options: &brush_core::parser::ParserOptions,
    simple: &ast::SimpleCommand,
) -> bool {
    if simple
        .prefix
        .as_ref()
        .is_some_and(|prefix| !prefix.0.is_empty())
    {
        return false;
    }
    let Some(word) = &simple.word_or_name else {
        return false;
    };
    let Some(name) = raw_name(options, word) else {
        return false;
    };
    if !PROVABLE_BUILTINS.contains(&name.as_str()) {
        return false;
    }
    // A definition with a builtin's name is what actually runs, and it can do anything.
    if shell.funcs().get(&name).is_some() {
        return false;
    }
    if shell.options().expand_aliases && shell.aliases().contains_key(&name) {
        return false;
    }
    simple.suffix.as_ref().is_none_or(|suffix| {
        suffix.0.iter().all(|item| match item {
            ast::CommandPrefixOrSuffixItem::Word(word) => literal_word(options, word),
            _ => false,
        })
    })
}

/// The command name when it is one raw, unquoted literal, and `None` otherwise.
///
/// A quoted or expanded name is refused rather than resolved: `"echo"` and `$cmd` may name the same
/// builtin, but proving that is expansion, which is exactly what this must not do.
fn raw_name(options: &brush_core::parser::ParserOptions, word: &ast::Word) -> Option<String> {
    let pieces = brush_core::parser::word::parse(&word.value, options).ok()?;
    match pieces.as_slice() {
        [only] => match &only.piece {
            WordPiece::Text(text) if *text == word.value => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Whether an argument word is made only of literal pieces.
fn literal_word(options: &brush_core::parser::ParserOptions, word: &ast::Word) -> bool {
    brush_core::parser::word::parse(&word.value, options)
        .is_ok_and(|pieces| literal_pieces(options, &pieces))
}

/// Whether every piece of a parsed word is a literal one.
///
/// Single quotes, ANSI-C quotes and escape sequences are literal by construction. Double quotes are
/// literal exactly when everything inside them is. Unquoted text is literal only when it holds no
/// pattern metacharacter and none of the raw characters the parser would expand later.
fn literal_pieces(
    options: &brush_core::parser::ParserOptions,
    pieces: &[WordPieceWithSource],
) -> bool {
    pieces.iter().all(|piece| match &piece.piece {
        WordPiece::Text(text) => plain_text(options, text),
        WordPiece::SingleQuotedText(_)
        | WordPiece::AnsiCQuotedText(_)
        | WordPiece::EscapeSequence(_) => true,
        WordPiece::DoubleQuotedSequence(inner) => literal_pieces(options, inner),
        // Gettext quoting, every expansion and every substitution: what they produce is decided
        // while the command runs.
        _ => false,
    })
}

/// Whether unquoted `text` expands to itself.
fn plain_text(options: &brush_core::parser::ParserOptions, text: &str) -> bool {
    !brush_core::parser::pattern::pattern_has_glob_metacharacters(
        text,
        options.enable_extended_globbing,
    ) && !text
        .chars()
        .any(|character| UNSAFE_RAW.contains(&character))
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A plain shell for the checker to prove against: no profile, no rc, nothing defined.
    fn shell() -> brush_core::Shell {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                brush_core::Shell::builder()
                    .interactive(false)
                    .no_editing(true)
                    .profile(brush_core::ProfileLoadBehavior::Skip)
                    .rc(brush_core::RcLoadBehavior::Skip)
                    .build()
                    .await
            })
            .expect("a shell")
    }

    /// The verdict a static checker gives `cmd` in `shell`.
    fn verdict(shell: &brush_core::Shell, cmd: &str) -> Verdict {
        PurityCheckerBuilder::new()
            .static_checks()
            .build()
            .check(shell, CommandKey { cmd, dir: "" })
    }

    /// The whole point of the static mode: a command whose syntax cannot act is let through, and
    /// checking it never runs any part of it.
    #[test]
    fn a_literal_composition_of_known_builtins_is_proved_pure() {
        let shell = shell();
        for proved in [
            "true",
            ":",
            "false",
            "pwd",
            "echo hello",
            "true; echo 'literal $(touch hidden)' && pwd",
            "{ true; echo one; }",
            "( echo one; pwd )",
            "echo \"a b\"",
            "echo a\\ b",
        ] {
            assert_eq!(verdict(&shell, proved), Verdict::Pure, "{proved}");
        }
    }

    /// Everything the proof cannot bound takes the transaction, and nothing it refused was run to
    /// find that out.
    #[test]
    fn anything_that_could_act_is_sandboxed() {
        let shell = shell();
        for refused in [
            "echo \"$(touch hidden)\"",
            "echo `touch hidden`",
            "echo $HOME",
            "echo x > hidden",
            "echo x; touch hidden",
            "touch hidden",
            "printf x",
            "f() { touch hidden; }",
            "echo one &",
            "echo *",
            "echo ~",
            "echo {a,b}",
            "if true; then echo one; fi",
            "while true; do echo one; done",
            "! true",
            "VAR=1 echo one",
            "\"echo\" one",
            "echo one |",
        ] {
            assert_eq!(verdict(&shell, refused), Verdict::Sandboxed, "{refused}");
        }
        assert!(
            !std::path::Path::new("hidden").exists(),
            "checking never runs a command substitution"
        );
    }

    /// An imported or defined function with a builtin's name is what actually runs, so a familiar
    /// spelling alone is not proof.
    #[test]
    fn a_shadowing_definition_withdraws_the_proof() {
        let mut shell = shell();
        assert_eq!(verdict(&shell, "echo x"), Verdict::Pure);
        shell
            .define_func_from_str("echo", "() { touch hidden; }")
            .expect("define a shadowing function");
        assert_eq!(
            verdict(&shell, "echo x"),
            Verdict::Sandboxed,
            "the definition is what runs"
        );
    }

    /// The proof reads the shell's parser options, not the parser's defaults — and an extglob the
    /// detector fails to translate must not become a literal.
    #[test]
    fn extended_globbing_follows_the_shell_and_is_never_literal() {
        let mut shell = shell();
        shell.options_mut().extended_globbing = true;
        for refused in [
            "echo @(hidden)",
            "echo +(hidden)",
            "echo @($(touch hidden))",
        ] {
            assert_eq!(verdict(&shell, refused), Verdict::Sandboxed, "{refused}");
        }
        assert!(
            !std::path::Path::new("hidden").exists(),
            "no nested substitution was performed"
        );
    }

    /// A static checker approves from syntax alone: a learned record is not a reason it accepts,
    /// and it writes none of its own.
    #[test]
    fn a_static_checker_neither_reads_nor_writes_learned_state() {
        let shell = shell();
        let checker = PurityCheckerBuilder::new().build();
        let key = CommandKey {
            cmd: "cat -- file0.txt",
            dir: "",
        };
        checker.observe(key, Verdict::Pure);
        assert_eq!(
            checker.check(&shell, key),
            Verdict::Sandboxed,
            "an external command is never proved by syntax, whatever it was told"
        );
    }

    /// A learned checker is usable before it is restored: an empty cache vouches for nothing, and
    /// what it observes meanwhile still stands.
    #[test]
    fn a_learned_checker_starts_empty_and_usable() {
        let shell = shell();
        let checker = PurityCheckerBuilder::new().learned().build();
        let key = CommandKey {
            cmd: "cat -- file0.txt",
            dir: "src",
        };
        assert_eq!(checker.check(&shell, key), Verdict::Sandboxed);
        checker.observe(key, Verdict::Pure);
        assert_eq!(checker.check(&shell, key), Verdict::Pure);
        assert_eq!(
            checker.check(
                &shell,
                CommandKey {
                    cmd: "cat -- file0.txt",
                    dir: "api"
                }
            ),
            Verdict::Sandboxed,
            "another directory is another command"
        );
        assert_eq!(
            checker.check(
                &shell,
                CommandKey {
                    cmd: "true",
                    dir: ""
                }
            ),
            Verdict::Sandboxed,
            "a learned checker proves nothing from syntax"
        );
    }

    /// The cache's whole contract: a verdict earned in one session is what the next one starts
    /// from, and a demotion is what it starts from after that.
    #[test]
    fn a_verdict_survives_the_session_that_earned_it() {
        let scratch = tempfile::tempdir().expect("scratch directory");
        let persistence =
            PersistenceLayer::new(scratch.path().join("seed"), scratch.path().join("state"));
        std::fs::create_dir_all(persistence.meta()).expect("meta");
        let key = CommandKey {
            cmd: "printf x > a.txt",
            dir: "src",
        };

        let mut first = PurityCheckerBuilder::new().learned().build();
        first.restore(&persistence).expect("open the cache");
        first.observe(key, Verdict::Pure);
        drop(first);

        let mut second = PurityCheckerBuilder::new().learned().build();
        second.restore(&persistence).expect("reopen the cache");
        let shell = shell();
        assert_eq!(second.check(&shell, key), Verdict::Pure);
        second.observe(key, Verdict::Sandboxed);
        drop(second);

        let mut third = PurityCheckerBuilder::new().learned().build();
        third.restore(&persistence).expect("reopen the cache again");
        assert_eq!(
            third.check(&shell, key),
            Verdict::Sandboxed,
            "the last record for a key is the one that stands"
        );
    }
}
