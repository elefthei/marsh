//! Which commands may skip the sandbox, and what the mux learns about them.
//!
//! A transaction costs a copy-on-write snapshot of the seed and a walk of two trees. A command that
//! writes nothing and requests no capability has nothing for either to do, so the mux is willing to
//! run it in the seed itself. Willingness is not proof: the only evidence marsh accepts is a trace,
//! so a command earns the verdict by having been traced doing nothing, and a bypassed run is traced
//! too — which is how a verdict that has gone wrong is withdrawn instead of trusted.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use crate::error::MuxError;
use crate::session::Session;
use crate::wal::JsonLog;

/// Log file name under the session's `meta/` directory.
const PURITY_FILE: &str = "purity.jsonl";

/// What a source knows about one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Requested no capability and wrote nothing: it may run in the seed, with no snapshot and no
    /// merge.
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

/// A source of purity verdicts.
///
/// Sources are consulted in the order [`crate::ShellMux::open`] was given them and the first
/// answer wins, so an explicit source overrides what the mux learned. Implement this to teach marsh
/// about commands it cannot observe for itself: a project configuration, a policy service, a list
/// of commands an operator vouches for.
pub trait PuritySource: Send + Sync {
    /// Short name, quoted when a verdict from this source is withdrawn.
    ///
    /// `'static` because a source's name identifies the kind of source, not the instance: it is a
    /// label an operator matches against a configuration, never a per-command string.
    fn name(&self) -> &'static str;

    /// This source's verdict, or `None` when it has no opinion.
    fn verdict(&self, key: CommandKey<'_>) -> Option<Verdict>;

    /// Records what a run turned out to do. The default ignores it: only a learning source stores
    /// what it is told.
    fn observe(&self, key: CommandKey<'_>, verdict: Verdict) {
        let _ = (key, verdict);
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
pub struct LearnedPurity {
    /// Seed-relative directory to command line to verdict.
    known: Mutex<HashMap<String, HashMap<String, Verdict>>>,
    /// The append-only log the map is rebuilt from at startup.
    log: Mutex<JsonLog<PurityRecord>>,
}

impl LearnedPurity {
    /// Opens the cache, reading back what earlier sessions learned.
    ///
    /// # Errors
    ///
    /// Fails when the log cannot be read or opened for appending.
    pub fn open(session: &Session) -> Result<Self, MuxError> {
        let path = session.meta().join(PURITY_FILE);
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
        Ok(Self {
            known: Mutex::new(known),
            log: Mutex::new(JsonLog::open(&path)?),
        })
    }

    /// The verdict map, recovering a poisoned lock: the map is a cache, and refusing to serve it
    /// would cost snapshots rather than protect anything.
    fn known(&self) -> MutexGuard<'_, HashMap<String, HashMap<String, Verdict>>> {
        self.known.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The append handle, with the same poisoning recovery as [`Self::known`].
    fn log(&self) -> MutexGuard<'_, JsonLog<PurityRecord>> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PuritySource for LearnedPurity {
    fn name(&self) -> &'static str {
        "learned"
    }

    fn verdict(&self, key: CommandKey<'_>) -> Option<Verdict> {
        self.known()
            .get(key.dir)
            .and_then(|commands| commands.get(key.cmd))
            .copied()
    }

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
        let appended = self.log().append(&[record]);
        if let Err(error) = appended {
            eprintln!("marsh: cannot record the purity of {:?}: {error}", key.cmd);
        }
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::snapshot::tests::test_root;

    /// A session over a scratch directory: only `meta()` is ever touched here.
    fn scratch_session(root: &Path) -> Session {
        Session {
            seed: root.join("seed"),
            root: root.join("state"),
        }
    }

    /// A source that answers from a fixed table and never learns, which is what an operator's
    /// configuration would be.
    struct Fixed {
        /// The one command line it has an opinion about.
        cmd: String,
        /// The opinion.
        verdict: Verdict,
    }

    impl PuritySource for Fixed {
        fn name(&self) -> &'static str {
            "fixed"
        }

        fn verdict(&self, key: CommandKey<'_>) -> Option<Verdict> {
            (key.cmd == self.cmd).then_some(self.verdict)
        }
    }

    /// The first source with an opinion decides, which is the whole of the ordering contract: an
    /// operator's list has to be able to override what the mux taught itself.
    #[test]
    fn the_first_source_with_an_opinion_wins() {
        let root = test_root();
        let learned = LearnedPurity::open(&scratch_session(&root)).expect("open the cache");
        let key = CommandKey { cmd: "ls", dir: "" };
        learned.observe(key, Verdict::Pure);

        let sources: Vec<Box<dyn PuritySource>> = vec![
            Box::new(Fixed {
                cmd: "ls".to_string(),
                verdict: Verdict::Sandboxed,
            }),
            Box::new(learned),
        ];
        let first = sources.iter().find_map(|source| source.verdict(key));
        assert_eq!(
            first,
            Some(Verdict::Sandboxed),
            "the explicit source overrides what was learned"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The cache's whole contract: a verdict earned in one session is what the next one starts
    /// from, and a demotion is what it starts from after that.
    #[test]
    fn a_verdict_survives_the_session_that_earned_it() {
        let root = test_root();
        let session = scratch_session(&root);
        let key = CommandKey {
            cmd: "printf x > a.txt",
            dir: "src",
        };

        let first = LearnedPurity::open(&session).expect("open the cache");
        assert_eq!(first.verdict(key), None, "an empty cache has no opinion");
        first.observe(key, Verdict::Pure);
        drop(first);

        let second = LearnedPurity::open(&session).expect("reopen the cache");
        assert_eq!(second.verdict(key), Some(Verdict::Pure));
        second.observe(key, Verdict::Sandboxed);
        drop(second);

        let third = LearnedPurity::open(&session).expect("reopen the cache again");
        assert_eq!(
            third.verdict(key),
            Some(Verdict::Sandboxed),
            "the last record for a key is the one that stands"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A relative command names a different program in a different directory, so a verdict earned
    /// in one job directory must not let it out of the sandbox in another.
    #[test]
    fn the_job_directory_is_part_of_the_key() {
        let root = test_root();
        let learned = LearnedPurity::open(&scratch_session(&root)).expect("open the cache");
        learned.observe(
            CommandKey {
                cmd: "./build.sh",
                dir: "",
            },
            Verdict::Pure,
        );

        assert_eq!(
            learned.verdict(CommandKey {
                cmd: "./build.sh",
                dir: "api",
            }),
            None,
            "another directory is another command"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}
