//! Recording builtin invocations.
//!
//! Builtins run inside the shell process, so `strace` sees their syscalls but never the invocation
//! itself: `git add foo` executed as a builtin looks like a few reads and writes under `.git/`. This
//! module supplies the other half of the instrumentation — a [`brush_core::BuiltinHook`] that
//! records every builtin lifecycle in memory, plus the record vocabulary the translator consumes.
//!
//! There is exactly one hook implementation, and it writes nothing: tests install it and assert on
//! [`RecordingHook::records`], and the executor dumps the same records once, at exit, to the path
//! the mux named on its command line. A hook that wrote to a file would make those two consumers
//! different code paths.
//!
//! Records carry `CLOCK_REALTIME` microseconds and the emitting thread id — the same clock domain
//! and tid namespace `strace -ttt -f` stamps its lines with, which is what makes merging the two
//! streams into one ordered sequence well defined.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::MuxError;

/// One builtin lifecycle record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "k")]
pub enum BuiltinRecord {
    /// A builtin began executing.
    #[serde(rename = "b")]
    Begin {
        /// Invocation id, unique within one recorder; echoed by the matching [`Self::End`].
        id: u64,
        /// `CLOCK_REALTIME` microseconds at the call.
        ts: u64,
        /// Thread that executed the builtin.
        tid: u32,
        /// Registered builtin name, which for a two-token registration is `"git add"`.
        builtin: String,
        /// Full argument vector, including `argv[0]`.
        argv: Vec<String>,
        /// The shell's logical working directory at the call.
        cwd: PathBuf,
    },
    /// The builtin identified by `id` finished.
    #[serde(rename = "e")]
    End {
        /// Invocation id from the matching [`Self::Begin`].
        id: u64,
        /// `CLOCK_REALTIME` microseconds at the return.
        ts: u64,
        /// Thread that executed the builtin.
        tid: u32,
        /// Exit code the builtin produced.
        exit: u8,
    },
}

impl BuiltinRecord {
    /// The record's timestamp, whichever variant it is.
    pub fn ts(&self) -> u64 {
        match self {
            Self::Begin { ts, .. } | Self::End { ts, .. } => *ts,
        }
    }
}

/// The canonical [`brush_core::BuiltinHook`]: records every builtin lifecycle in memory.
#[derive(Default)]
pub struct RecordingHook {
    records: Mutex<Vec<BuiltinRecord>>,
    next: AtomicU64,
}

impl RecordingHook {
    /// Every record collected so far, in the order the shell produced them.
    pub fn records(&self) -> Vec<BuiltinRecord> {
        self.records
            .lock()
            .expect("recorder lock is never poisoned: the guarded code cannot panic")
            .clone()
    }

    /// Appends one record.
    fn push(&self, record: BuiltinRecord) {
        self.records
            .lock()
            .expect("recorder lock is never poisoned: the guarded code cannot panic")
            .push(record);
    }
}

impl brush_core::BuiltinHook for RecordingHook {
    fn begin(&self, name: &str, argv: &[String], cwd: &Path) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.push(BuiltinRecord::Begin {
            id,
            ts: now_micros(),
            tid: current_tid(),
            builtin: name.to_string(),
            argv: argv.to_vec(),
            cwd: cwd.to_path_buf(),
        });
        id
    }

    fn end(&self, id: u64, exit: u8) {
        self.push(BuiltinRecord::End {
            id,
            ts: now_micros(),
            tid: current_tid(),
            exit,
        });
    }
}

/// `CLOCK_REALTIME` microseconds — the clock `strace -ttt` stamps its lines with.
///
/// A pre-epoch clock is impossible on a running system; were it to happen, 0 orders the record
/// before every syscall, which refuses to merge rather than mis-attributing one.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
        })
}

/// The calling thread's id, in the namespace `strace -f` reports.
pub fn current_tid() -> u32 {
    // SAFETY: `gettid(2)` reads the calling thread's own id; it takes no arguments, touches no
    // memory, and cannot fail.
    let tid = unsafe { libc::gettid() };
    u32::try_from(tid).unwrap_or(0)
}

/// Parses a dumped record array.
///
/// The dump is written once, whole, at executor exit, so there is no partial-line case to tolerate:
/// either the file parses as an array of records or the run's instrumentation is unusable.
pub fn parse_records(text: &str) -> Result<Vec<BuiltinRecord>, MuxError> {
    serde_json::from_str::<Vec<BuiltinRecord>>(text)
        .map_err(|error| MuxError::TraceParse(format!("builtin record dump: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brush_core::BuiltinHook;

    #[test]
    fn records_round_trip_through_json() {
        let records = vec![
            BuiltinRecord::Begin {
                id: 7,
                ts: 1_700_000_000_000_001,
                tid: 42,
                builtin: "git add".to_string(),
                argv: vec!["git".to_string(), "add".to_string(), "foo".to_string()],
                cwd: PathBuf::from("/work/src"),
            },
            BuiltinRecord::End {
                id: 7,
                ts: 1_700_000_000_000_009,
                tid: 42,
                exit: 0,
            },
        ];
        let text = serde_json::to_string(&records).expect("serialize");
        assert_eq!(parse_records(&text).expect("parse"), records);
    }

    #[test]
    fn a_malformed_dump_is_a_parse_error() {
        let error = parse_records("{\"k\":\"b\"}").expect_err("an object is not an array");
        assert!(
            matches!(&error, MuxError::TraceParse(message) if message.contains("builtin record dump")),
            "got {error:?}"
        );
    }

    #[test]
    fn the_recorder_pairs_begins_with_ends_in_order() {
        let hook = RecordingHook::default();
        let cwd = PathBuf::from("/work");
        let first = hook.begin("cd", &["cd".to_string(), "src".to_string()], &cwd);
        let second = hook.begin("git add", &["git".to_string(), "add".to_string()], &cwd);
        hook.end(second, 0);
        hook.end(first, 1);

        assert_ne!(first, second, "ids identify invocations, not builtins");
        let records = hook.records();
        assert_eq!(records.len(), 4);
        let stamps: Vec<u64> = records.iter().map(BuiltinRecord::ts).collect();
        assert!(
            stamps.windows(2).all(|pair| pair[0] <= pair[1]),
            "record order is time order: {stamps:?}"
        );
        let tid = current_tid();
        assert!(
            records.iter().all(|record| match record {
                BuiltinRecord::Begin { tid: recorded, .. }
                | BuiltinRecord::End { tid: recorded, .. } => *recorded == tid,
            }),
            "a builtin is recorded by the thread that ran it"
        );
        let BuiltinRecord::Begin { builtin, argv, .. } = &records[1] else {
            panic!("expected a begin record, got {:?}", records[1]);
        };
        assert_eq!(builtin, "git add");
        assert_eq!(argv, &["git".to_string(), "add".to_string()]);
        assert_eq!(
            records[3],
            BuiltinRecord::End {
                id: first,
                ts: records[3].ts(),
                tid,
                exit: 1,
            },
            "the exit code reaches the record verbatim"
        );
    }
}
