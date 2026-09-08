//! One ordered, policy-neutral record of what an execution did.
//!
//! A command produces two instrumentation streams — syscalls, lexed from the tracer's log, and
//! builtin invocations, dumped by the worker — and both stamp `CLOCK_REALTIME` microseconds
//! ([`crate::hooks::now_micros`] on one side, `strace -ttt` on the other). That shared clock is
//! what makes one interleaved sequence well defined, and interleaving them here is what keeps a
//! consumer from having to open, decode, and merge two files it did not write.
//!
//! Nothing in this module knows about principals, capabilities, policies, or grants. It reports
//! execution facts; deciding what they *mean* belongs to the caller.

use crate::error::ExecError;
use crate::hooks::BuiltinRecord;

/// One decoded line of the trace.
#[derive(Debug)]
pub struct TraceLine {
    /// Thread id that issued the call.
    pub tid: u32,
    /// `CLOCK_REALTIME` microseconds `-ttt` stamped the line with.
    ///
    /// For a call strace split across a context switch this is the *entry* stamp: per-thread entry
    /// order is program order, which is the ordering the stream merge relies on.
    pub ts_us: u64,
    /// What the line records.
    pub call: Call,
}

/// A trace line's payload.
#[derive(Debug)]
pub enum Call {
    /// A completed syscall.
    Syscall {
        /// Syscall name.
        name: String,
        /// Raw argument text between the outermost parentheses.
        args: String,
        /// Return value. `?` (as printed for `exit_group`) and unparsable returns become `-1`,
        /// which reads as "not a success" everywhere a consumer looks at it.
        ret: i64,
        /// Path `-y` printed for a returned descriptor, e.g. `= 3</abs/path>`.
        ret_path: Option<String>,
    },
    /// Process exit record.
    Exited {
        /// Exit status the process reported.
        status: i32,
    },
}

/// One element of the ordered execution record.
#[derive(Debug)]
pub enum ExecutionEvent {
    /// A syscall the tracer observed.
    System(TraceLine),
    /// A builtin lifecycle edge the worker reported.
    Builtin(BuiltinRecord),
}

impl ExecutionEvent {
    /// Sort key: timestamp first, then edge rank.
    ///
    /// The rank makes a builtin's span inclusive at both ends — a syscall sharing a microsecond
    /// with a `Begin` or an `End` counts as *inside* the span. That is the conservative choice for
    /// every consumer that reads spans: a borderline syscall lands inside the builtin that was
    /// running rather than beside it.
    const fn key(&self) -> (u64, u8) {
        match self {
            Self::System(line) => (line.ts_us, 1),
            Self::Builtin(BuiltinRecord::Begin { ts, .. }) => (*ts, 0),
            Self::Builtin(BuiltinRecord::End { ts, .. }) => (*ts, 2),
        }
    }
}

/// Everything one execution was observed to do, in one order.
#[derive(Debug)]
pub struct ExecutionEvidence {
    /// Both instrumentation streams, interleaved by timestamp and edge rank.
    events: Vec<ExecutionEvent>,
    /// Exit status of the traced *root* process, when the trace recorded it.
    root_exit: Option<i32>,
}

impl ExecutionEvidence {
    /// Decodes and interleaves both instrumentation streams.
    ///
    /// `builtin_text` is a whole record array; `"[]"` is what a run that dumped nothing supplies.
    /// The root thread is the one that issued the first decoded syscall — the tracer's own
    /// `execve` of the worker — so it is known before any interleaving happens, and only that
    /// thread's exit record becomes the execution's status. A child's exit says nothing about the
    /// command.
    ///
    /// # Errors
    ///
    /// Fails with [`ExecError::TraceParse`] when either stream is malformed.
    pub fn parse(trace_text: &str, builtin_text: &str) -> Result<Self, ExecError> {
        let lines = crate::strace::parse_trace(trace_text)?;
        let records = crate::hooks::parse_records(builtin_text)?;
        let root_tid = lines.first().map(|line| line.tid);

        let mut root_exit = None;
        let mut events: Vec<ExecutionEvent> = Vec::with_capacity(lines.len() + records.len());
        for line in lines {
            if let Call::Exited { status } = &line.call
                && Some(line.tid) == root_tid
            {
                root_exit = Some(*status);
            }
            events.push(ExecutionEvent::System(line));
        }
        events.extend(records.into_iter().map(ExecutionEvent::Builtin));
        // Stable, so within one timestamp and one rank both streams keep their recorded order —
        // and per-thread order, which is program order, is never disturbed.
        events.sort_by_key(ExecutionEvent::key);

        Ok(Self { events, root_exit })
    }

    /// Both streams as one chronological sequence.
    pub fn events(&self) -> &[ExecutionEvent] {
        &self.events
    }

    /// Exit status of the traced root process, when the trace recorded it.
    pub const fn root_exit_code(&self) -> Option<i32> {
        self.root_exit
    }
}

/// Splits raw argument text into top-level arguments.
#[allow(
    clippy::string_slice,
    reason = "`start` and `index` are byte offsets of the ASCII delimiters this scanner matched, so both are char boundaries"
)]
pub fn split_args(args: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (index, byte) in args.bytes().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(args[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let last = args[start..].trim();
    if !last.is_empty() || !parts.is_empty() {
        parts.push(last);
    }
    parts
}

/// Decodes one quoted, C-escaped strace string argument.
///
/// Returns `None` for anything that is not a quoted string (flag names, numbers, structs).
pub fn parse_quoted(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let inner = arg.strip_prefix('"')?;
    // Truncated strings are printed as `"…"...`; the visible prefix is still the best available.
    let close = inner.rfind('"')?;
    Some(unescape(inner.get(..close)?))
}

/// Reverses strace's C escaping of string arguments.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(digit @ '1'..='7') => {
                // Octal escape: up to three digits, the first already consumed.
                let mut value = digit as u32 - '0' as u32;
                let mut taken = 1;
                let mut lookahead = chars.clone();
                while taken < 3 {
                    match lookahead.next() {
                        Some(next @ '0'..='7') => {
                            value = value * 8 + (next as u32 - '0' as u32);
                            chars.next();
                            lookahead = chars.clone();
                            taken += 1;
                        }
                        _ => break,
                    }
                }
                if let Some(character) = char::from_u32(value) {
                    out.push(character);
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A `-ttt` timestamp for a microsecond count.
    fn at(ts: u64) -> String {
        format!("{}.{:06}", ts / 1_000_000, ts % 1_000_000)
    }

    fn begin(ts: u64, tid: u32, id: u64, builtin: &str) -> BuiltinRecord {
        BuiltinRecord::Begin {
            id,
            ts,
            tid,
            builtin: builtin.to_string(),
            argv: vec!["git".to_string(), "add".to_string(), "p".to_string()],
            cwd: PathBuf::from("/work"),
        }
    }

    #[test]
    fn root_exit_status_is_recorded() {
        let text = format!(
            "10  {} execve(\"/exec/marsh-exec\", [\"marsh-exec\"], 0x7ffd) = 0\n\
             11  {} +++ exited with 7 +++\n\
             10  {} +++ exited with 1 +++\n",
            at(1),
            at(2),
            at(3),
        );
        let evidence = ExecutionEvidence::parse(&text, "[]").expect("parse");
        assert_eq!(
            evidence.root_exit_code(),
            Some(1),
            "the traced root process, not a child, determines the command's status"
        );
    }

    #[test]
    fn both_streams_interleave_by_timestamp_and_rank() {
        let text = format!(
            "10  {} execve(\"/exec/marsh-exec\", [\"marsh-exec\"], 0x7ffd) = 0\n\
             10  {} openat(AT_FDCWD</work>, \".git/index\", O_RDONLY) = 4</work/.git/index>\n",
            at(1),
            at(2),
        );
        let records = vec![
            begin(2, 10, 0, "git add"),
            BuiltinRecord::End {
                id: 0,
                ts: 2,
                tid: 10,
                exit: 0,
            },
        ];
        let dump = serde_json::to_string(&records).expect("serialize");
        let evidence = ExecutionEvidence::parse(&text, &dump).expect("parse");
        let shape: Vec<&str> = evidence
            .events()
            .iter()
            .map(|event| match event {
                ExecutionEvent::System(_) => "syscall",
                ExecutionEvent::Builtin(BuiltinRecord::Begin { .. }) => "begin",
                ExecutionEvent::Builtin(BuiltinRecord::End { .. }) => "end",
            })
            .collect();
        assert_eq!(
            shape,
            vec!["syscall", "begin", "syscall", "end"],
            "a syscall sharing a microsecond with both edges lands inside the span"
        );
    }

    #[test]
    fn a_malformed_stream_is_a_parse_error() {
        let error = ExecutionEvidence::parse("", "{\"k\":\"b\"}")
            .expect_err("an object is not a record array");
        assert!(
            matches!(&error, ExecError::TraceParse(message) if message.contains("builtin record dump")),
            "got {error:?}"
        );
    }

    #[test]
    fn unescapes_c_string_escapes() {
        assert_eq!(
            parse_quoted("\"step 1\\n\"").as_deref(),
            Some("step 1\n"),
            "newline escape"
        );
        assert_eq!(
            parse_quoted("\"a\\\\b\\\"c\"").as_deref(),
            Some("a\\b\"c"),
            "backslash and quote escapes"
        );
        assert_eq!(
            parse_quoted("\"\\101\"").as_deref(),
            Some("A"),
            "octal escape"
        );
        assert_eq!(parse_quoted("O_RDONLY"), None, "flags are not strings");
    }
}
