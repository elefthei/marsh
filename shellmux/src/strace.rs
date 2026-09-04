//! Spawning the traced executor and lexing `strace` output.
//!
//! This module is the syscall *recorder*, one of the two instrumentation streams a command
//! produces: it turns a command line into a chronological list of [`TraceLine`]s and provides the
//! argument lexer [`crate::translate`] reads them with. The other stream is the builtin record dump
//! ([`crate::hooks`]), which the executor writes to the path named by the `--hook-log` argument
//! composed here. Both streams stamp `CLOCK_REALTIME` microseconds — `-ttt` on this side,
//! [`crate::hooks::now_micros`] on the other — which is what lets the translator merge them into
//! one ordered sequence.
//!
//! The system `strace` binary is used deliberately: `-y` fd decoration is what makes relative paths
//! resolvable without reimplementing the kernel's path walk, and the Rust tracer crates surveyed
//! emit formatted text without it.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::MuxError;

/// Exit code reported when the command was killed for exceeding its timeout.
pub(crate) const TIMEOUT_EXIT_CODE: i32 = 124;

/// The descriptor every traced child receives its instrumentation stream on.
///
/// A traced shell has three standard streams, not two: stdout, stderr, and fd 3 — the stream a
/// front-end reads instrumentation out of band from. The vendored brush-core seeds its open-file
/// table from this descriptor, so a builtin's `echo x >&3` and an external child's write to fd 3
/// reach the same sink. Placement is decided here in *every* mode: a traced shell must never
/// inherit whatever the caller happened to leave open on 3.
const INSTRUMENTATION_FD: RawFd = 3;

/// Result of one traced execution.
pub(crate) struct TraceSpawn {
    /// Exit status of the `strace` process itself.
    ///
    /// This is only the *fallback*: the authoritative exit code is the traced root process's
    /// `+++ exited with N +++` record, which [`crate::translate::translate`] extracts.
    pub exit_code: i32,
    /// Command stdout, captured through a pipe.
    pub stdout: Vec<u8>,
    /// Command stderr, captured through a pipe.
    pub stderr: Vec<u8>,
    /// Where the syscall record was written. Retained after the run: it is the audit trail.
    pub trace_log: PathBuf,
    /// Where the executor was told to dump its builtin records. Retained for the same reason, and
    /// absent only when the run died before it could write ([`TIMEOUT_EXIT_CODE`]).
    pub builtin_log: PathBuf,
}

/// One decoded line of the trace.
pub(crate) struct TraceLine {
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
pub(crate) enum Call {
    /// A completed syscall.
    Syscall {
        /// Syscall name.
        name: String,
        /// Raw argument text between the outermost parentheses.
        args: String,
        /// Return value. `?` (as printed for `exit_group`) and unparsable returns become `-1`,
        /// which reads as "not a success" everywhere in the translator.
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

/// Where a traced command's standard streams come from, and how its instrumentation stream is
/// supplied.
///
/// The two variants are the two front-ends. The library and batch caller
/// ([`crate::ShellMux::run_cmd`]) captures output for a program to inspect, so the command must not
/// reach the caller's terminal at all. The console runs the command as a job the user is looking
/// at, so it inherits the real terminal and a full-screen program behaves exactly as it would under
/// any other shell.
#[derive(Clone, Copy)]
pub(crate) enum TraceIo {
    /// Captured: stdin is `/dev/null`, stdout and stderr are pipes [`run_traced`] drains.
    Piped,
    /// Attached to the caller's terminal: stdin, stdout and stderr are inherited, and the terminal
    /// signals the console front-end ignores are restored to their default disposition in the
    /// child.
    Terminal {
        /// Descriptor to place on the child's fd 3. [`INSTRUMENTATION_FD`] itself needs no work —
        /// the caller already holds it and children inherit it. `None` means the session has no
        /// instrumentation sink, and the child gets `/dev/null` like the piped path does.
        instrumentation: Option<RawFd>,
    },
}

/// A spawned tracer whose command is still running.
pub(crate) struct TracedChild {
    /// The `strace` process. Dropping the handle neither waits nor kills, which is what lets the
    /// console own the reap: it must `waitpid` itself to observe a job *stop*, and afterwards this
    /// handle is nothing but a spent pid.
    pub child: Child,
    /// Pid of `strace`, which is also the process-group id of the whole traced tree — the group
    /// `process_group(0)` created, and the one a terminal handoff (`tcsetpgrp`) or a group signal
    /// (`kill(-pgid, …)`) has to name.
    pub pid: libc::pid_t,
    /// Where strace is writing the syscall record.
    pub trace_log: PathBuf,
    /// Where the executor was told to dump its builtin records.
    pub builtin_log: PathBuf,
}

/// Spawns `cmd` in `cwd` inside the traced executor and returns without waiting for it.
///
/// The exact invocation is
/// `strace -f -y -ttt -q -s 4096 -e trace=%file,%process,fchdir -o <trace_log> --
///  <executor> --hook-log <builtin_log> -c <cmd>`:
/// `-f` follows the shell's children (that is where external commands live), `-y` decorates
/// descriptors with their paths, `-ttt` stamps every line with `CLOCK_REALTIME` microseconds so the
/// two streams can be merged, `-q` keeps the `+++ exited with N +++` records that `-qq` would drop,
/// and the syscall set is everything that can touch a path plus process lifecycle.
///
/// `--hook-log` is the entire mux-to-executor instrumentation contract: an argument, not an
/// environment variable, so a command cannot unset it and the executor cannot be instrumented by
/// accident.
pub(crate) fn spawn_traced(
    strace: &Path,
    executor: &Path,
    cmd: &str,
    cwd: &Path,
    envs: &[(OsString, OsString)],
    trace_log: &Path,
    io: TraceIo,
) -> Result<TracedChild, MuxError> {
    if let Some(parent) = trace_log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let builtin_log = trace_log.with_file_name("builtins.json");

    let mut command = Command::new(strace);
    command
        .args(["-f", "-y", "-ttt", "-q", "-s", "4096", "-e"])
        .arg("trace=%file,%process,fchdir")
        .arg("-o")
        .arg(trace_log)
        .arg("--")
        .arg(executor)
        .arg("--hook-log")
        .arg(&builtin_log)
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
        // Own process group inside the caller's session — no setsid, no pty. It is what lets a
        // timeout kill the shell's whole descendant tree instead of just the tracer, and what
        // `tcsetpgrp` hands the terminal to when the console foregrounds the job.
        .process_group(0);
    for (key, value) in envs {
        command.env(key, value);
    }

    let (attached, requested) = match io {
        TraceIo::Piped => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            (false, None)
        }
        TraceIo::Terminal { instrumentation } => {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            (true, instrumentation)
        }
    };

    // Opened here, not in the child: `open` is not async-signal-safe, and a failure to provide the
    // stream is the caller's error, not a half-spawned command's. Rust adds `O_CLOEXEC`, so this
    // descriptor itself never survives the `exec` — only the `dup2` copy on fd 3 does.
    let devnull = match requested {
        Some(_) => None,
        None => Some(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .map_err(|error| MuxError::Exec(format!("open /dev/null: {error}")))?,
        ),
    };
    // A stream already sitting on fd 3 needs nothing done to it; anything else — a descriptor the
    // caller named, or the `/dev/null` fallback — is moved into place after the fork.
    let place = requested
        .filter(|fd| *fd != INSTRUMENTATION_FD)
        .or_else(|| devnull.as_ref().map(AsRawFd::as_raw_fd));

    // The child half of the spawn, running between `fork` and `exec`, where only async-signal-safe
    // operations are permitted. It calls nothing but `libc::signal`, `libc::fcntl` and
    // `libc::dup2`, allocates nothing (the signal list is a stack array), and touches no state
    // shared with the parent.
    let child_setup = move || -> std::io::Result<()> {
        if attached {
            // The console takes the terminal signals away from itself so its own prompt
            // survives them — ignoring most of them, handling `SIGINT` — and both an ignored
            // disposition and, until `exec`, a handler are inherited by the child. Without
            // this reset a job would be immune to Ctrl-C, Ctrl-\ and Ctrl-Z, and background
            // jobs would read the terminal instead of stopping on SIGTTIN.
            for signal in [
                libc::SIGINT,
                libc::SIGQUIT,
                libc::SIGTSTP,
                libc::SIGTTIN,
                libc::SIGTTOU,
            ] {
                // SAFETY: `signal` is one of the five constants above and `SIG_DFL` is always a
                // valid disposition, so this only resets a standard signal to its default.
                if unsafe { libc::signal(signal, libc::SIG_DFL) } == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
        if let Some(source) = place {
            if source == INSTRUMENTATION_FD {
                // `/dev/null` lands on fd 3 itself whenever the parent left it free, and
                // `dup2(fd, fd)` is defined to do nothing at all — including leaving
                // `O_CLOEXEC` set. Clearing that flag is the entire job in this case.
                //
                // SAFETY: `source` is an open descriptor owned by this process, and `F_SETFD`
                // with a flag word takes no pointer argument.
                if unsafe { libc::fcntl(source, libc::F_SETFD, 0) } == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            // SAFETY: `source` is an open descriptor owned by this process and
            // `INSTRUMENTATION_FD` is a valid descriptor number; `dup2` closes any prior fd 3.
            } else if unsafe { libc::dup2(source, INSTRUMENTATION_FD) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    };

    // SAFETY: `child_setup` upholds `pre_exec`'s contract — it is async-signal-safe, allocates
    // nothing, and shares no state with the parent.
    unsafe {
        command.pre_exec(child_setup);
    }

    let child = command
        .spawn()
        .map_err(|error| MuxError::Exec(format!("spawn {}: {error}", strace.display())))?;
    // A Linux pid is bounded by `/proc/sys/kernel/pid_max`, itself capped at 2^22, so the value
    // always fits `pid_t`; `cast_signed` states that reinterpretation instead of hiding it in `as`.
    let pid = child.id().cast_signed();
    Ok(TracedChild {
        child,
        pid,
        trace_log: trace_log.to_path_buf(),
        builtin_log,
    })
}

/// Runs `cmd` to completion under [`TraceIo::Piped`] and captures both of its output streams.
///
/// This is the batch front-end: it owns the wait, so it also owns the wall-clock budget. The
/// console front-end instead spawns with [`spawn_traced`] and waits itself, because only a
/// `waitpid` of its own can observe a job stopping.
pub(crate) fn run_traced(
    strace: &Path,
    executor: &Path,
    cmd: &str,
    cwd: &Path,
    envs: &[(OsString, OsString)],
    trace_log: &Path,
    timeout: Duration,
) -> Result<TraceSpawn, MuxError> {
    let mut traced = spawn_traced(strace, executor, cmd, cwd, envs, trace_log, TraceIo::Piped)?;
    let pid = traced.pid;

    // Drain both pipes on their own threads: a command that fills the 64 KiB pipe buffer would
    // otherwise block forever while we wait for it to exit.
    let mut child_stdout = traced.child.stdout.take().ok_or_else(|| {
        MuxError::Exec("traced child was spawned without a stdout pipe".to_string())
    })?;
    let mut child_stderr = traced.child.stderr.take().ok_or_else(|| {
        MuxError::Exec("traced child was spawned without a stderr pipe".to_string())
    })?;
    let stdout_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = child_stdout.read_to_end(&mut buffer);
        buffer
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = child_stderr.read_to_end(&mut buffer);
        buffer
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match traced.child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(error) => return Err(MuxError::Exec(format!("wait: {error}"))),
        }
        if Instant::now() >= deadline {
            timed_out = true;
            // SAFETY: `kill(2)` with a negative pid signals the process group we created above;
            // it has no memory-safety requirements.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            break traced
                .child
                .wait()
                .map_err(|error| MuxError::Exec(format!("wait after kill: {error}")))
                .map(Some)?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    let exit_code = if timed_out {
        TIMEOUT_EXIT_CODE
    } else {
        status.and_then(|status| status.code()).unwrap_or(-1)
    };

    Ok(TraceSpawn {
        exit_code,
        stdout,
        stderr,
        trace_log: traced.trace_log,
        builtin_log: traced.builtin_log,
    })
}

/// A syscall interrupted by a context switch: `(tid, name)` and the entry timestamp with the
/// argument text printed before the interruption.
type PendingCall = ((u32, String), (u64, String));

/// Lexes a whole `strace` log into chronological [`TraceLine`]s.
///
/// Lines strace splits across a context switch (`… <unfinished ...>` followed later by
/// `<... name resumed> …`) are rejoined, so the translator sees each syscall exactly once, with the
/// return value it actually produced and the timestamp of its *entry*. Signal records and kill
/// records carry no path information and are dropped.
pub(crate) fn parse_trace(text: &str) -> Result<Vec<TraceLine>, MuxError> {
    let mut lines = Vec::new();
    // (tid, syscall name) -> entry timestamp and argument text seen before the call was interrupted.
    let mut pending: Vec<PendingCall> = Vec::new();

    for raw in text.lines() {
        let raw = raw.trim_end();
        if raw.is_empty() {
            continue;
        }
        let Some((tid, ts_us, rest)) = split_prefix(raw) else {
            // strace's own diagnostics ("strace: Process … attached") carry no syscall.
            continue;
        };

        if let Some(status) = rest.strip_prefix("+++ exited with ") {
            let status = status
                .trim_end_matches(" +++")
                .trim()
                .parse::<i32>()
                .map_err(|_| MuxError::TraceParse(format!("exit record: {raw}")))?;
            lines.push(TraceLine {
                tid,
                ts_us,
                call: Call::Exited { status },
            });
            continue;
        }
        if rest.starts_with("+++") || rest.starts_with("---") || rest.starts_with("strace:") {
            continue;
        }

        // Resumption of an interrupted call: `<... openat resumed>) = 3</abs/path>`.
        if let Some(after) = rest.strip_prefix("<... ") {
            let Some((name, tail)) = after.split_once(" resumed>") else {
                continue;
            };
            let (entry_ts, prefix) =
                take_pending(&mut pending, tid, name).unwrap_or_else(|| (ts_us, String::new()));
            let Some((args_tail, ret_text)) = split_close(tail) else {
                continue;
            };
            let mut args = prefix;
            args.push_str(args_tail);
            let (ret, ret_path) = parse_return(ret_text);
            lines.push(TraceLine {
                tid,
                ts_us: entry_ts,
                call: Call::Syscall {
                    name: name.to_string(),
                    args,
                    ret,
                    ret_path,
                },
            });
            continue;
        }

        let Some(open) = rest.find('(') else {
            continue;
        };
        let Some(name) = rest.get(..open) else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let Some(body) = rest.get(open + 1..) else {
            continue;
        };

        if let Some(partial) = body.strip_suffix("<unfinished ...>") {
            pending.push((
                (tid, name.to_string()),
                (ts_us, partial.trim_end().to_string()),
            ));
            continue;
        }

        let Some((args, ret_text)) = split_close(body) else {
            continue;
        };
        let (ret, ret_path) = parse_return(ret_text);
        lines.push(TraceLine {
            tid,
            ts_us,
            call: Call::Syscall {
                name: name.to_string(),
                args: args.to_string(),
                ret,
                ret_path,
            },
        });
    }

    Ok(lines)
}

/// Splits the leading thread id and `-ttt` timestamp from a trace line.
///
/// The prefix strace prints is `TID <ws> SECS.MICROS <ws> rest`; an unstamped line (there is none
/// while `-ttt` is passed) yields no line at all rather than a line that would merge at time zero.
fn split_prefix(line: &str) -> Option<(u32, u64, &str)> {
    let end = line.find(|c: char| !c.is_ascii_digit())?;
    if end == 0 {
        return None;
    }
    let tid = line.get(..end)?.parse::<u32>().ok()?;
    let rest = line.get(end..)?.trim_start();
    let (stamp, rest) = rest.split_once(' ')?;
    let (seconds, micros) = stamp.split_once('.')?;
    if micros.len() != 6 {
        return None;
    }
    let seconds = seconds.parse::<u64>().ok()?;
    let micros = micros.parse::<u64>().ok()?;
    Some((tid, seconds * 1_000_000 + micros, rest.trim_start()))
}

/// Removes and returns the entry timestamp and buffered argument prefix of an interrupted call.
fn take_pending(pending: &mut Vec<PendingCall>, tid: u32, name: &str) -> Option<(u64, String)> {
    let index = pending
        .iter()
        .rposition(|((ptid, pname), _)| *ptid == tid && pname == name)?;
    Some(pending.remove(index).1)
}

/// Splits argument text from the return text at the call's closing parenthesis.
///
/// `body` starts just after the opening parenthesis. Nesting (`[`, `{`, `(`) and quoted strings are
/// tracked so that a `)` inside a struct or a filename does not end the argument list.
fn split_close(body: &str) -> Option<(&str, &str)> {
    let bytes = body.as_bytes();
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
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
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    let tail = body.get(index + 1..)?.trim_start();
                    let ret = tail.strip_prefix('=').map_or(tail, str::trim_start);
                    return Some((body.get(..index)?, ret));
                }
            }
            _ => {}
        }
    }
    None
}

/// Parses the text after `= ` into a return value and its optional `-y` path decoration.
#[allow(
    clippy::string_slice,
    reason = "every index here is a byte offset into ASCII syntax — a leading `-`, an ASCII digit/hexdigit run, or a `<`/`>` found by `find`/`rfind` — so it is always a char boundary"
)]
fn parse_return(text: &str) -> (i64, Option<String>) {
    let text = text.trim();
    if text.is_empty() || text.starts_with('?') {
        return (-1, None);
    }
    let mut end = 0;
    let bytes = text.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    if text[end..].starts_with("0x") {
        let hex_end = end
            + 2
            + text[end + 2..]
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(text.len() - end - 2);
        let value = i64::from_str_radix(&text[end + 2..hex_end], 16).unwrap_or(-1);
        return (value, None);
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let Ok(value) = text[..end].parse::<i64>() else {
        return (-1, None);
    };
    let decoration = text[end..].strip_prefix('<').and_then(|rest| {
        rest.rfind('>')
            .map(|close| rest[..close].to_string())
            .filter(|path| path.starts_with('/'))
    });
    (value, decoration)
}

/// Splits raw argument text into top-level arguments.
#[allow(
    clippy::string_slice,
    reason = "`start` and `index` are byte offsets of the ASCII delimiters this scanner matched, so both are char boundaries"
)]
pub(crate) fn split_args(args: &str) -> Vec<&str> {
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
pub(crate) fn parse_quoted(arg: &str) -> Option<String> {
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

    fn syscall(line: &TraceLine) -> (&str, &str, i64, Option<&str>) {
        match &line.call {
            Call::Syscall {
                name,
                args,
                ret,
                ret_path,
            } => (name, args, *ret, ret_path.as_deref()),
            Call::Exited { .. } => panic!("expected a syscall"),
        }
    }

    #[test]
    fn parses_openat_with_return_decoration() {
        let text = "7844  1788295173.846003 openat(AT_FDCWD</work>, \"a.txt\", O_RDONLY) = 3</work/a.txt>\n";
        let lines = parse_trace(text).expect("parse");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].tid, 7844);
        assert_eq!(lines[0].ts_us, 1_788_295_173_846_003);
        let (name, args, ret, ret_path) = syscall(&lines[0]);
        assert_eq!(name, "openat");
        assert_eq!(args, "AT_FDCWD</work>, \"a.txt\", O_RDONLY");
        assert_eq!(ret, 3);
        assert_eq!(ret_path, Some("/work/a.txt"));
        assert_eq!(
            split_args(args),
            vec!["AT_FDCWD</work>", "\"a.txt\"", "O_RDONLY"]
        );
    }

    #[test]
    fn parses_failed_call_as_negative_return() {
        let text = "12  1788295173.851293 openat(AT_FDCWD</work>, \"missing\", O_RDONLY) = -1 ENOENT (No such file or directory)\n";
        let lines = parse_trace(text).expect("parse");
        let (name, _, ret, ret_path) = syscall(&lines[0]);
        assert_eq!(name, "openat");
        assert_eq!(ret, -1);
        assert_eq!(ret_path, None);
    }

    #[test]
    fn rejoins_unfinished_and_resumed_pair() {
        let text = concat!(
            "31  1788295173.886545 openat(AT_FDCWD</work>, \"slow.txt\" <unfinished ...>\n",
            "32  1788295173.899935 clone(child_stack=NULL, flags=SIGCHLD) = 33\n",
            "31  1788295173.900045 <... openat resumed>, O_WRONLY|O_CREAT, 0666) = 4</work/slow.txt>\n",
        );
        let lines = parse_trace(text).expect("parse");
        assert_eq!(lines.len(), 2, "the unfinished line is not a separate call");
        let (name, args, ret, ret_path) = syscall(&lines[1]);
        assert_eq!(name, "openat");
        assert_eq!(
            args,
            "AT_FDCWD</work>, \"slow.txt\", O_WRONLY|O_CREAT, 0666"
        );
        assert_eq!(ret, 4);
        assert_eq!(ret_path, Some("/work/slow.txt"));
        assert_eq!(
            lines[1].ts_us, 1_788_295_173_886_545,
            "a rejoined call is stamped when it entered, not when it resumed: per-thread entry \
             order is program order, which is what the stream merge relies on"
        );
    }

    #[test]
    fn parses_execve_argv_vector() {
        let text = "40  1788295173.846003 execve(\"/usr/bin/git\", [\"git\", \"add\", \"--\", \"src/file0.txt\"], 0x7ffd /* 80 vars */) = 0\n";
        let lines = parse_trace(text).expect("parse");
        let (name, args, ret, _) = syscall(&lines[0]);
        assert_eq!(name, "execve");
        assert_eq!(ret, 0);
        let parts = split_args(args);
        assert_eq!(parts.len(), 3, "path, argv, envp: {parts:?}");
        assert_eq!(parse_quoted(parts[0]).as_deref(), Some("/usr/bin/git"));
        let argv: Vec<String> = split_args(parts[1].trim_start_matches('[').trim_end_matches(']'))
            .into_iter()
            .filter_map(parse_quoted)
            .collect();
        assert_eq!(argv, vec!["git", "add", "--", "src/file0.txt"]);
    }

    #[test]
    fn parses_clone_child_tid_and_exit_records() {
        let text = concat!(
            "50  1788295173.100000 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 51\n",
            "51  1788295173.200000 exit_group(0)                     = ?\n",
            "51  1788295173.300000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n",
            "51  1788295173.400000 +++ exited with 0 +++\n",
            "50  1788295173.500000 +++ exited with 3 +++\n",
        );
        let lines = parse_trace(text).expect("parse");
        assert_eq!(lines.len(), 4, "signal lines are dropped");
        let (name, _, ret, _) = syscall(&lines[0]);
        assert_eq!((name, ret), ("clone", 51));
        let (name, _, ret, _) = syscall(&lines[1]);
        assert_eq!(
            (name, ret),
            ("exit_group", -1),
            "an unknown `= ?` return never reads as success"
        );
        assert!(matches!(lines[2].call, Call::Exited { status: 0 }));
        assert!(matches!(lines[3].call, Call::Exited { status: 3 }));
        assert_eq!(lines[3].tid, 50);
        assert_eq!(
            lines[3].ts_us, 1_788_295_173_500_000,
            "exit records are stamped too"
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

    #[test]
    fn keeps_parentheses_inside_quoted_arguments() {
        let text = "60  1788295173.846003 openat(AT_FDCWD</work>, \"weird)name.txt\", O_RDONLY) = 5</work/weird)name.txt>\n";
        let lines = parse_trace(text).expect("parse");
        let (_, args, ret, ret_path) = syscall(&lines[0]);
        assert_eq!(ret, 5);
        assert_eq!(ret_path, Some("/work/weird)name.txt"));
        assert_eq!(
            parse_quoted(split_args(args)[1]).as_deref(),
            Some("weird)name.txt")
        );
    }
}
