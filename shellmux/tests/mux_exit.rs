//! Real-terminal regressions for cancellation-only shell exit and traced-process lifetime.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::panic, clippy::panic_in_result_fn)]

mod common;

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::Fixture;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const DESCENDANT_TIMEOUT: Duration = Duration::from_secs(2);
const PROMPT: &str = "main@.$ ";
const LIVE_JOB: &str = "bash -c 'trap \"\" HUP; sleep 60 & printf \"child:%s\\n\" \"$!\" >&3; printf \"ready:%s\\n\" \"$$\" >&3; wait' &slow\n";

/// How the first and accepted requests ask the shell to exit.
#[derive(Clone, Copy)]
enum ExitRequest {
    Typed,
    Eof,
    Interrupt,
}

impl ExitRequest {
    /// Bytes interpreted by the terminal as this request.
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Typed => b"exit\n",
            Self::Eof => b"\x04",
            Self::Interrupt => b"\x03",
        }
    }
}

/// A marsh child attached to a real pseudo-terminal.
struct PtyShell {
    child: Child,
    master: File,
    slave: File,
    original_modes: libc::tcflag_t,
    original_suspend: libc::cc_t,
    output: Vec<u8>,
}

/// Creates a session and makes the already-installed PTY slave its controlling terminal.
fn configure_pty_child() -> std::io::Result<()> {
    // SAFETY: `setsid` takes no arguments and has no memory preconditions.
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: stdin is the PTY slave after `Command` installs its standard streams;
    // `TIOCSCTTY` receives a scalar argument.
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
impl PtyShell {
    /// Starts marsh's basic editor on `fixture`'s seed and waits for its first prompt.
    fn start(fixture: &Fixture) -> Self {
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: both descriptor pointers and the winsize are valid for the duration of the call.
        let opened = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &raw const size,
            )
        };
        assert_eq!(opened, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: successful `openpty` returned two new owned descriptors.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        // SAFETY: successful `openpty` returned two new owned descriptors.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        set_cloexec(master.as_raw_fd());
        set_cloexec(slave.as_raw_fd());

        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `slave` names a terminal and `original` is writable storage for `tcgetattr`.
        let got_modes = unsafe { libc::tcgetattr(slave.as_raw_fd(), original.as_mut_ptr()) };
        assert_eq!(
            got_modes,
            0,
            "tcgetattr: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `tcgetattr` initialized `original` after succeeding.
        let original = unsafe { original.assume_init() };

        let stdin = File::from(slave.try_clone().expect("clone PTY slave"));
        let stdout = File::from(slave.try_clone().expect("clone PTY slave"));
        let stderr = File::from(slave.try_clone().expect("clone PTY slave"));
        let mut command = Command::new(common::executor().with_file_name("marsh"));
        command
            .args(["--input-backend", "basic", "--disable-color"])
            .env("TERM", "xterm-256color")
            .current_dir(fixture.seed_root())
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: `configure_pty_child` is restricted to async-signal-safe system calls.
        unsafe {
            command.pre_exec(configure_pty_child);
        }
        let child = command.spawn().expect(
            "spawn target/debug/marsh; build both runtime binaries before running mux_exit",
        );
        set_nonblocking(master.as_raw_fd());

        let mut shell = Self {
            child,
            master: File::from(master),
            slave: File::from(slave),
            original_modes: original.c_lflag,
            original_suspend: original.c_cc[libc::VSUSP],
            output: Vec::new(),
        };
        shell.wait_for(PROMPT, STARTUP_TIMEOUT);
        shell
    }

    /// Writes terminal input exactly as a user would.
    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).expect("write PTY input");
        self.master.flush().expect("flush PTY input");
    }

    /// Discards previously observed output so later waits prove a new event occurred.
    fn clear_output(&mut self) {
        self.output.clear();
    }

    /// Reads until `needle` appears or the deadline expires.
    fn wait_for(&mut self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !String::from_utf8_lossy(&self.output).contains(needle) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; output: {}",
                String::from_utf8_lossy(&self.output)
            );
            self.read_available(deadline);
        }
    }

    /// Reads currently available PTY output, waiting only as long as `deadline` permits.
    fn read_available(&mut self, deadline: Instant) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut descriptor = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` is one valid poll entry for the call's duration.
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if ready == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return;
            }
            panic!("poll PTY: {error}");
        }
        if ready == 0 {
            return;
        }
        let mut buffer = [0_u8; 4096];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => self.output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("read PTY: {error}"),
            }
        }
    }

    /// Waits for marsh to terminate and returns its status.
    fn wait_for_exit(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll marsh") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "marsh did not exit within {timeout:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Confirms the terminal modes and the suspend character marsh changed were restored.
    fn assert_terminal_restored(&self) {
        let mut current = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `slave` remains an open terminal and `current` is writable termios storage.
        let result = unsafe { libc::tcgetattr(self.slave.as_raw_fd(), current.as_mut_ptr()) };
        assert_eq!(result, 0, "tcgetattr after exit");
        // SAFETY: `tcgetattr` initialized `current` after succeeding.
        let current = unsafe { current.assume_init() };
        let mask = libc::ICANON | libc::ECHO | libc::ISIG;
        assert_eq!(current.c_lflag & mask, self.original_modes & mask);
        assert_eq!(
            current.c_cc[libc::VSUSP],
            self.original_suspend,
            "the suspend character marsh disabled is the user's again"
        );
    }
}

impl Drop for PtyShell {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Adds close-on-exec to one test-owned descriptor.
fn set_cloexec(fd: libc::c_int) {
    // SAFETY: `fd` is open and both fcntl operations use scalar arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert_ne!(flags, -1, "F_GETFD: {}", std::io::Error::last_os_error());
    // SAFETY: `fd` is open and the flag word is valid.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    assert_ne!(result, -1, "F_SETFD: {}", std::io::Error::last_os_error());
}

/// Makes the PTY master suitable for deadline-driven reads.
fn set_nonblocking(fd: libc::c_int) {
    // SAFETY: `fd` is open and both fcntl operations use scalar arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert_ne!(flags, -1, "F_GETFL: {}", std::io::Error::last_os_error());
    // SAFETY: `fd` is open and the flag word is valid.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_ne!(result, -1, "F_SETFL: {}", std::io::Error::last_os_error());
}

/// Finds a decimal pid printed after `prefix`, ignoring the echoed command text.
fn find_reported_pid(output: &[u8], prefix: &str) -> Option<libc::pid_t> {
    let text = String::from_utf8_lossy(output);
    text.match_indices(prefix).find_map(|(start, _)| {
        let digits: String = text
            .get(start + prefix.len()..)
            .unwrap_or_default()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        (!digits.is_empty()).then(|| digits.parse().expect("parse reported pid"))
    })
}

/// Extracts a decimal pid printed after `prefix`.
fn reported_pid(output: &[u8], prefix: &str) -> libc::pid_t {
    find_reported_pid(output, prefix).unwrap_or_else(|| {
        panic!(
            "missing numeric {prefix:?} in {}",
            String::from_utf8_lossy(output)
        )
    })
}

/// Whether a process exists in a non-zombie state.
fn is_running(pid: libc::pid_t) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, tail)| tail.as_bytes().first())
        .is_some_and(|state| *state != b'Z')
}

/// Waits for a process to disappear or become a zombie.
fn wait_not_running(pid: libc::pid_t) {
    let deadline = Instant::now() + DESCENDANT_TIMEOUT;
    while is_running(pid) {
        assert!(Instant::now() < deadline, "process {pid} remained live");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Starts the long-running background fixture and proves it remains live after its launcher exits.
fn start_live_job(shell: &mut PtyShell) -> (libc::pid_t, libc::pid_t) {
    shell.clear_output();
    shell.send(LIVE_JOB.as_bytes());
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if find_reported_pid(&shell.output, "child:").is_some()
            && find_reported_pid(&shell.output, "ready:").is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for job pids; output: {}",
            String::from_utf8_lossy(&shell.output)
        );
        shell.read_available(deadline);
    }
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    let child = reported_pid(&shell.output, "child:");
    let root = reported_pid(&shell.output, "ready:");

    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(" running ", STARTUP_TIMEOUT);
    assert!(is_running(root));
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    assert!(is_running(child));
    (root, child)
}

/// Exercises the warning followed by one accepted, bounded exit request.
fn accepted_exit(request: ExitRequest, label: &str) {
    let fixture = Fixture::cold(label);
    let mut shell = PtyShell::start(&fixture);
    let (root, child) = start_live_job(&mut shell);

    shell.clear_output();
    shell.send(request.bytes());
    match request {
        ExitRequest::Typed | ExitRequest::Eof => {
            shell.wait_for("there are running jobs", STARTUP_TIMEOUT);
        }
        ExitRequest::Interrupt => {
            shell.wait_for("press Ctrl-C again to quit", STARTUP_TIMEOUT);
        }
    }
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    let started = Instant::now();
    shell.send(request.bytes());
    shell.wait_for_exit(EXIT_TIMEOUT);
    assert!(started.elapsed() <= EXIT_TIMEOUT);
    shell.assert_terminal_restored();
    wait_not_running(root);
    wait_not_running(child);
}

#[test]
fn typed_exit_cancels_live_work_immediately() {
    accepted_exit(ExitRequest::Typed, "exit-typed");
}

#[test]
fn eof_cancels_live_work_immediately() {
    accepted_exit(ExitRequest::Eof, "exit-eof");
}

#[test]
fn prompt_interrupt_cancels_live_work_immediately() {
    accepted_exit(ExitRequest::Interrupt, "exit-interrupt");
}

#[test]
fn abrupt_shell_death_kills_traced_descendants() {
    let fixture = Fixture::cold("exit-killed");
    let mut shell = PtyShell::start(&fixture);
    let (root, child) = start_live_job(&mut shell);

    shell.child.kill().expect("SIGKILL marsh");
    shell.wait_for_exit(EXIT_TIMEOUT);
    wait_not_running(root);
    wait_not_running(child);
}

#[test]
fn committed_state_is_reclaimed_only_by_the_next_startup() {
    let fixture = Fixture::cold("exit-persistence");
    let mut shell = PtyShell::start(&fixture);

    shell.clear_output();
    shell.send(b"printf 'committed\\n' > durable.txt\n");
    shell.wait_for("%main committed seq=", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for("%main*", STARTUP_TIMEOUT);
    let text = String::from_utf8_lossy(&shell.output);
    let uid = text
        .lines()
        .find(|line| line.contains("%main*"))
        .and_then(|line| {
            line.split_whitespace()
                .find(|word| word.len() == 8 && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
        })
        .expect("main job uid");
    let snapshot = fixture.persistence().work(uid);

    shell.send(b"exit\n");
    shell.wait_for_exit(EXIT_TIMEOUT);
    assert!(
        snapshot.exists(),
        "normal exit leaves reclamation to startup"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.seed("durable.txt")).expect("read durable seed file"),
        "committed\n"
    );

    let mut restarted = PtyShell::start(&fixture);
    assert!(
        !snapshot.exists(),
        "the next startup reclaims the old snapshot"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.seed("durable.txt")).expect("reread durable seed file"),
        "committed\n"
    );
    restarted.send(b"exit\n");
    restarted.wait_for_exit(EXIT_TIMEOUT);
}

#[test]
fn completed_history_survives_abrupt_death() {
    let fixture = Fixture::cold("exit-history");
    let mut shell = PtyShell::start(&fixture);

    let command = "printf 'history-marker\\n'\n";
    shell.clear_output();
    shell.send(command.as_bytes());
    shell.wait_for("%main committed seq=", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    shell
        .child
        .kill()
        .expect("SIGKILL marsh after completed command");
    shell.wait_for_exit(EXIT_TIMEOUT);

    let history = fixture.persistence().meta().join("console.history");
    assert!(
        std::fs::read_to_string(&history)
            .expect("read recall history")
            .contains(command.trim_end()),
        "completed input was saved before the next prompt"
    );
    let mut restarted = PtyShell::start(&fixture);
    restarted.send(b"exit\n");
    restarted.wait_for_exit(EXIT_TIMEOUT);
}

#[test]
fn accepted_exit_does_not_open_the_history_file() {
    let fixture = Fixture::cold("exit-history-fifo");
    let mut shell = PtyShell::start(&fixture);
    shell.clear_output();
    shell.send(b"true\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    let history = fixture.persistence().meta().join("console.history");
    let saved = fixture.persistence().meta().join("console.history.saved");
    std::fs::rename(&history, &saved).expect("move saved history");
    let path = CString::new(history.as_os_str().as_bytes()).expect("history path has no NUL");
    // SAFETY: `path` is a valid C string and the mode is an ordinary FIFO permission mask.
    let made = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());

    shell.send(b"exit\n");
    shell.wait_for_exit(EXIT_TIMEOUT);
    std::fs::remove_file(&history).expect("remove test FIFO");
    std::fs::rename(saved, history).expect("restore history");
}

/// A `jobs` row for `name`, ignoring instrumentation lines that merely mention it.
///
/// Row-shaped rather than substring-shaped on purpose: an echoed command and a gray announcement
/// both contain the job's name, and neither is evidence about the table.
fn job_row(output: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(output)
        .lines()
        .find(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|first| first.trim_end_matches('*') == name)
        })
        .map(str::to_string)
}

/// The eight-hex sandbox uid a fresh `jobs` prints for `name`, read back at `prompt`.
fn job_uid(shell: &mut PtyShell, prompt: &str, name: &str) -> String {
    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(prompt, STARTUP_TIMEOUT);
    let row = job_row(&shell.output, name).unwrap_or_else(|| {
        panic!(
            "no {name} row in {}",
            String::from_utf8_lossy(&shell.output)
        )
    });
    row.split_whitespace()
        .find(|word| word.len() == 8 && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("no sandbox uid in {row:?}"))
        .to_string()
}

/// One `/proc/<pid>/stat` field after the parenthesised command name, `0` being the run state.
fn stat_field(pid: libc::pid_t, index: usize) -> Option<libc::pid_t> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, tail) = stat.rsplit_once(") ")?;
    tail.split_whitespace().nth(index)?.parse().ok()
}

/// The process group `pid` belongs to, or `None` once it is gone.
fn process_group(pid: libc::pid_t) -> Option<libc::pid_t> {
    stat_field(pid, 2)
}

/// The foreground process group of `pid`'s controlling terminal.
///
/// Read through the process rather than with `tcgetpgrp`, because the terminal marsh took over is
/// not this test process's controlling terminal and the call would answer `ENOTTY`.
fn terminal_owner(pid: libc::pid_t) -> Option<libc::pid_t> {
    stat_field(pid, 5)
}

/// Sends `signal` to `pid` from the test process itself.
fn signal(pid: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` signals a process by id and has no memory-safety requirements.
    let sent = unsafe { libc::kill(pid, signal) };
    assert_eq!(sent, 0, "kill({pid}): {}", std::io::Error::last_os_error());
}

/// Runs `line` and waits for the prompt to come back.
fn run_line(shell: &mut PtyShell, line: &str) {
    shell.clear_output();
    shell.send(line.as_bytes());
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
}

/// The gated background command: it reports its pid, waits for `SIGUSR1`, then writes the seed.
const GATED_JOB: &str = "bash -c 'done=false; trap \"done=true\" USR1; printf \"ready:%s\\n\" \"$$\" >&3; until \"$done\"; do sleep 0.05; done'; printf 'done\\n' > src/file0.txt &graceful\n";

/// A plain `stop` closes an idle job at once and defers a busy one without waiting for it: the
/// command it found runs to completion and merges, and only then does the job go.
#[test]
fn graceful_stop_closes_idle_and_deferred_jobs() {
    let fixture = Fixture::cold("stop-graceful");
    let mut shell = PtyShell::start(&fixture);

    // An idle job: nothing is using it, so the stop completes inside the line that asked for it.
    shell.clear_output();
    shell.send(b"sd idle .\n");
    shell.wait_for("idle@.$ ", STARTUP_TIMEOUT);
    let idle_uid = job_uid(&mut shell, "idle@.$ ", "%idle");
    shell.clear_output();
    shell.send(b"stop idle\n");
    shell.wait_for("%idle closed", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    assert!(
        !fixture.persistence().work(&idle_uid).exists(),
        "a closed job's snapshot is reclaimed"
    );

    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    assert!(job_row(&shell.output, "%idle").is_none(), "its row is gone");
    assert!(
        job_row(&shell.output, "%main").is_some(),
        "and the prompt's job is the one that is left"
    );

    // Rejected targets: neither a name nothing answers to nor the console's own job.
    for (line, diagnostic) in [
        ("stop nosuchjob\n", "no such job: %nosuchjob"),
        ("stop main\n", "%main is the console's own job"),
        ("stop -f main\n", "%main is the console's own job"),
    ] {
        shell.clear_output();
        shell.send(line.as_bytes());
        shell.wait_for(diagnostic, STARTUP_TIMEOUT);
        shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    }
    run_line(&mut shell, "printf 'still here\\n' > src/file1.txt\n");
    shell.wait_for("%main committed seq=", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    // A busy job: the stop is accepted and answered at once, and the command keeps running.
    shell.clear_output();
    shell.send(GATED_JOB.as_bytes());
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while find_reported_pid(&shell.output, "ready:").is_none() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the gated pid; output: {}",
            String::from_utf8_lossy(&shell.output)
        );
        shell.read_available(deadline);
    }
    let gated = reported_pid(&shell.output, "ready:");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    let graceful_uid = job_uid(&mut shell, PROMPT, "%graceful");

    shell.clear_output();
    shell.send(b"stop graceful\n");
    shell.wait_for("%graceful will close when idle", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    assert!(is_running(gated), "the command it found is still running");
    shell.clear_output();
    shell.send(b"stop graceful\n");
    shell.wait_for("%graceful will close when idle", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    let row = job_row(&shell.output, "%graceful").expect("the closing job is still listed");
    assert!(row.contains(" running "), "and still running: {row:?}");

    shell.clear_output();
    shell.send(b"fg graceful\n");
    shell.wait_for("fg: %graceful is closing", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    // Releasing the gate lets the transaction finish normally, and the job closes behind it.
    run_line(&mut shell, &format!("kill -USR1 {gated}\n"));
    shell.wait_for("%graceful committed seq=", STARTUP_TIMEOUT);
    shell.wait_for("%graceful closed", STARTUP_TIMEOUT);
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed"),
        "done\n",
        "a graceful stop merges the command it let finish"
    );
    assert!(
        !fixture.persistence().work(&graceful_uid).exists(),
        "and reclaims the snapshot afterwards"
    );
    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    assert!(job_row(&shell.output, "%graceful").is_none());

    shell.send(b"exit\n");
    shell.wait_for_exit(EXIT_TIMEOUT);
}

/// `stop -f` kills the whole traced tree, takes the job out of the table without waiting for a
/// merge, rolls the transaction back, and reclaims the snapshot once the tree is provably gone.
#[test]
fn force_stop_kills_descendants_and_removes_the_job() {
    let fixture = Fixture::cold("stop-force");
    let mut shell = PtyShell::start(&fixture);
    let before = std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed");

    shell.clear_output();
    shell.send(
        b"printf 'partial\\n' > src/file0.txt; bash -c 'trap \"\" HUP TERM INT; sleep 60 & printf \"child:%s\\n\" \"$!\" >&3; printf \"ready:%s\\n\" \"$$\" >&3; wait' &forced\n",
    );
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while find_reported_pid(&shell.output, "child:").is_none()
        || find_reported_pid(&shell.output, "ready:").is_none()
    {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for job pids; output: {}",
            String::from_utf8_lossy(&shell.output)
        );
        shell.read_available(deadline);
    }
    let root = reported_pid(&shell.output, "ready:");
    let child = reported_pid(&shell.output, "child:");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    let uid = job_uid(&mut shell, PROMPT, "%forced");

    run_line(&mut shell, "stop -f forced\n");
    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    assert!(
        job_row(&shell.output, "%forced").is_none(),
        "a forced job leaves the table without waiting for its merge"
    );
    wait_not_running(root);
    wait_not_running(child);

    shell.wait_for("%forced failed exit=137", STARTUP_TIMEOUT);
    shell.wait_for("%forced closed", STARTUP_TIMEOUT);
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("reread seed"),
        before,
        "a forcibly aborted transaction merges nothing"
    );
    assert!(
        !fixture.persistence().work(&uid).exists(),
        "its snapshot is reclaimed once the tree is gone"
    );

    shell.send(b"exit\n");
    shell.wait_for_exit(EXIT_TIMEOUT);
}

/// A trace can hold a successful root exit while a descendant is still traced. The abort is owned
/// by the transaction, so that record may not commit what force just cancelled.
#[test]
fn force_stop_never_commits_a_partially_completed_trace() {
    let fixture = Fixture::cold("stop-partial");
    let mut shell = PtyShell::start(&fixture);
    let before = std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("read seed");

    shell.clear_output();
    shell.send(
        b"printf 'partial\\n' > src/file0.txt; bash -c 'sleep 60 & printf \"child:%s\\n\" \"$!\" >&3; printf \"ready:%s\\n\" \"$$\" >&3; exit 0' &partial\n",
    );
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while find_reported_pid(&shell.output, "child:").is_none()
        || find_reported_pid(&shell.output, "ready:").is_none()
    {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for job pids; output: {}",
            String::from_utf8_lossy(&shell.output)
        );
        shell.read_available(deadline);
    }
    let root = reported_pid(&shell.output, "ready:");
    let child = reported_pid(&shell.output, "child:");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    wait_not_running(root);
    assert!(is_running(child), "the descendant outlives its root");
    let row = job_row(&job_table(&mut shell), "%partial").expect("the job is still listed");
    assert!(
        row.contains(" running "),
        "and the job is still running, because its tracer is: {row:?}"
    );

    run_line(&mut shell, "stop -f partial\n");
    wait_not_running(child);
    shell.wait_for("%partial failed exit=137", STARTUP_TIMEOUT);
    assert_eq!(
        std::fs::read_to_string(fixture.seed("src/file0.txt")).expect("reread seed"),
        before,
        "the successful exit record in a partial trace does not override the abort"
    );

    shell.send(b"exit\n");
    shell.wait_for_exit(EXIT_TIMEOUT);
}

/// Fresh `jobs` output.
fn job_table(shell: &mut PtyShell) -> Vec<u8> {
    shell.clear_output();
    shell.send(b"jobs\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    shell.output.clone()
}

/// The suspend key is disabled for the whole session, including after a command has reconfigured
/// the terminal, so Ctrl-Z reaches a foreground job as an ordinary byte rather than as a stop.
#[test]
fn ctrl_z_does_not_suspend_foreground_work() {
    let fixture = Fixture::cold("stop-ctrl-z");
    let mut shell = PtyShell::start(&fixture);

    // At the prompt the line editor owns the keystroke; then a command puts the suspend character
    // back, which taking the terminal away from it has to undo.
    shell.send(b"\x1a");
    run_line(&mut shell, "stty sane\n");

    shell.clear_output();
    shell.send(
        b"bash -c 'trap \"echo progress >&3\" USR1; printf \"ready:%s\\n\" \"$$\" >&3; while :; do sleep 0.05; done'\n",
    );
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while find_reported_pid(&shell.output, "ready:").is_none() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the foreground pid; output: {}",
            String::from_utf8_lossy(&shell.output)
        );
        shell.read_available(deadline);
    }
    let foreground = reported_pid(&shell.output, "ready:");
    shell.clear_output();
    shell.send(b"\x1a");
    std::thread::sleep(Duration::from_millis(200));

    // A live pid proves nothing — a suspended process has one too. An acknowledged signal proves
    // the command is still running.
    signal(foreground, libc::SIGUSR1);
    shell.wait_for("progress", DESCENDANT_TIMEOUT);
    let observed = String::from_utf8_lossy(&shell.output).into_owned();
    assert!(
        !observed.contains(PROMPT),
        "marsh did not take the terminal back: {observed:?}"
    );
    assert_eq!(
        terminal_owner(foreground),
        process_group(foreground),
        "the job's process group still owns the terminal"
    );

    shell.send(b"\x03");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);
    run_line(&mut shell, "printf 'usable\\n' > src/file2.txt\n");
    shell.wait_for("%main committed seq=", STARTUP_TIMEOUT);
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    shell.send(b"exit\n");
    shell.wait_for_exit(EXIT_TIMEOUT);
    shell.assert_terminal_restored();
}
