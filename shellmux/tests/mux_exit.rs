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

    /// Confirms the terminal modes marsh changed were restored.
    fn assert_terminal_restored(&self) {
        let mut current = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `slave` remains an open terminal and `current` is writable termios storage.
        let result = unsafe { libc::tcgetattr(self.slave.as_raw_fd(), current.as_mut_ptr()) };
        assert_eq!(result, 0, "tcgetattr after exit");
        // SAFETY: `tcgetattr` initialized `current` after succeeding.
        let current = unsafe { current.assume_init() };
        let mask = libc::ICANON | libc::ECHO | libc::ISIG;
        assert_eq!(current.c_lflag & mask, self.original_modes & mask);
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
    let mut fixture = Fixture::new(label);
    fixture.finish_mux();
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
    let mut fixture = Fixture::new("exit-killed");
    fixture.finish_mux();
    let mut shell = PtyShell::start(&fixture);
    let (root, child) = start_live_job(&mut shell);

    shell.child.kill().expect("SIGKILL marsh");
    shell.wait_for_exit(EXIT_TIMEOUT);
    wait_not_running(root);
    wait_not_running(child);
}

#[test]
fn committed_state_is_reclaimed_only_by_the_next_startup() {
    let mut fixture = Fixture::new("exit-persistence");
    fixture.finish_mux();
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
    let snapshot = fixture.session().work(uid);

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
    let mut fixture = Fixture::new("exit-history");
    fixture.finish_mux();
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

    let history = fixture.session().meta().join("console.history");
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
    let mut fixture = Fixture::new("exit-history-fifo");
    fixture.finish_mux();
    let mut shell = PtyShell::start(&fixture);
    shell.clear_output();
    shell.send(b"true\n");
    shell.wait_for(PROMPT, STARTUP_TIMEOUT);

    let history = fixture.session().meta().join("console.history");
    let saved = fixture.session().meta().join("console.history.saved");
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
