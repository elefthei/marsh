//! Terminal utilities.

use crate::{error, openfiles, sys, terminal};
use std::{io::IsTerminal, os::fd::AsFd, path::PathBuf};

/// Terminal configuration.
#[derive(Clone, Debug)]
pub struct Config {
    termios: nix::sys::termios::Termios,
}

impl Config {
    /// Creates a new `Config` from the actual terminal attributes of the terminal associated
    /// with the given file descriptor.
    ///
    /// # Arguments
    ///
    /// * `file` - A reference to the open terminal.
    pub fn from_term(file: &openfiles::OpenFile) -> Result<Self, error::Error> {
        let fd = file.try_borrow_as_fd()?;
        let termios = nix::sys::termios::tcgetattr(fd)?;
        Ok(Self { termios })
    }

    /// Applies the terminal settings to the terminal associated with the given file descriptor.
    ///
    /// # Arguments
    ///
    /// * `file` - A reference to the open terminal.
    pub fn apply_to_term(&self, file: &openfiles::OpenFile) -> Result<(), error::Error> {
        let fd = file.try_borrow_as_fd()?;
        nix::sys::termios::tcsetattr(fd, nix::sys::termios::SetArg::TCSANOW, &self.termios)?;
        Ok(())
    }

    /// Applies the given high-level terminal settings to this configuration. Does not modify any
    /// terminal itself.
    ///
    /// # Arguments
    ///
    /// * `settings` - The high-level terminal settings to apply to this configuration.
    pub fn update(&mut self, settings: &terminal::Settings) {
        if let Some(echo_input) = &settings.echo_input {
            if *echo_input {
                self.termios.local_flags |= nix::sys::termios::LocalFlags::ECHO;
            } else {
                self.termios.local_flags -= nix::sys::termios::LocalFlags::ECHO;
            }
        }

        if let Some(line_input) = &settings.line_input {
            if *line_input {
                self.termios.local_flags |= nix::sys::termios::LocalFlags::ICANON;
            } else {
                self.termios.local_flags -= nix::sys::termios::LocalFlags::ICANON;
            }
        }

        if let Some(interrupt_signals) = &settings.interrupt_signals {
            if *interrupt_signals {
                self.termios.local_flags |= nix::sys::termios::LocalFlags::ISIG;
            } else {
                self.termios.local_flags -= nix::sys::termios::LocalFlags::ISIG;
            }
        }

        if let Some(output_nl_as_nlcr) = &settings.output_nl_as_nlcr {
            if *output_nl_as_nlcr {
                self.termios.output_flags |=
                    nix::sys::termios::OutputFlags::OPOST | nix::sys::termios::OutputFlags::ONLCR;
            } else {
                self.termios.output_flags -= nix::sys::termios::OutputFlags::ONLCR;
            }
        }
    }
}

/// Guard that disables the terminal's suspend character and restores it on drop.
///
/// Disabling `VSUSP` is the terminal-level way to take Ctrl-Z away from a whole session: the
/// character never becomes a `SIGTSTP` at all, so it survives a child that installs its own signal
/// disposition and an `exec` that resets one. [`crate::terminal::AutoModeGuard`] is not a
/// substitute — it restores a whole snapshot, overwriting every unrelated mode change made while it
/// was alive.
#[cfg(target_os = "linux")]
pub struct SuspendKeyGuard {
    /// The terminal whose suspend character was replaced.
    file: openfiles::OpenFile,
    /// The character that was there before, restored on drop.
    previous: nix::libc::cc_t,
}

#[cfg(target_os = "linux")]
impl SuspendKeyGuard {
    /// Disables the suspend character on `file`, remembering what it was.
    ///
    /// # Arguments
    ///
    /// * `file` - The terminal to control. Held for the guard's lifetime.
    ///
    /// # Errors
    ///
    /// Fails when `file` is not a terminal or its attributes cannot be read or written.
    pub fn new(file: openfiles::OpenFile) -> Result<Self, error::Error> {
        let previous = replace_suspend_char(&file, nix::sys::termios::_POSIX_VDISABLE)?;
        Ok(Self { file, previous })
    }

    /// Disables the suspend character again, without taking a second guard.
    ///
    /// For reasserting the setting after something else has reconfigured the terminal: a completed
    /// `stty sane` restores the suspend character, and the original guard still holds the value to
    /// put back at the end of the session.
    ///
    /// # Arguments
    ///
    /// * `file` - The terminal to control.
    ///
    /// # Errors
    ///
    /// Fails when `file` is not a terminal or its attributes cannot be read or written.
    pub fn disable(file: &openfiles::OpenFile) -> Result<(), error::Error> {
        replace_suspend_char(file, nix::sys::termios::_POSIX_VDISABLE)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for SuspendKeyGuard {
    fn drop(&mut self) {
        // Against freshly read attributes, so restoring one character does not undo whatever else
        // the session changed. Best-effort, like `AutoModeGuard::drop`: a terminal that has gone
        // away is nothing a destructor can act on.
        let _ = replace_suspend_char(&self.file, self.previous);
    }
}

/// Writes `value` as the terminal's suspend character, returning the one it replaced.
#[cfg(target_os = "linux")]
fn replace_suspend_char(
    file: &openfiles::OpenFile,
    value: nix::libc::cc_t,
) -> Result<nix::libc::cc_t, error::Error> {
    let mut config = Config::from_term(file)?;
    let index = nix::sys::termios::SpecialCharacterIndices::VSUSP as usize;
    let previous = config.termios.control_chars[index];
    config.termios.control_chars[index] = value;
    config.apply_to_term(file)?;
    Ok(previous)
}

/// Disables the suspend character on the terminal behind `fd`.
///
/// The descriptor-shaped counterpart of [`replace_suspend_char`], which needs an
/// [`openfiles::OpenFile`] this module does not have while it is still assembling a terminal.
#[cfg(target_os = "linux")]
fn disable_suspend_char(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    let mut termios = nix::sys::termios::tcgetattr(fd)?;
    let index = nix::sys::termios::SpecialCharacterIndices::VSUSP as usize;
    termios.control_chars[index] = nix::sys::termios::_POSIX_VDISABLE;
    nix::sys::termios::tcsetattr(fd, nix::sys::termios::SetArg::TCSANOW, &termios)?;
    Ok(())
}

/// Opens a private pseudoterminal pair sized `rows` by `cols`, returning `(master, slave)`.
///
/// The slave is the end handed to a child as its standard descriptors and controlling terminal;
/// the master is the end the shell reads and writes. It is obtained with the `TIOCGPTPEER` ioctl
/// rather than `openpty` or `ptsname` followed by `open`: those hand back a descriptor without
/// `O_CLOEXEC`, and a concurrent `fork`/`exec` between the open and a later `FD_CLOEXEC` change
/// leaks the terminal into an unrelated child. `TIOCGPTPEER` applies the flag atomically.
///
/// The master is opened `O_NONBLOCK` so an async reactor can poll it for readiness; the slave is
/// left blocking, because a child writing to a full terminal buffer must wait rather than lose
/// output to `EAGAIN`. Neither end becomes this process's controlling terminal (`O_NOCTTY`), and
/// packet mode is left off.
///
/// The requested size is applied to the slave, which both ends observe: the pair shares one
/// `winsize`. The suspend character is disabled on the new terminal, so Ctrl-Z reaches the job as
/// an ordinary byte instead of becoming a `SIGTSTP` no child disposition can take back.
///
/// # Arguments
///
/// * `rows` - The terminal height, in character cells.
/// * `cols` - The terminal width, in character cells.
///
/// # Errors
///
/// Fails when no pseudoterminal can be allocated, when the master cannot be granted or unlocked,
/// when the kernel refuses `TIOCGPTPEER`, or when the initial size or attributes cannot be
/// applied. Every descriptor opened along the way is closed before returning an error.
#[cfg(target_os = "linux")]
pub fn open_pty(
    rows: u16,
    cols: u16,
) -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let master = nix::pty::posix_openpt(
        nix::fcntl::OFlag::O_RDWR
            | nix::fcntl::OFlag::O_CLOEXEC
            | nix::fcntl::OFlag::O_NOCTTY
            | nix::fcntl::OFlag::O_NONBLOCK,
    )?;
    nix::pty::grantpt(&master)?;
    nix::pty::unlockpt(&master)?;

    // `PtyMaster` already owns its descriptor, and so does the `OwnedFd` it converts into, so
    // every early return below still closes the master.
    let master = std::os::fd::OwnedFd::from(master);

    let request = libc::TIOCGPTPEER;
    let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY;
    // SAFETY:
    // This is calling a libc function on a live, unlocked pseudoterminal master. `TIOCGPTPEER`
    // takes its argument by value, so no pointer is handed to the kernel.
    let slave = unsafe { libc::ioctl(master.as_raw_fd(), request, flags) };
    if slave < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY:
    // `slave` is a fresh descriptor the kernel just returned and nothing else owns it yet.
    let slave = unsafe { std::os::fd::OwnedFd::from_raw_fd(slave) };

    resize_pty(slave.as_fd(), rows, cols)?;
    disable_suspend_char(slave.as_fd())?;

    Ok((master, slave))
}

/// Resizes the terminal behind `fd` to `rows` by `cols`.
///
/// Either half of a pseudoterminal pair may be passed: they share one `winsize`, so a resize
/// through the master is what the child sees through the slave.
///
/// # Arguments
///
/// * `fd` - A descriptor open on the terminal to resize.
/// * `rows` - The new terminal height, in character cells.
/// * `cols` - The new terminal width, in character cells.
///
/// # Errors
///
/// Fails when `fd` is not a terminal or the kernel rejects the `TIOCSWINSZ` request.
#[cfg(target_os = "linux")]
pub fn resize_pty(fd: std::os::fd::BorrowedFd<'_>, rows: u16, cols: u16) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let request = libc::TIOCSWINSZ;
    // SAFETY:
    // This is calling a libc function with a descriptor kept alive by the borrow and a pointer to
    // a live `winsize`, which is exactly what `TIOCSWINSZ` reads.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, &raw const size) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Reads the size of the terminal behind `fd` as `(rows, cols)`.
///
/// Rows come first: the pair is returned in the order [`resize_pty`] and
/// [`open_pty`] take it, so a caller can pass it straight back without transposing it.
///
/// # Arguments
///
/// * `fd` - A descriptor open on the terminal to measure.
///
/// # Errors
///
/// Fails when `fd` is not a terminal or the kernel rejects the `TIOCGWINSZ` request.
#[cfg(target_os = "linux")]
pub fn terminal_size(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<(u16, u16)> {
    use std::os::fd::AsRawFd as _;

    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let request = libc::TIOCGWINSZ;
    // SAFETY:
    // This is calling a libc function with a descriptor kept alive by the borrow and a pointer to
    // a live `winsize`, which is exactly what `TIOCGWINSZ` fills in.
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, &raw mut size) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok((size.ws_row, size.ws_col))
}

/// Get the process ID of this process's parent.
pub fn get_parent_process_id() -> Option<sys::process::ProcessId> {
    Some(nix::unistd::getppid().as_raw())
}

/// Get the process group ID for this process's process group.
pub fn get_process_group_id() -> Option<sys::process::ProcessId> {
    Some(nix::unistd::getpgrp().as_raw())
}

/// Get the foreground process ID of the attached terminal.
pub fn get_foreground_pid() -> Option<sys::process::ProcessId> {
    nix::unistd::tcgetpgrp(std::io::stdin())
        .ok()
        .map(|pgid| pgid.as_raw())
}

/// Move the specified process to the foreground of the attached terminal.
pub fn move_to_foreground(pid: sys::process::ProcessId) -> Result<(), error::Error> {
    nix::unistd::tcsetpgrp(std::io::stdin(), nix::unistd::Pid::from_raw(pid))?;
    Ok(())
}

/// Moves the current process to the foreground of the attached terminal.
// This function needs to return `std::io::Error` so that the OS error code can be recovered.
pub fn move_self_to_foreground() -> Result<(), std::io::Error> {
    if std::io::stdin().is_terminal() {
        let pgid = nix::unistd::getpgid(None)?;

        // TODO(jobs): This sometimes fails with ENOTTY even though we checked that stdin is a
        // terminal. We should investigate why this is happening.
        let _ = nix::unistd::tcsetpgrp(std::io::stdin(), pgid);
    }

    Ok(())
}

/// Tries to get the path of the terminal device associated with the attached terminal.
/// Returns `None` if there is no terminal attached or the lookup failed.
pub fn try_get_terminal_device_path() -> Option<PathBuf> {
    nix::unistd::ttyname(std::io::stdin()).ok()
}

#[allow(
    clippy::expect_used,
    reason = "a terminal test has nothing to recover to"
)]
#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;

    /// The suspend character is the only thing the guard owns. Restoring a whole snapshot instead
    /// would silently revert whatever the session changed while the guard was alive — which is
    /// exactly what a line editor does to `ECHO` on every prompt.
    #[cfg(target_os = "linux")]
    #[test]
    fn suspend_key_guard_restores_only_vsusp() {
        let pty = nix::pty::openpty(None, None).expect("open a private pty");
        // The master is retained for the whole test: closing it would hang up the slave.
        let _master = pty.master;
        let terminal: openfiles::OpenFile = std::fs::File::from(pty.slave).into();
        let index = nix::sys::termios::SpecialCharacterIndices::VSUSP as usize;

        let original = Config::from_term(&terminal).expect("read the original attributes");
        let suspend_char = original.termios.control_chars[index];
        let echo_before = original
            .termios
            .local_flags
            .contains(nix::sys::termios::LocalFlags::ECHO);

        let guard = SuspendKeyGuard::new(terminal.clone()).expect("disable the suspend character");
        let disabled = Config::from_term(&terminal).expect("read the guarded attributes");
        assert_eq!(
            disabled.termios.control_chars[index],
            nix::sys::termios::_POSIX_VDISABLE,
            "the guard disables the suspend character while it lives"
        );

        let settings = terminal::Settings::builder()
            .echo_input(!echo_before)
            .build();
        let mut toggled = disabled;
        toggled.update(&settings);
        toggled.apply_to_term(&terminal).expect("toggle ECHO");
        drop(guard);

        let restored = Config::from_term(&terminal).expect("read the restored attributes");
        assert_eq!(
            restored.termios.control_chars[index], suspend_char,
            "the suspend character comes back"
        );
        assert_eq!(
            restored
                .termios
                .local_flags
                .contains(nix::sys::termios::LocalFlags::ECHO),
            !echo_before,
            "and the unrelated change made meanwhile survives"
        );
    }

    /// A job's terminal is created at the mux's size and resized in place afterwards, so both
    /// halves must agree: a resize applied to the master that the slave did not observe would
    /// leave every child reading a stale `TIOCGWINSZ`. The blocking-ness of each end and the
    /// disabled suspend character are the other properties the job runtime depends on.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_new_pty_reports_the_size_it_was_opened_with() {
        use std::os::fd::AsRawFd as _;

        let (master, slave) = open_pty(24, 80).expect("open a private pty");

        assert_eq!(
            terminal_size(master.as_fd()).expect("measure the master"),
            (24, 80),
            "the master reports the size the pair was opened with"
        );
        assert_eq!(
            terminal_size(slave.as_fd()).expect("measure the slave"),
            (24, 80),
            "and so does the slave the child would be given"
        );

        resize_pty(master.as_fd(), 30, 100).expect("resize through the master");
        assert_eq!(
            terminal_size(master.as_fd()).expect("re-measure the master"),
            (30, 100),
            "a resize is retained"
        );
        assert_eq!(
            terminal_size(slave.as_fd()).expect("re-measure the slave"),
            (30, 100),
            "and the two descriptors share one window size"
        );

        let attributes =
            nix::sys::termios::tcgetattr(slave.as_fd()).expect("read the slave attributes");
        let index = nix::sys::termios::SpecialCharacterIndices::VSUSP as usize;
        assert_eq!(
            attributes.control_chars[index],
            nix::sys::termios::_POSIX_VDISABLE,
            "Ctrl-Z never becomes a SIGTSTP on a freshly opened job terminal"
        );

        // SAFETY:
        // This is calling a libc function to read the status flags of a live descriptor.
        let master_flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert!(master_flags >= 0, "read the master status flags");
        assert_ne!(
            master_flags & libc::O_NONBLOCK,
            0,
            "the master is non-blocking, so an async reactor can poll it"
        );

        // SAFETY:
        // This is calling a libc function to read the status flags of a live descriptor.
        let slave_flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
        assert!(slave_flags >= 0, "read the slave status flags");
        assert_eq!(
            slave_flags & libc::O_NONBLOCK,
            0,
            "the slave stays blocking, so a child's output is not lost to EAGAIN"
        );
    }
}
