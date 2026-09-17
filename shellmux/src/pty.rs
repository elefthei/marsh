//! Pseudoterminals, and the suspend character a job's terminal does not have.
//!
//! A job runs attached to its own pseudoterminal: the shell owns the master, the traced child gets
//! the slave as its standard descriptors and controlling terminal. Two things about that terminal
//! are not what a default `openpty` would give, and both are load-bearing:
//!
//! * The descriptors are opened with `O_CLOEXEC` atomically, so a concurrent `fork`/`exec`
//!   elsewhere in the process cannot leak a job's terminal into an unrelated child.
//! * The suspend character is disabled, so Ctrl-Z reaches the job as an ordinary byte instead of
//!   becoming a `SIGTSTP` that no child disposition can take back.
//!
//! [`SuspendKeyGuard`] does the same to the *console's* terminal for the length of a session, and
//! puts back exactly the one character it took — never a whole snapshot, which would silently
//! revert everything else the session changed meanwhile.

#![cfg(target_os = "linux")]

use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

use brush_core::openfiles::OpenFile;

/// Guard that disables the terminal's suspend character and restores it on drop.
///
/// Disabling `VSUSP` is the terminal-level way to take Ctrl-Z away from a whole session: the
/// character never becomes a `SIGTSTP` at all, so it survives a child that installs its own signal
/// disposition and an `exec` that resets one. `brush_core::terminal::AutoModeGuard` is not a
/// substitute — it restores a whole snapshot, overwriting every unrelated mode change made while
/// it was alive.
pub struct SuspendKeyGuard {
    /// The terminal whose suspend character was replaced.
    file: OpenFile,
    /// The character that was there before, restored on drop.
    previous: libc::cc_t,
}

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
    pub fn new(file: OpenFile) -> Result<Self, brush_core::Error> {
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
    pub fn disable(file: &OpenFile) -> Result<(), brush_core::Error> {
        replace_suspend_char(file, nix::sys::termios::_POSIX_VDISABLE)?;
        Ok(())
    }
}

impl Drop for SuspendKeyGuard {
    fn drop(&mut self) {
        // Against freshly read attributes, so restoring one character does not undo whatever else
        // the session changed. Best-effort: a terminal that has gone away is nothing a destructor
        // can act on.
        let _ = replace_suspend_char(&self.file, self.previous);
    }
}

/// Writes `value` as the terminal's suspend character, returning the one it replaced.
///
/// The attributes are read and written directly rather than through `brush_core::sys::terminal::
/// Config`, whose `termios` field is private to brush-core: only one control character changes
/// here, and a round trip through a settings struct would carry every other mode with it.
fn replace_suspend_char(
    file: &OpenFile,
    value: libc::cc_t,
) -> Result<libc::cc_t, brush_core::Error> {
    let fd = file.try_borrow_as_fd()?;
    let mut termios = nix::sys::termios::tcgetattr(fd)?;
    let index = nix::sys::termios::SpecialCharacterIndices::VSUSP as usize;
    let previous = termios.control_chars[index];
    termios.control_chars[index] = value;
    nix::sys::termios::tcsetattr(fd, nix::sys::termios::SetArg::TCSANOW, &termios)?;
    Ok(previous)
}

/// Disables the suspend character on the terminal behind `fd`.
///
/// The descriptor-shaped counterpart of [`replace_suspend_char`], for a terminal that is still
/// being assembled and has no [`OpenFile`] yet.
fn disable_suspend_char(fd: BorrowedFd<'_>) -> std::io::Result<()> {
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
pub fn open_pty(rows: u16, cols: u16) -> std::io::Result<(OwnedFd, OwnedFd)> {
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
    let master = OwnedFd::from(master);

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
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };

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
pub fn resize_pty(fd: BorrowedFd<'_>, rows: u16, cols: u16) -> std::io::Result<()> {
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
/// Rows come first: the pair is returned in the order [`resize_pty`] and [`open_pty`] take it, so
/// a caller can pass it straight back without transposing it.
///
/// # Arguments
///
/// * `fd` - A descriptor open on the terminal to measure.
///
/// # Errors
///
/// Fails when `fd` is not a terminal or the kernel rejects the `TIOCGWINSZ` request.
pub fn terminal_size(fd: BorrowedFd<'_>) -> std::io::Result<(u16, u16)> {
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

#[allow(
    clippy::expect_used,
    reason = "a terminal test has nothing to recover to"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The suspend character is the only thing the guard owns. Restoring a whole snapshot instead
    /// would silently revert whatever the session changed while the guard was alive — which is
    /// exactly what a line editor does to `ECHO` on every prompt.
    #[test]
    fn suspend_key_guard_restores_only_vsusp() {
        let pty = nix::pty::openpty(None, None).expect("open a private pty");
        // The master is retained for the whole test: closing it would hang up the slave.
        let _master = pty.master;
        let terminal: OpenFile = std::fs::File::from(pty.slave).into();
        let index = nix::sys::termios::SpecialCharacterIndices::VSUSP as usize;

        let borrowed = terminal.try_borrow_as_fd().expect("borrow the terminal");
        let original =
            nix::sys::termios::tcgetattr(borrowed).expect("read the original attributes");
        let suspend_char = original.control_chars[index];
        let echo_before = original
            .local_flags
            .contains(nix::sys::termios::LocalFlags::ECHO);

        let guard = SuspendKeyGuard::new(terminal.clone()).expect("disable the suspend character");
        let borrowed = terminal.try_borrow_as_fd().expect("borrow the terminal");
        let disabled = nix::sys::termios::tcgetattr(borrowed).expect("read the guarded attributes");
        assert_eq!(
            disabled.control_chars[index],
            nix::sys::termios::_POSIX_VDISABLE,
            "the guard disables the suspend character while it lives"
        );

        // An unrelated mode change, made while the guard is alive, that the guard must not undo.
        let mut toggled = disabled;
        toggled
            .local_flags
            .set(nix::sys::termios::LocalFlags::ECHO, !echo_before);
        nix::sys::termios::tcsetattr(borrowed, nix::sys::termios::SetArg::TCSANOW, &toggled)
            .expect("toggle ECHO");
        drop(guard);

        let borrowed = terminal.try_borrow_as_fd().expect("borrow the terminal");
        let restored =
            nix::sys::termios::tcgetattr(borrowed).expect("read the restored attributes");
        assert_eq!(
            restored.control_chars[index], suspend_char,
            "the suspend character comes back"
        );
        assert_eq!(
            restored
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
    #[test]
    fn a_new_pty_reports_the_size_it_was_opened_with() {
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
