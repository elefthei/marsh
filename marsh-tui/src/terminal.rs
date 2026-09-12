//! The wire protocol between a job's emulated terminal and the real one.
//!
//! Three directions meet here and none of them may be confused with another: real key and mouse
//! events become the bytes a child expects, a child's own queries become the replies it is waiting
//! for, and neither is ever executed against the terminal this process is drawing on.
//!
//! Every coordinate on this side is the *emulated* screen's. A child asking where its cursor is
//! must be told where it is inside its own job, not where that job happens to be drawn.

use std::fmt::Write as _;

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use smallvec::SmallVec;
use vt100::{MouseProtocolEncoding, MouseProtocolMode, Screen};

/// One packet of input bytes, inline for the keystroke-sized traffic that dominates.
pub type KeyBytes = SmallVec<[u8; 32]>;

/// The replies a job's own escape sequences asked for, queued until its writer drains them.
///
/// A query is answered from the emulated screen even while that job is hidden: a child blocked on
/// a cursor-position report would otherwise hang because the user looked at another tab.
#[derive(Debug, Default)]
pub struct TerminalReplies {
    /// Reply bytes not yet handed to the job's input writer.
    pending: Vec<u8>,
}

impl TerminalReplies {
    /// Takes everything queued, leaving the queue empty.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// Queues one reply.
    fn reply(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }
}

/// The first value of a CSI parameter, or `0` when the parameter was omitted.
fn param(params: &[&[u16]], index: usize) -> u16 {
    params
        .get(index)
        .and_then(|values| values.first())
        .copied()
        .unwrap_or(0)
}

impl vt100::Callbacks for TerminalReplies {
    fn unhandled_csi(
        &mut self,
        screen: &mut Screen,
        i1: Option<u8>,
        _i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        let private = i1 == Some(b'?');
        match c {
            'n' => match param(params, 0) {
                // Device status report: the terminal is operational.
                5 if !private => self.reply(b"\x1b[0n"),
                6 => {
                    let (row, col) = screen.cursor_position();
                    let report = if private {
                        format!("\x1b[?{};{}R", row + 1, col + 1)
                    } else {
                        format!("\x1b[{};{}R", row + 1, col + 1)
                    };
                    self.reply(report.as_bytes());
                }
                _ => {}
            },
            'c' => {
                if i1 == Some(b'>') {
                    self.reply(b"\x1b[>0;0;0c");
                } else if param(params, 0) == 0 {
                    self.reply(PRIMARY_DEVICE_ATTRIBUTES);
                }
            }
            't' if param(params, 0) == 18 => {
                let (rows, cols) = screen.size();
                self.reply(format!("\x1b[8;{rows};{cols}t").as_bytes());
            }
            _ => {}
        }
    }

    fn unhandled_escape(&mut self, _: &mut Screen, i1: Option<u8>, _i2: Option<u8>, b: u8) {
        if i1.is_none() && b == b'Z' {
            self.reply(PRIMARY_DEVICE_ATTRIBUTES);
        }
    }

    fn unhandled_osc(&mut self, _: &mut Screen, params: &[&[u8]]) {
        // Only the two color queries are answered. A title, an icon name or a clipboard request is
        // about the *real* terminal, which is this process's and not a job's to reconfigure.
        if params.get(1).copied() != Some(b"?") {
            return;
        }
        match params.first().copied() {
            Some(b"10") => self.reply(b"\x1b]10;rgb:ffff/ffff/ffff\x07"),
            Some(b"11") => self.reply(b"\x1b]11;rgb:0000/0000/0000\x07"),
            _ => {}
        }
    }
}

/// What this emulator claims to be: a VT100 with an advanced video option, which is what vt100
/// implements.
const PRIMARY_DEVICE_ATTRIBUTES: &[u8] = b"\x1b[?1;2c";

/// The `1 + shift + 2*alt + 4*ctrl` parameter a modified CSI key carries, or `1` for none.
const fn modifier_parameter(modifiers: KeyModifiers) -> u8 {
    let mut value = 1;
    if modifiers.contains(KeyModifiers::SHIFT) {
        value += 1;
    }
    if modifiers.contains(KeyModifiers::ALT) {
        value += 2;
    }
    if modifiers.contains(KeyModifiers::CONTROL) {
        value += 4;
    }
    value
}

/// The control byte Ctrl with `c` produces, or `None` when the combination has none.
const fn control_byte(c: char) -> Option<u8> {
    match c {
        'a'..='z' => Some(c as u8 - 0x60),
        'A'..='Z' => Some(c as u8 - 0x40),
        ' ' | '@' => Some(0),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        // Crossterm decodes 0x1c-0x1f as Ctrl with '4'-'7', because that is what a terminal sends
        // for Ctrl-\, Ctrl-], Ctrl-^ and Ctrl-_. Encoding the same way is what makes a doubled
        // prefix reach the child as the byte the user asked for.
        '4' => Some(0x1c),
        '5' => Some(0x1d),
        '6' => Some(0x1e),
        '7' => Some(0x1f),
        '?' => Some(0x7f),
        _ => None,
    }
}

/// The tilde-terminated CSI number an editing key carries.
const fn editing_key(code: KeyCode) -> Option<u8> {
    match code {
        KeyCode::Insert => Some(2),
        KeyCode::Delete => Some(3),
        KeyCode::PageUp => Some(5),
        KeyCode::PageDown => Some(6),
        _ => None,
    }
}

/// The final byte a cursor key uses in both its CSI and its SS3 form.
const fn cursor_key(code: KeyCode) -> Option<u8> {
    match code {
        KeyCode::Up => Some(b'A'),
        KeyCode::Down => Some(b'B'),
        KeyCode::Right => Some(b'C'),
        KeyCode::Left => Some(b'D'),
        KeyCode::Home => Some(b'H'),
        KeyCode::End => Some(b'F'),
        _ => None,
    }
}

/// The CSI number an F5-F12 key carries.
const fn function_key(number: u8) -> Option<u8> {
    match number {
        5 => Some(15),
        6 => Some(17),
        7 => Some(18),
        8 => Some(19),
        9 => Some(20),
        10 => Some(21),
        11 => Some(23),
        12 => Some(24),
        _ => None,
    }
}

/// The bytes `key` sends to a child whose screen is `screen`.
///
/// Empty for a key release, a modifier-only key, and every extended key ordinary Crossterm
/// reporting cannot tell apart from one already encoded here: inventing bytes for a key that was
/// never pressed is worse than dropping it.
#[must_use]
pub fn encode_key(key: KeyEvent, screen: &Screen) -> KeyBytes {
    let mut out = KeyBytes::new();
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return out;
    }
    let modifier = modifier_parameter(key.modifiers);

    if let Some(final_byte) = cursor_key(key.code) {
        if modifier > 1 {
            out.extend_from_slice(format!("\x1b[1;{modifier}").as_bytes());
        } else if screen.application_cursor() {
            out.extend_from_slice(b"\x1bO");
        } else {
            out.extend_from_slice(b"\x1b[");
        }
        out.push(final_byte);
        return out;
    }
    if let Some(number) = editing_key(key.code) {
        if modifier > 1 {
            out.extend_from_slice(format!("\x1b[{number};{modifier}~").as_bytes());
        } else {
            out.extend_from_slice(format!("\x1b[{number}~").as_bytes());
        }
        return out;
    }
    if let KeyCode::F(number) = key.code {
        if (1..=4).contains(&number) {
            let final_byte = b'P' + (number - 1);
            if modifier > 1 {
                out.extend_from_slice(format!("\x1b[1;{modifier}").as_bytes());
            } else {
                out.extend_from_slice(b"\x1bO");
            }
            out.push(final_byte);
        } else if let Some(csi) = function_key(number) {
            if modifier > 1 {
                out.extend_from_slice(format!("\x1b[{csi};{modifier}~").as_bytes());
            } else {
                out.extend_from_slice(format!("\x1b[{csi}~").as_bytes());
            }
        }
        return out;
    }
    if key.code == KeyCode::KeypadBegin {
        out.extend_from_slice(if screen.application_keypad() {
            b"\x1bOE"
        } else {
            b"\x1b[E"
        });
        return out;
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let mut body = KeyBytes::new();
    match key.code {
        KeyCode::Char(c) => {
            if let Some(byte) = control_byte(c).filter(|_| ctrl) {
                body.push(byte);
            } else {
                let mut buffer = [0u8; 4];
                body.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
        KeyCode::Null => body.push(0),
        KeyCode::Enter => body.push(b'\r'),
        KeyCode::Backspace => body.push(0x7f),
        KeyCode::Tab => body.push(b'\t'),
        KeyCode::BackTab => body.extend_from_slice(b"\x1b[Z"),
        KeyCode::Esc => body.push(0x1b),
        _ => return out,
    }
    // Alt is a prefixed escape only for the character and control bytes; a CSI key carries it in
    // its modifier parameter instead, and prefixing there would produce two keys.
    if key.modifiers.contains(KeyModifiers::ALT) {
        out.push(0x1b);
    }
    out.extend_from_slice(&body);
    out
}

/// The button/modifier code a mouse report carries, or `None` for an event with no encoding.
fn mouse_code(event: MouseEvent) -> (u8, bool) {
    let button = |button: MouseButton| match button {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
    };
    let (mut code, release) = match event.kind {
        MouseEventKind::Down(which) => (button(which), false),
        MouseEventKind::Up(which) => (button(which), true),
        MouseEventKind::Drag(which) => (button(which) + 32, false),
        MouseEventKind::Moved => (35, false),
        MouseEventKind::ScrollUp => (64, false),
        MouseEventKind::ScrollDown => (65, false),
        MouseEventKind::ScrollLeft => (66, false),
        MouseEventKind::ScrollRight => (67, false),
    };
    if event.modifiers.contains(KeyModifiers::SHIFT) {
        code += 4;
    }
    if event.modifiers.contains(KeyModifiers::ALT) {
        code += 8;
    }
    if event.modifiers.contains(KeyModifiers::CONTROL) {
        code += 16;
    }
    (code, release)
}

/// Whether `screen`'s mouse mode asks to hear about `event` at all.
fn mouse_wanted(event: MouseEvent, screen: &Screen) -> bool {
    match screen.mouse_protocol_mode() {
        MouseProtocolMode::None => false,
        MouseProtocolMode::Press | MouseProtocolMode::PressRelease => {
            !matches!(event.kind, MouseEventKind::Drag(_) | MouseEventKind::Moved)
        }
        MouseProtocolMode::ButtonMotion => !matches!(event.kind, MouseEventKind::Moved),
        MouseProtocolMode::AnyMotion => true,
    }
}

/// The mouse report `event` sends to a child, for a job-local zero-based `row`/`col`.
///
/// `None` when the child asked for no mouse reports, when it asked only for events of another
/// kind, or when the position cannot be represented in the encoding it chose — a legacy report
/// that wrapped past column 223 would name a cell the user never clicked.
#[must_use]
pub fn encode_mouse(event: MouseEvent, row: u16, col: u16, screen: &Screen) -> Option<KeyBytes> {
    if !mouse_wanted(event, screen) {
        return None;
    }
    let (code, release) = mouse_code(event);
    let (row, col) = (u32::from(row) + 1, u32::from(col) + 1);
    let mut out = KeyBytes::new();
    match screen.mouse_protocol_encoding() {
        MouseProtocolEncoding::Default => {
            let code = if release { 3 } else { code };
            let cell = |value: u32| u8::try_from(value + 32).ok();
            out.extend_from_slice(b"\x1b[M");
            out.push(code.checked_add(32)?);
            out.push(cell(col)?);
            out.push(cell(row)?);
        }
        MouseProtocolEncoding::Utf8 => {
            let code = if release { 3 } else { code };
            let mut buffer = [0u8; 4];
            out.extend_from_slice(b"\x1b[M");
            out.push(code.checked_add(32)?);
            for value in [col, row] {
                let point = char::from_u32(value + 32)?;
                out.extend_from_slice(point.encode_utf8(&mut buffer).as_bytes());
            }
        }
        MouseProtocolEncoding::Sgr => {
            let final_byte = if release { 'm' } else { 'M' };
            out.extend_from_slice(format!("\x1b[<{code};{col};{row}{final_byte}").as_bytes());
        }
    }
    Some(out)
}

/// Text that is safe to put in a label: control characters are shown, never executed.
///
/// A job name, a diagnostic and a capability segment all come from outside this process, and a
/// terminal that is asked to render one verbatim would run whatever escape it contains against the
/// user's own screen.
#[must_use]
pub fn escape_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn screen(bytes: &[u8]) -> vt100::Parser<TerminalReplies> {
        let mut parser = vt100::Parser::new_with_callbacks(24, 80, 0, TerminalReplies::default());
        parser.process(bytes);
        parser
    }

    /// The one encoding decision a child can observe going wrong silently: arrows change shape
    /// with application-cursor mode, and Ctrl-C must stay a byte rather than becoming a signal.
    #[test]
    fn arrows_follow_application_cursor_mode_and_control_keys_stay_bytes() {
        let normal = screen(b"");
        assert_eq!(
            encode_key(press(KeyCode::Up, KeyModifiers::NONE), normal.screen()).as_slice(),
            b"\x1b[A",
        );
        let application = screen(b"\x1b[?1h");
        assert_eq!(
            encode_key(press(KeyCode::Up, KeyModifiers::NONE), application.screen()).as_slice(),
            b"\x1bOA",
        );
        assert_eq!(
            encode_key(
                press(KeyCode::Up, KeyModifiers::SHIFT),
                application.screen()
            )
            .as_slice(),
            b"\x1b[1;2A",
            "a modified cursor key is always the CSI form",
        );
        assert_eq!(
            encode_key(
                press(KeyCode::Char('c'), KeyModifiers::CONTROL),
                normal.screen()
            )
            .as_slice(),
            b"\x03",
        );
        assert_eq!(
            encode_key(
                press(KeyCode::Char('d'), KeyModifiers::CONTROL),
                normal.screen()
            )
            .as_slice(),
            b"\x04",
        );
        assert_eq!(
            encode_key(
                press(KeyCode::Char('x'), KeyModifiers::ALT),
                normal.screen()
            )
            .as_slice(),
            b"\x1bx",
        );
    }

    /// A query is answered from the emulated screen's own coordinates, whatever is on screen.
    #[test]
    fn cursor_reports_use_the_jobs_own_coordinates() {
        let mut parser = screen(b"\x1b[3;4H\x1b[6n");
        assert_eq!(parser.callbacks_mut().take(), b"\x1b[3;4R".to_vec());

        let mut parser = screen(b"\x1b[5n");
        assert_eq!(parser.callbacks_mut().take(), b"\x1b[0n".to_vec());

        let mut parser = screen(b"\x1b[c");
        assert_eq!(parser.callbacks_mut().take(), b"\x1b[?1;2c".to_vec());

        let mut parser = screen(b"\x1b[18t");
        assert_eq!(parser.callbacks_mut().take(), b"\x1b[8;24;80t".to_vec());
    }

    /// A chunk boundary inside a UTF-8 sequence or a CSI must not corrupt either.
    #[test]
    fn split_byte_chunks_are_reassembled_by_the_parser() {
        let mut parser = screen(b"");
        parser.process(b"\xe7\x95");
        parser.process(b"\x8c\x1b[3");
        parser.process(b"1mred");
        assert!(parser.screen().contents().starts_with('界'));
        assert_eq!(
            parser.screen().cell(0, 2).map(vt100::Cell::fgcolor),
            Some(vt100::Color::Idx(1)),
        );
    }

    /// Mouse reports are the child's coordinates, and are withheld entirely when it asked for
    /// none.
    #[test]
    fn mouse_reports_are_sent_only_when_the_child_asked_for_them() {
        let silent = screen(b"");
        let event = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 9,
            row: 3,
            modifiers: KeyModifiers::NONE,
        };
        assert!(encode_mouse(event, 3, 9, silent.screen()).is_none());

        let sgr = screen(b"\x1b[?1000h\x1b[?1006h");
        assert_eq!(
            encode_mouse(event, 3, 9, sgr.screen())
                .expect("an enabled mouse mode reports a press")
                .as_slice(),
            b"\x1b[<0;10;4M",
        );
    }

    /// A label is shown, never executed: an embedded escape must not reconfigure the real
    /// terminal.
    #[test]
    fn labels_show_control_characters_rather_than_running_them() {
        assert_eq!(escape_controls("a\x1b[2Jb"), "a\\x1b[2Jb");
        assert_eq!(escape_controls("plain"), "plain");
    }
}
