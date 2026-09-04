//! Printing whole lines while the editor holds the terminal.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A handle for printing a line from another thread while the shell may be editing one.
///
/// A raw write to the terminal during `Reedline::read_line` is erased by the editor's next
/// repaint, because reedline repaints from a cursor origin cached before that write. Handing the
/// line to reedline instead makes it print above the prompt and redraw, which is what
/// [`reedline::ExternalPrinter`] exists for. The editor only drains the channel while it is
/// running, so a caller printing outside that window is told to print the line itself rather than
/// have it sit queued until the next prompt.
#[derive(Clone)]
pub struct LinePrinter {
    /// The editor's queue of lines to print above the prompt.
    printer: reedline::ExternalPrinter<String>,
    /// Whether the editor is inside `read_line`, i.e. whether anything drains the queue.
    editing: Arc<AtomicBool>,
}

impl LinePrinter {
    /// Creates a printer over `printer`, reporting activity through `editing`.
    pub(super) const fn new(
        printer: reedline::ExternalPrinter<String>,
        editing: Arc<AtomicBool>,
    ) -> Self {
        Self { printer, editing }
    }

    /// Queues `line` for display above the prompt.
    ///
    /// Returns `false` when no editor is running or its queue is full, in which case the caller
    /// must print the line itself. Never blocks: a full queue must not stall the thread that
    /// produced the line.
    pub fn try_print(&self, line: &str) -> bool {
        self.editing.load(Ordering::SeqCst)
            && self.printer.sender().try_send(line.to_string()).is_ok()
    }
}
