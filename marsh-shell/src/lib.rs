//! `marsh`: a shell whose every submitted line is one capability-gated transaction.
//!
//! The console is a real interactive shell — line editing, history, completion and prompt
//! composition all come from brush's own interactive layer. What the fork changes is *where* a
//! submitted line runs: instead of executing in this process, every line is handed to the session
//! in [`entry`], which turns it into one [`shellmux::ShellMux`] transaction — snapshot the seed,
//! run the line under the tracer, translate its syscalls into capabilities, submit them to the
//! authority, merge on a full grant.
//!
//! Instrumentation is the console's own reporting, not a stream a command can reach: every
//! capability request and every verdict the mux produces is printed in light gray, so a
//! transaction's capability traffic is visually separable from the command's own output on one
//! shared terminal. A command has stdin, stdout and stderr and nothing else.

mod builtins;
pub mod console;
pub mod entry;
pub mod error;
