//! `marsh`: a shell whose every submitted line is one capability-gated transaction.
//!
//! The console is a real interactive shell — line editing, history, completion and prompt
//! composition all come from brush's own interactive layer. What the fork changes is *where* a
//! submitted line runs: instead of executing in this process, every line is handed to the session
//! in [`entry`], which turns it into one [`shellmux::ShellMux`] transaction — snapshot the seed,
//! run the line under the tracer, translate its syscalls into capabilities, submit them to the
//! authority, merge on a full grant.
//!
//! Instrumentation has its own stream. fd 3 is a third standard stream — stdout=1, stderr=2,
//! instrumentation=3 — in brush-core, so a job's `echo x >&3`, a builtin's `stdinstr()` writer and
//! any external process's fd 3 all land in the console's instrumentation pipe. Everything that
//! arrives there, plus every verdict the mux produces, is printed in light gray, so a
//! transaction's capability traffic is visually separable from the command's own output on one
//! shared terminal.

mod builtins;
pub mod console;
pub mod entry;
mod repl;
