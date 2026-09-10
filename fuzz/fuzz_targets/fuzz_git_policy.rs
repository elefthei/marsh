//! libFuzzer driver for the git trace-policy generator and checker.
//!
//! Fuzzes trace generation and policy evaluation for panics and for no-surprise violations. It
//! executes no git, no shell and no filesystem operation, which is what lets libFuzzer explore
//! millions of inputs: a target that took a btrfs snapshot and forked a traced shell per input
//! would be a very slow test loop, not a fuzzer.
//!
//! The ground-truth replay of granted operations lives in `shellmux/tests/mux_frontend_fuzz.rs`,
//! which drives the same generator from its own seeds — the fixed reference corpus and a fresh
//! random one — rather than from this target's corpus. The corpus stays local to libFuzzer.
//!
//! Needs `cargo-fuzz` and a nightly toolchain:
//! `cargo +nightly fuzz run fuzz_git_policy`.

#![no_main]
// A panic *is* how a libFuzzer target reports a finding, as in `fuzz_highlight`.
#![allow(clippy::panic)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let trace = marsh_trace::validate_trace(data);
    if let Some(surprise) = marsh_trace::no_surprise_violation(&trace.history) {
        panic!("no-surprise violated: {surprise}");
    }
});
