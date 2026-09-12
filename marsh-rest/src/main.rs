//! Entry point: the 4-line delegation every marsh binary's `main.rs` is.

fn main() -> std::process::ExitCode {
    marsh_rest::entry::run()
}
