# GitHub Copilot Coding Agent Instructions for marsh

## Project Overview

**marsh** is a Linux transactional shell built on the retained brush libraries. Its runtime consists of the `marsh` and `marsh-exec` binaries. The workspace uses Rust 2024 and MSRV 1.94.0.

## Critical: Read AGENTS.md First

Before changing files, read repository-root `AGENTS.md` for shared development conventions. It still contains upstream brush commands and paths. For marsh-specific workspace paths, toolchain/platform requirements, task commands, and CI coverage, follow this guide and verify against `Cargo.toml`, `.cargo/config.toml`, and `.github/workflows/ci.yaml`. Those configuration files determine what is available. The marsh port removed xtask and the upstream YAML compatibility harness; do not restore them just to satisfy inherited instructions.

This is a narrow correction to task and configuration facts, not permission to ignore AGENTS.md's coding, error-handling, documentation, or contribution conventions.

## Code Review Checklist

When reviewing PRs, verify:

- [ ] **Documentation**: All exported APIs have rustdoc comments (missing docs = CI failure)
- [ ] **Forbidden patterns**: No `panic`, `unwrap_in_result`, `expect_used`, or `todo` (all denied by clippy)
- [ ] **Error handling**: Uses `thiserror` for crate errors; `anyhow` only in tests
- [ ] **Logging**: Uses `tracing::debug!(target: trace_categories::CATEGORY, "msg")` pattern
- [ ] **Testing**: Compatibility fixes have regression coverage in the affected crate's existing Rust unit or integration tests
- [ ] **Testing**: Transaction and job changes have regression coverage in `shellmux/tests/`
- [ ] **Testing**: Unit tests expected for new public APIs (when feasible) (see AGENTS.md section 2)
- [ ] **Platform code**: Platform-specific code is in `brush-core/src/sys/` modules
- [ ] **Breaking changes**: Public API changes are clearly highlighted and documented
- [ ] **Builder pattern**: Configuration uses builder pattern (see `Shell::builder()`)
- [ ] **Code quality**: Passes `cargo fmt --check` and `cargo clippy` without warnings
- [ ] **Commit format**: Follows [Conventional Commits](https://www.conventionalcommits.org/) (feat:, fix:, docs:, test:)
- [ ] **Dependencies**: No unnecessary cloning (use references when possible)
- [ ] **Cross-platform**: Uses appropriate `cfg(unix)`, `cfg(windows)`, `cfg(target_family = "wasm")`

## Workspace Structure

```text
marsh/
├── marsh-shell/        # CLI; binary marsh
├── marsh-exec/         # Traced executor; binary marsh-exec
├── shellmux/           # Transaction mux
├── marsh-trace/        # Pure git trace generation and policy validation
├── rust-validator/     # Cargo package junco-rust-validator
├── brush-core/
├── brush-builtins/
├── brush-interactive/
├── brush-parser/
├── fuzz/               # cargo-fuzz targets, including fuzz_git_policy
└── docs/
```

**Dependency flow:** `marsh-shell → shellmux → {marsh-exec, junco-rust-validator}`. `marsh-trace` depends only on `junco-rust-validator`; both `fuzz` and `shellmux`'s integration tests drive it, so the fuzzed trace generation and the executed trace generation are one implementation. Both `marsh-shell` and `shellmux` also depend on retained brush libraries.

Root Cargo commands default to `marsh-shell`. Workspace validation must specify `--workspace`, and building the complete runtime must select both binary-owning packages.

## Build & Validation Commands

### Terminal Command Execution

When running commands that may take more than a few seconds (cargo build, cargo check, cargo test, cargo clippy, etc.), **run them in background mode and poll for results** rather than blocking. This prevents commands from being cancelled due to timeouts. Use `isBackground: true` with `run_in_terminal`, then use `get_terminal_output` to check results.

### Prerequisites

- Use Rust 1.94.0 or newer with rustfmt and clippy. Linux is the supported marsh runtime.
- Native builds require `libbtrfsutil-dev` and `libclang-dev` on the Ubuntu CI hosts.
- Full workspace tests and shellmux integration tests additionally require Git, `btrfs-progs`, `strace`, and writable btrfs scratch storage mounted with `user_subvol_rm_allowed`. Fixtures create subvolumes at Cargo's compiled-in `CARGO_TARGET_TMPDIR`; CI provides this at `target/tmp`. Tests do not quietly skip on ext4, and mounting an arbitrary directory is insufficient. Follow the `Mount btrfs at target/tmp` step in `.github/workflows/ci.yaml` when provisioning the test environment; do not embed privileged setup in routine task commands.
- The dependency audit requires `cargo-deny`. `cargo-nextest` is needed only to reproduce CI's test runner. A missing tool is an explicit prerequisite, not a reason to install or restore xtask.

### Local Iteration

Use the affected crate's `[package].name` for `<package>`; the directory name is not always the Cargo package name. Start with targeted checks and an existing Rust unit or relevant integration test:

```sh
cargo check --package <package>
cargo test --package <package>

cargo test --package brush-parser
cargo test --package brush-builtins
cargo test --package shellmux --test mux_jobs
```

The shellmux integration test requires the test prerequisites above. Shellmux transaction tests are not a replacement for the removed bash-oracle YAML suite. When formatting needs to be applied, run `cargo fmt --all`.

### Comprehensive Validation

After targeted checks, use this checklist when finishing Rust changes. Keep the dependency audit last rather than running it repeatedly during iteration:

```sh
cargo fmt --check --all
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-features --all-targets
cargo test --workspace
cargo deny --all-features check all
```

`cargo test --workspace` runs workspace unit, integration, and doc tests. This checklist does not reproduce every CI job: nightly unused-dependency analysis and PR benchmark comparison remain separate.

### CI Test-Runner Parity

To reproduce CI's test runner, run both commands:

```sh
cargo nextest run --workspace
cargo test --workspace --doc
```

`cargo-nextest` is an additional tool. The Cargo-native `cargo test --workspace` command remains the ordinary local path.

### Build Variants

Both binary-owning packages are required for a usable runtime:

```sh
cargo build -p marsh-shell -p shellmux
cargo build --release -p marsh-shell -p shellmux
```

Current CI has no schema-generation, coverage-threshold, or upstream YAML compatibility gate; this guide does not advertise replacement commands for those removed workflows.

## Testing Philosophy

**Regression-first approach:** When fixing bugs or adding features, add coverage using the affected crate's existing Rust unit or integration tests before implementation when feasible. The upstream YAML compatibility harness is not in this workspace. Comparisons with bash may still be useful behavior checks, but there is no named bash-oracle suite to invoke.

**Test categories:**
- Unit tests: In-file with `#[cfg(test)]`
- Integration tests: `brush-core/tests/`, `shellmux/tests/`, and `rust-validator/tests/`
- Benchmarks: `brush-parser/benches/` and `rust-validator/benches/`

## Common Pitfalls & Solutions

### ❌ Don't Do This
- Run full test suite on every change (too slow)
- Skip `cargo fmt` and `cargo clippy` before committing
- Use `cargo deny check` during development iteration
- Clone values unnecessarily (use references)
- Add breaking changes to public APIs without highlighting them
- Forget to add affected-crate Rust regression coverage for compatibility fixes

### ✅ Do This
- Target specific packages/tests during development
- Run fmt/clippy before every commit
- Follow builder pattern for configuration (see `Shell::builder()`)
- Keep platform-specific code in `brush-core/src/sys/`
- Document all exported APIs with rustdoc
- Use `tracing::debug!(target: trace_categories::CATEGORY, "msg")` for logging
- Add regression coverage in the affected crate's existing Rust unit or integration tests

## Error Handling & Logging

```rust
// Use thiserror for crate-specific errors
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MyError { ... }

// Use anyhow ONLY in tests
#[cfg(test)]
use anyhow::Result;

// Logging with trace categories
use crate::trace_categories;
tracing::debug!(target: trace_categories::COMMANDS, "executing: {}", cmd);
```

**Available trace categories:** COMMANDS, COMPLETION, EXPANSION, FUNCTIONS, INPUT, JOBS, PARSE, PATTERN, UNIMPLEMENTED

## Linting Configuration

The project uses **extremely strict** linting (workspace-level in `Cargo.toml`):
- All Rust warnings denied
- All clippy warnings denied (pedantic, cargo, nursery, perf)
- `expect_used`, `panic`, `todo`, `unwrap_in_result` are **forbidden**
- Missing docs on exported items are errors

**Your code MUST pass `cargo clippy` without warnings.**

## Cross-Platform Considerations

- The marsh runtime and CI support Linux on x86_64 and aarch64.
- WSL requires the same Linux native dependencies, tracing tools, and writable btrfs test scratch storage.
- Retained brush crates still contain platform-specific code in `brush-core/src/sys/`; respect their existing `cfg(unix)`, `cfg(windows)`, and `cfg(target_family = "wasm")` boundaries.
- Do not infer full-workspace macOS, Windows, or WASM support from the retained brush code. See `.cargo/config.toml` for target-specific configuration.

## CI Pipeline (What Will Run on Your PR)

`.github/workflows/ci.yaml` defines these jobs:

1. **Builds** on Linux x86_64 and aarch64, producing both `marsh` and `marsh-exec`.
2. **Tests** on Linux x86_64 and aarch64 with `cargo nextest run --workspace`, followed by separate workspace doc tests.
3. **Workspace checks** on stable and MSRV 1.94.0. Format, clippy, and cargo-deny checks run only on stable.
4. **Unused-dependency analysis** with cargo-udeps under nightly.
5. **Criterion benchmark comparisons** between the pull request and `main` on pull requests.

The workflow does not establish schema, coverage-threshold, external bash-completion, OS-distribution, or public-API analysis gates.

## Making Changes

### Editing Core Shell Behavior
1. Check `brush-core/src/shell.rs` for `Shell` struct
2. Use `Shell::builder()` for construction
3. Update `marsh-shell/src/main.rs` if CLI changes are needed

### Adding/Modifying Builtins
1. Edit files in `brush-builtins/src/`
2. Register in `brush-builtins/src/factory.rs`
3. Add Rust regression tests in the affected crate

### Parser Changes
1. Modify `brush-parser/src/`
2. Update AST definitions
3. Test with `cargo test --package brush-parser`

### Breaking Changes Policy
- Avoid breaking public APIs (all crate exports are public)
- If unavoidable, highlight clearly and document thoroughly
- New optional fields on public structs are OK if struct implements `Default`
- See AGENTS.md section 3 for complete breaking change policy

## Performance & Benchmarking

```bash
cargo bench --workspace --benches
```

CI compares Criterion benchmark results against `main` on pull requests.

## Documentation Standards

**Rustdoc:** REQUIRED for all exported types, functions, traits, modules. Missing docs = CI failure.
**Examples:** Only needed for major feature additions.
**Style:** Follow Rust documentation best practices.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
```
feat: add support for X
fix: correct behavior of Y
docs: update Z documentation
test: add test cases for W
```

## AI-Assisted Contributions

If using AI assistance significantly, add to PR description or commit message:
```
Assisted-by: GitHub Copilot
```

## When Something Fails

1. **Test failures:** Focus on the affected area first and check whether regression coverage needs updating
2. **Format/clippy failures:** Fix immediately before proceeding
3. **Shell-behavior or integration failures:** Treat them as behavior regressions and update the implementation or valid expectations
4. **Build failures:** Check dependencies and verify Rust version 1.94.0 or newer
5. **Long-running commands:** Use the background-execution workflow under **Terminal Command Execution**

## Quick Reference

Use the command checklist and prerequisites under **Build & Validation Commands**.

