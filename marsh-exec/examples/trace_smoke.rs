//! Smoke proof of the public executor API: one real command, one evidence object.
//!
//! Usage: `cargo run -p marsh-exec --example trace_smoke -- /abs/path/to/marsh-exec`
//!
//! Runs a program that exercises both instrumentation streams — a builtin redirection, an external
//! process, and a read of what the builtin wrote — and requires every fact back out of the single
//! returned result. A missing fact is a failure, not a reduced claim.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use marsh_exec::evidence::{parse_quoted, split_args};
use marsh_exec::hooks::BuiltinRecord;
use marsh_exec::{Call, ExecutionEvent, ExecutionRequest, MarshExecutor, PersistenceLayer};

/// The program under test: a builtin that redirects, an external process, and a read-back.
const PROGRAM: &str = "printf builtin > builtin.txt; touch external.txt; cat builtin.txt";

/// Wall-clock budget for the run.
const BUDGET: Duration = Duration::from_secs(5);

fn main() -> Result<(), Box<dyn Error>> {
    let worker = std::env::args()
        .nth(1)
        .ok_or("usage: trace_smoke <worker>")?;

    let work = tempfile::tempdir()?;
    let state = tempfile::tempdir()?;
    let executor = MarshExecutor::builder(PersistenceLayer::new(
        work.path().to_path_buf(),
        state.path().to_path_buf(),
    ))
    .worker(&worker)
    .command_timeout(BUDGET)
    .build()?;
    let result = executor
        .prepare()?
        .run(ExecutionRequest {
            command: PROGRAM,
            cwd: work.path(),
            envs: &[],
            run_id: "smoke",
        })?
        .collect()?;

    if result.exit_code != 0 {
        return Err(format!(
            "exit {}: {}",
            result.exit_code,
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(result.stdout)?;
    if stdout != "builtin" {
        return Err(format!("stdout {stdout:?} is not {:?}", "builtin").into());
    }
    let builtin_file = std::fs::read_to_string(work.path().join("builtin.txt"))?;
    if builtin_file != "builtin" {
        return Err(format!("builtin.txt {builtin_file:?} is not {:?}", "builtin").into());
    }
    let external_file = work.path().join("external.txt").exists();
    if !external_file {
        return Err("external.txt was not created".into());
    }

    let evidence = result
        .evidence
        .ok_or("a successful run must carry evidence")?;
    if !printf_record(&evidence) {
        return Err("no matched, successful printf invocation in the builtin stream".into());
    }
    if !touch_exec(&evidence) {
        return Err("no successful execve of touch in the system stream".into());
    }

    println!(
        "exit=0 stdout={stdout} builtin_file={builtin_file} external_file={external_file} \
         printf_record=true touch_exec=true"
    );
    Ok(())
}

/// Whether the builtin stream holds a `printf` invocation with a matching successful `End`.
fn printf_record(evidence: &marsh_exec::ExecutionEvidence) -> bool {
    let events = evidence.events();
    events.iter().any(|event| {
        let ExecutionEvent::Builtin(BuiltinRecord::Begin { id, builtin, .. }) = event else {
            return false;
        };
        builtin == "printf"
            && events.iter().any(|other| {
                matches!(
                    other,
                    ExecutionEvent::Builtin(BuiltinRecord::End { id: ended, exit: 0, .. })
                        if ended == id
                )
            })
    })
}

/// Whether the system stream holds a successful `execve` whose program is `touch`.
fn touch_exec(evidence: &marsh_exec::ExecutionEvidence) -> bool {
    evidence.events().iter().any(|event| {
        let ExecutionEvent::System(line) = event else {
            return false;
        };
        let Call::Syscall {
            name, args, ret, ..
        } = &line.call
        else {
            return false;
        };
        if name != "execve" || *ret != 0 {
            return false;
        }
        let parts = split_args(args);
        let program = parts.first().copied().and_then(parse_quoted);
        program.as_deref().is_some_and(|path| {
            Path::new(path)
                .file_name()
                .is_some_and(|name| name == "touch")
        })
    })
}
