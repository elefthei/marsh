//! Session startup and the routing of every submitted line.
//!
//! The order in here is load-bearing twice over, and both orders were bought with a bug:
//!
//! 1. fd 3 is claimed *first*, before any other file is opened, because the kernel hands out the
//!    lowest free descriptor and the mux's write-ahead log is the very next thing opened.
//! 2. The [`ShellMux`] is kept alive past `block_on`, because it owns a tokio runtime of its own
//!    and dropping a runtime from inside an asynchronous context panics.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use brush_builtins::BuiltinSet;
use brush_core::extensions::DefaultShellExtensions;
use brush_core::results::ExecutionControlFlow;
use brush_core::{CommandArg, ExecutionContext, ExecutionResult, ShellVariable};
use brush_interactive::{
    BasicInputBackend, InteractiveExecutionResult, InteractiveOptions, InteractiveShell,
    LineExecutor, ShellError, ShellRef, UIOptions,
};
use shellmux::{MuxError, MuxOptions, ShellMux};

use crate::console::{self, Console};
use crate::repl::{self, FOREGROUND, Input};

/// The session's state directory, relative to the mux root.
const STATE_DIR: &str = ".marsh";

/// Command-line help, printed for `-h`/`--help`.
const USAGE: &str = "\
usage: marsh [ROOT]

ROOT is a directory on a btrfs filesystem mounted with `user_subvol_rm_allowed` (default: the
current directory). It is created and initialized as a mux root on first use, and reopened —
replaying its write-ahead log — afterwards. See README.md for the mount requirement.

Every submitted line is one transaction against the seed, run as principal `main`. Console
builtins:
  CMD &                  start CMD as a background job (and principal) named 1, 2, …
  spawn NAME CMD         start CMD as a background job (and principal) named NAME
  jobs                   list the open jobs
  fg [%NAME]             attach a job to the terminal (default: the most recent one)
  bg [%NAME]             resume a stopped job in the background
  kill [-SIG] %NAME|PID  signal a job's process group, or a process id
  exit                   end the session (Ctrl-D does too)

The foreground job owns the terminal, so full-screen programs work: Ctrl-C interrupts it, Ctrl-Z
stops it into the background. Instrumentation — capability requests, verdicts, and anything a
command writes to fd 3 — is printed in gray. History is kept in .marsh/history.
";

/// Runs the console, returning the process's exit code.
pub fn run() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let root = match args.next() {
        Some(argument) if argument == "-h" || argument == "--help" => {
            print!("{USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        Some(argument) => PathBuf::from(argument),
        None => PathBuf::from("."),
    };

    // Before anything else opens a file: fd 3 is a standard stream of this process, and the kernel
    // hands out the lowest free descriptor to whoever asks first. Claiming it here is what keeps
    // the mux's own write-ahead log — the very next thing opened — from landing on the number the
    // instrumentation stream owns.
    let instrumentation = match console::open_instrumentation() {
        Ok(read_end) => read_end,
        Err(error) => {
            eprintln!("marsh: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    console::spawn_instrumentation_reader(instrumentation);

    let mux = match open_mux(&root) {
        Ok(mux) => Arc::new(mux),
        Err(error) => {
            eprintln!("marsh: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // The seed is the tree the session is about: `\w` in the prompt, path completion and every
    // relative path the user types should all mean the same directory the transactions run in.
    if let Err(error) = std::env::set_current_dir(mux.seed_dir()) {
        eprintln!("marsh: cannot enter {}: {error}", mux.seed_dir().display());
        return std::process::ExitCode::FAILURE;
    }

    // A multi-thread runtime, not a current-thread one: reedline's history adapter blocks on the
    // shell mutex through `block_in_place`, which panics on a current-thread runtime — and so does
    // every mux call the console makes.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("marsh: cannot start the async runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // The mux keeps a reference here on purpose. It owns a tokio runtime of its own (brush's shell
    // builder is async), and dropping a runtime from inside an asynchronous context panics — which
    // is exactly what would happen if the session's last reference died inside `block_on`.
    let result = runtime.block_on(session(Arc::clone(&mux)));
    drop(mux);
    if let Err(error) = result {
        eprintln!("marsh: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Opens `root` as a mux, creating and seeding it when it is not one yet.
fn open_mux(root: &Path) -> Result<ShellMux, MuxError> {
    std::fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    if root.join("seed").exists() {
        ShellMux::open(&root, MuxOptions::default())
    } else {
        // An empty seed still gets a seed commit, so `git checkout HEAD -- p` has a source from the
        // very first command.
        ShellMux::create(&root, MuxOptions::default(), |_| Ok(()))
    }
}

/// Sets up the terminal and the outer shell, then runs the REPL.
///
/// fd 3 already holds the instrumentation pipe (claimed in [`run`], before any other descriptor
/// could take the number), which is what the outer shell's file table picks up when it is built
/// below; the terminal handle is opened here, *after* fd 3 is occupied, so it cannot land on that
/// number either.
async fn session(mux: Arc<ShellMux>) -> Result<(), String> {
    let history = mux
        .seed_dir()
        .parent()
        .unwrap_or_else(|| mux.seed_dir())
        .join(STATE_DIR)
        .join("history");

    // A job-control shell needs a terminal it can hand to a process group; `/dev/tty` is that
    // terminal even if stdout has been redirected.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| format!("cannot open /dev/tty: {error}"))?;

    let own_pgid = console::claim_terminal_signals();

    let shell = build_shell(&history)
        .await
        .map_err(|error| format!("cannot build the shell: {error}"))?;
    let shell_ref: ShellRef<DefaultShellExtensions> = Arc::new(tokio::sync::Mutex::new(shell));

    let console = Arc::new(Mutex::new(Console::new(mux, tty, own_pgid)));
    // Installed before the loop starts, because the job-control builtins reach the console through
    // this process-global: a `Registration`'s `execute_func` is a plain function pointer.
    console::install(Arc::clone(&console))?;

    let ui_options = UIOptions::default();
    let interactive_options = InteractiveOptions::from(&ui_options);
    // The basic backend, not reedline. A background job's fd-3 write arrives while the editor holds
    // the terminal, and reedline repaints its line from a cursor origin cached *before* that write:
    // the next keypress then erases the instrumentation line (measured — the gray line is on screen
    // until a key is pressed, and gone afterwards). Losing a capability report is worse than losing
    // reedline's editing niceties, and the basic backend builds its line reader per read, so it
    // never repaints over output it did not write.
    let mut backend = BasicInputBackend;
    let mut interactive = InteractiveShell::new(&shell_ref, &mut backend, &interactive_options)
        .map_err(|error| format!("cannot start the console: {error}"))?;
    interactive.set_line_executor(Box::new(Session {
        console: Arc::clone(&console),
    }));

    let seed = with_console(&console, |console| console.seed_dir().display().to_string());
    println!("marsh: seed {seed}");
    console::gray(
        "builtins: CMD & · spawn NAME CMD · jobs · fg [%NAME] · bg [%NAME] · \
         kill [-SIG] %NAME|PID · exit",
    );

    let result = interactive.run_interactively().await;

    // Unconditionally: `exit`, Ctrl-D and a fatal error all leave jobs holding snapshots, and a
    // snapshot nobody concludes is a subvolume nobody deletes.
    with_console(&console, Console::sweep);

    result.map_err(|error| error.to_string())
}

/// Builds the outer shell: the one that composes prompts, owns history and feeds completion.
///
/// It never executes a user line — the session intercepts all of them — so most of its builtin
/// registry exists only as completion candidates. The exceptions are the job-control builtins,
/// which are registered *after* the standard set so they replace the stock `fg`/`bg`/`jobs`/`kill`:
/// those act on this shell's own job table, which is necessarily empty, because this shell runs
/// nothing.
///
/// Profile and rc loading stay skipped for a sharper reason: they would execute *here*, in this
/// process, untraced, with the seed as the working directory.
async fn build_shell(history: &Path) -> Result<brush_core::Shell, brush_core::Error> {
    let standard = brush_builtins::default_builtins::<DefaultShellExtensions>(BuiltinSet::BashMode);
    brush_core::Shell::builder()
        .interactive(true)
        .read_commands_from_stdin(true)
        .shell_name("marsh".to_string())
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
        .var("PS1", ShellVariable::new(format!("{FOREGROUND}$ ")))
        .var(
            "HISTFILE",
            ShellVariable::new(history.display().to_string()),
        )
        .builtins(standard)
        .builtins(crate::builtins::registrations())
        .build()
        .await
}

/// Runs `action` against the console.
///
/// `block_in_place` because a console action ends in a blocking syscall — `waitpid`, or a mux call
/// that blocks on the mux's own runtime — and a runtime worker must be told before it is blocked.
fn with_console<R>(console: &Arc<Mutex<Console>>, action: impl FnOnce(&mut Console) -> R) -> R {
    tokio::task::block_in_place(|| {
        let mut console = console.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut console)
    })
}

/// The handle installed into the interactive loop.
///
/// The console itself is shared rather than owned by the loop, because the exit sweep has to reach
/// the job table *after* the loop has returned — the jobs that outlive the session are exactly the
/// ones whose transactions still need concluding.
struct Session {
    /// The console this session drives.
    console: Arc<Mutex<Console>>,
}

impl LineExecutor<DefaultShellExtensions> for Session {
    fn execute<'a>(
        &'a mut self,
        shell: &'a ShellRef<DefaultShellExtensions>,
        line: String,
    ) -> Pin<Box<dyn Future<Output = Result<InteractiveExecutionResult, ShellError>> + Send + 'a>>
    {
        Box::pin(async move {
            let input = repl::parse(&line);
            if !matches!(input, Input::Exit) {
                with_console(&self.console, Console::disarm_exit);
            }

            // Only whole-line console forms reach the outer shell, and they reach it as
            // *constructed argv* — never as text handed back to a parser. That is what makes
            // `jobs && rm x` impossible to run in this process: it is not one of these forms, so it
            // falls through to the mux as one traced foreground transaction.
            let result = match input {
                Input::Empty => executed(0),
                Input::Jobs => invoke_builtin(shell, "jobs", Vec::new()).await,
                Input::Fg(name) => invoke_builtin(shell, "fg", name.into_iter().collect()).await,
                Input::Bg(name) => invoke_builtin(shell, "bg", name.into_iter().collect()).await,
                Input::Kill(args) => invoke_builtin(shell, "kill", args).await,
                Input::Spawn { name, cmd } => invoke_builtin(shell, "spawn", vec![name, cmd]).await,
                Input::Exit => self.exit(),
                Input::Background(cmd) => with_console(&self.console, |console| {
                    let name = console.next_name();
                    executed(console.spawn(name, cmd, &mut std::io::stderr()))
                }),
                Input::Foreground(cmd) => with_console(&self.console, |console| {
                    executed(console.foreground(cmd, &mut std::io::stderr()))
                }),
                Input::Invalid(message) => {
                    let _ = writeln!(std::io::stderr(), "{message}");
                    executed(2)
                }
            };
            Ok(result)
        })
    }

    fn before_prompt(&mut self) {
        with_console(&self.console, Console::reap);
    }
}

impl Session {
    /// Ends the session, warning once while jobs are still open.
    fn exit(&self) -> InteractiveExecutionResult {
        if with_console(&self.console, |console| {
            console.may_exit(&mut std::io::stderr())
        }) {
            return InteractiveExecutionResult::Executed(ExecutionResult {
                next_control_flow: ExecutionControlFlow::ExitShell,
                exit_code: 0u8.into(),
            });
        }
        executed(0)
    }
}

/// Invokes a registered builtin of the outer shell with a constructed argument vector.
///
/// `argv[0]` is the builtin's own name, because that is what a builtin's argument parser expects to
/// find there. Nothing here re-parses `line`: the arguments are the ones the grammar produced.
async fn invoke_builtin(
    shell: &ShellRef<DefaultShellExtensions>,
    name: &str,
    args: Vec<String>,
) -> InteractiveExecutionResult {
    let mut guard = shell.lock().await;
    let params = guard.default_exec_params();
    let Some(registration) = guard.builtins().get(name).cloned() else {
        let _ = writeln!(
            std::io::stderr(),
            "marsh: {name}: builtin is not registered"
        );
        return executed(127);
    };
    let argv: Vec<CommandArg> = std::iter::once(name.to_string())
        .chain(args)
        .map(CommandArg::String)
        .collect();
    let context = ExecutionContext {
        shell: &mut guard,
        command_name: name.to_string(),
        params,
    };

    match (registration.execute_func)(context, argv).await {
        Ok(result) => InteractiveExecutionResult::Executed(result),
        Err(error) => InteractiveExecutionResult::Failed(error),
    }
}

/// A completed console builtin, with the exit status the shell should record.
fn executed(code: u8) -> InteractiveExecutionResult {
    InteractiveExecutionResult::Executed(ExecutionResult::new(code))
}
