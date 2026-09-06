//! Session startup and the routing of every submitted line.
//!
//! The order in here is load-bearing twice over, and both orders were bought with a bug:
//!
//! 1. fd 3 is claimed *first*, before any other file is opened, because the kernel hands out the
//!    lowest free descriptor and the mux's write-ahead log is the very next thing opened.
//! 2. The [`ShellMux`] is kept alive past `block_on`, because it owns a tokio runtime of its own
//!    and dropping a runtime from inside an asynchronous context panics.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use brush_builtins::BuiltinSet;
use brush_core::extensions::DefaultShellExtensions;
use brush_core::results::ExecutionControlFlow;
use brush_core::{CommandArg, ExecutionContext, ExecutionResult, ShellVariable};
use brush_interactive::{
    BasicInputBackend, InputBackend, InteractiveExecutionResult, InteractiveOptions,
    InteractiveShell, LineExecutor, MinimalInputBackend, ReedlineInputBackend, ShellError,
    ShellRef, UIOptions,
};
use clap::Parser;
use shellmux::{MuxError, ShellMux};

use crate::console::{self, Console};
use crate::error::Error;
use crate::repl::{self, Input};

// Deliberately plain `//` comments, not doc comments: clap's derive turns a doc comment on the
// struct into `about`/`long_about`, and it normalizes leading whitespace, which would wreck the
// alignment of the builtins table below.
#[derive(clap::Parser)]
#[command(name = "marsh", version, about = ABOUT, long_about = LONG_ABOUT)]
struct Cli {
    /// Line editor to use; defaults to reedline on a terminal and minimal otherwise.
    #[arg(long, value_name = "BACKEND")]
    input_backend: Option<InputBackendType>,

    /// Disable colored output in the line editor.
    #[arg(long)]
    disable_color: bool,

    /// Disable syntax highlighting of the line being edited.
    #[arg(long)]
    disable_highlighting: bool,

    /// Disable bracketed paste mode.
    #[arg(long)]
    disable_bracketed_paste: bool,
}

/// The line editors marsh can run on, mirroring brush's own choice of backends.
#[derive(Clone, Copy, clap::ValueEnum)]
enum InputBackendType {
    /// brush's full reedline editor: highlighting, completion menu, hinting, history search.
    Reedline,
    /// A line reader with primitive completion, for automation.
    Basic,
    /// The most minimal reader, for a non-terminal stdin.
    Minimal,
}

/// The backend to use when `--input-backend` was not given.
///
/// reedline drives the terminal directly and does not do the right thing when stdin is not one
/// (nushell/reedline#509), which is the same test upstream brush makes.
fn default_input_backend() -> InputBackendType {
    if std::io::stdin().is_terminal() {
        InputBackendType::Reedline
    } else {
        InputBackendType::Minimal
    }
}

/// One-line summary, shown by `-h`.
const ABOUT: &str = "A shell whose every submitted line is one capability-gated transaction";

/// Full help, shown by `--help`.
///
/// Printed with source formatting: this workspace's clap enables only the `derive` feature, and
/// without `wrap_help` clap's `dimensions()` reports no terminal width, so it never reflows this
/// text and the builtins table keeps its alignment.
const LONG_ABOUT: &str = "\
marsh runs against the btrfs subvolume containing the directory you start it in: the first
subvolume at or above the current directory is the seed, and marsh keeps its snapshots and logs
beside it, in <seed>/../.marsh/<seed name>. Every submitted line is one transaction in the current
job's snapshot of that seed; a granted line lands in the seed at once.
See README.md, \"Setting up marsh\".

Console builtins:
  sd NAME DIR            create job NAME, a sandbox rooted at DIR — a path in the current job,
                         or /DIR from the seed root
  sda DIR                the same, named 1, 2, … in turn
  CMD &                  run CMD in a new job rooted where you are, without waiting
  CMD &NAME              the same, as job NAME — &\"NAME\" for a name with spaces
  jobs                   list the open jobs
  fg [JOB]               attach a job to the terminal (default: the most recent one)
  bg [JOB]               resume a stopped job in the background
  stop [-SIG] JOB        signal a job's process group
  close JOB              end a job: its sandbox and its snapshot
  kill [-SIG] PID        signal a process id
  exit                   end the session (Ctrl-D does too)

JOB is a job's name, spaces and all: fg long build. Quote it — fg \"long build\" — when it
would otherwise read as a flag.

The foreground job owns the terminal, so full-screen programs work: Ctrl-C interrupts it, Ctrl-Z
stops it into the background. Instrumentation — capability requests, verdicts, and anything a
command writes to fd 3 — is printed in gray.\
";

/// Runs the console, returning the process's exit code.
pub fn run() -> std::process::ExitCode {
    // Before anything the process could fail on: `--help` and `--version` must not claim fd 3 or
    // touch the filesystem, and an unexpected argument is clap's diagnostic and exit 2.
    let cli = Cli::parse();

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

    let mux = match open_mux() {
        Ok(mux) => Arc::new(mux),
        Err(error) => {
            eprintln!("marsh: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // No `chdir`: a command's working directory is its job's snapshot, which the mux sets, and this
    // process stays wherever the user started it.

    // A multi-thread runtime, not a current-thread one: reedline's history adapter blocks on the
    // shell mutex through `block_in_place`, which panics on a current-thread runtime — and so does
    // every mux call the console makes.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("marsh: {}", Error::Runtime(error));
            return std::process::ExitCode::FAILURE;
        }
    };

    // The mux keeps a reference here on purpose. It owns a tokio runtime of its own (brush's shell
    // builder is async), and dropping a runtime from inside an asynchronous context panics — which
    // is exactly what would happen if the session's last reference died inside `block_on`.
    let result = runtime.block_on(session(Arc::clone(&mux), &cli));
    drop(mux);
    if let Err(error) = result {
        eprintln!("marsh: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Opens the seed containing the current directory, creating its state directory on first use.
///
/// The learned purity cache is the one source marsh installs: a command an earlier traced run
/// showed requesting nothing and writing nothing skips the snapshot and the merge entirely.
fn open_mux() -> Result<ShellMux, MuxError> {
    let session = shellmux::Session::discover(&std::env::current_dir()?)?;
    // Before the cache creates its log: `materialize` is what refuses a seed marsh cannot snapshot,
    // and it must refuse before anything is written beside it. `ShellMux::open` calls it again,
    // which is a no-op once the directories exist.
    session.materialize()?;
    let learned = Arc::new(shellmux::LearnedPurity::open(&session)?);
    ShellMux::open(
        session,
        None,
        None,
        ShellMux::DEFAULT_CMD_TIMEOUT,
        vec![learned],
    )
}

/// Sets up the terminal and the outer shell, then runs the REPL.
///
/// fd 3 already holds the instrumentation pipe (claimed in [`run`], before any other descriptor
/// could take the number), which is what the outer shell's file table picks up when it is built
/// below; the terminal handle is opened here, *after* fd 3 is occupied, so it cannot land on that
/// number either.
async fn session(mux: Arc<ShellMux>, cli: &Cli) -> Result<(), Error> {
    // `meta/history.jsonl` is the authority's; two files called `history` in one directory would be
    // a trap.
    let history = mux.session().meta().join("console.history");

    // A job-control shell needs a terminal it can hand to a process group; `/dev/tty` is that
    // terminal even if stdout has been redirected.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(Error::Terminal)?;

    let own_pgid = console::claim_terminal_signals();

    let shell = build_shell(&history).await.map_err(Error::Shell)?;
    let shell_ref: ShellRef<DefaultShellExtensions> = Arc::new(tokio::sync::Mutex::new(shell));

    let console = Console::open(mux, tty, own_pgid)?;
    let console = Arc::new(Mutex::new(console));
    // Installed before the loop starts, because the job-control builtins reach the console through
    // this process-global: a `Registration`'s `execute_func` is a plain function pointer.
    console::install(Arc::clone(&console))?;
    // Started after `install`, because the watcher reaps through the process-global console; no job
    // exists yet, so no wakeup can be missed in between. Fatal on failure, like the instrumentation
    // pipe: a session that cannot watch its children merges late in exactly the way this prevents.
    console::watch_children()?;
    refresh_prompt(&shell_ref, &console).await;

    let (seed, root) = with_console(&console, |console| {
        let session = console.session();
        (
            session.seed.display().to_string(),
            session.root.display().to_string(),
        )
    });
    println!("marsh: seed {seed}");
    println!("  state {root}");
    console::gray(
        "builtins: sd NAME DIR · sda DIR · CMD &[NAME] · jobs · fg [JOB] · bg [JOB] · \
         stop [-SIG] JOB · close JOB · kill [-SIG] PID · exit",
    );

    let ui_options = UIOptions::builder()
        .disable_color(cli.disable_color)
        .disable_highlighting(cli.disable_highlighting)
        .disable_bracketed_paste(cli.disable_bracketed_paste)
        .build();

    // One arm per backend, as upstream brush does it: `InteractiveShell` is generic over the
    // backend, so each concrete type needs its own call.
    let result = match cli.input_backend.unwrap_or_else(default_input_backend) {
        InputBackendType::Reedline => {
            let mut backend =
                ReedlineInputBackend::new(&ui_options, &shell_ref).map_err(Error::LineEditor)?;
            // Installed before the loop, so the instrumentation reader thread stops writing
            // straight to a terminal the editor owns.
            console::install_printer(backend.line_printer());
            run_console(&shell_ref, &console, &mut backend, &ui_options).await
        }
        InputBackendType::Basic => {
            run_console(&shell_ref, &console, &mut BasicInputBackend, &ui_options).await
        }
        InputBackendType::Minimal => {
            run_console(&shell_ref, &console, &mut MinimalInputBackend, &ui_options).await
        }
    };

    // Unconditionally: `exit`, Ctrl-D and a fatal error all leave jobs holding snapshots, and a
    // snapshot nobody concludes is a subvolume nobody deletes.
    with_console(&console, Console::sweep);

    result.map_err(Error::from)
}

/// Runs the interactive loop over `backend`, with the console installed as its line executor.
async fn run_console(
    shell: &ShellRef<DefaultShellExtensions>,
    console: &Arc<Mutex<Console>>,
    backend: &mut impl InputBackend,
    ui_options: &UIOptions,
) -> Result<(), ShellError> {
    let interactive_options = InteractiveOptions::from(ui_options);
    let mut interactive = InteractiveShell::new(shell, backend, &interactive_options)?;
    interactive.set_line_executor(Box::new(Session {
        console: Arc::clone(console),
    }));
    interactive.run_interactively().await
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
/// process, untraced, in the directory the user started marsh in. `promptvars` is off for the same
/// reason: `PS1` carries a job's directory, which is text the user typed at `sd`, and prompt
/// expansion would run command substitutions in it once per prompt. `PS1` itself is set by
/// [`refresh_prompt`] as soon as the console exists, because only the console knows which job is
/// current.
async fn build_shell(history: &Path) -> Result<brush_core::Shell, brush_core::Error> {
    let standard = brush_builtins::default_builtins::<DefaultShellExtensions>(BuiltinSet::BashMode);
    let mut shell = brush_core::Shell::builder()
        .interactive(true)
        .read_commands_from_stdin(true)
        .shell_name("marsh".to_string())
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
        .disable_shopt_option("promptvars")
        .var(
            "HISTFILE",
            ShellVariable::new(history.display().to_string()),
        )
        .builtins(standard)
        .builtins(crate::builtins::registrations())
        .build()
        .await?;

    // The builder skips `load_config` when profile *and* rc are `Skip`, and `load_config` is also
    // what imports `HISTFILE`. Calling it here with the same two `Skip`s sources nothing and loads
    // `console.history`, so recall and Ctrl-R survive a restart. A missing or empty file is not an
    // error: `load_config` swallows the import's `Err`, and an empty file yields no history.
    shell
        .load_config(
            &brush_core::ProfileLoadBehavior::Skip,
            &brush_core::RcLoadBehavior::Skip,
        )
        .await?;

    Ok(shell)
}

/// Points the prompt and the outer shell's working directory at the console's current job.
///
/// `PS1` is not a constant here: it names the job every typed line runs in, and `sd`, `sda` and
/// `fg` all move that pointer. The working directory follows it for the same reason: it is what
/// the outer shell's completion resolves relative paths against, so a Tab at the prompt offers
/// the job's snapshot rather than the directory marsh was launched from. The shell lock is taken
/// before the console's, which is the order every job-control builtin already takes them in.
async fn refresh_prompt(shell: &ShellRef<DefaultShellExtensions>, console: &Arc<Mutex<Console>>) {
    let mut guard = shell.lock().await;
    let (prompt, dir) = with_console(console, |console| (console.prompt(), console.current_dir()));
    // A failure here costs a stale prompt or stale completions and nothing else; it is not worth
    // ending a session.
    let _ = guard
        .env_mut()
        .set_global("PS1", ShellVariable::new(prompt));
    let _ = guard.set_working_dir(dir);
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
            // A Ctrl-C pressed during the previous line must not count towards quitting on this
            // one.
            console::arm_interrupts();
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
                Input::Stop(args) => invoke_builtin(shell, "stop", args).await,
                Input::Close(name) => {
                    invoke_builtin(shell, "close", name.into_iter().collect()).await
                }
                Input::SpawnDir { name, dir } => match name {
                    Some(name) => invoke_builtin(shell, "sd", vec![name, dir]).await,
                    None => invoke_builtin(shell, "sda", vec![dir]).await,
                },
                Input::Exit => self.exit(),
                Input::Background { cmd, name } => with_console(&self.console, |console| {
                    executed(console.spawn(".", name, Some(cmd), &mut std::io::stderr()))
                }),
                Input::Foreground(cmd) => with_console(&self.console, |console| {
                    executed(console.foreground(&cmd, &mut std::io::stderr()))
                }),
                Input::Invalid(message) => {
                    let _ = writeln!(std::io::stderr(), "{message}");
                    executed(2)
                }
            };
            // `sd`, `sda` and `fg` all move the current job, and the prompt names it: refreshed
            // once per line rather than in each of them, so no console form can forget to.
            refresh_prompt(shell, &self.console).await;
            Ok(result)
        })
    }

    fn before_prompt(&mut self) {
        with_console(&self.console, |console| console.reap());
    }

    fn on_interrupt(&mut self) -> Option<InteractiveExecutionResult> {
        if !console::note_interrupt() {
            return None;
        }
        // Straight to the exit, deliberately bypassing `Console::may_exit`: a second Ctrl-C is the
        // escape hatch, and demanding a third press because jobs are running is what "cannot get
        // out" means. `Console::sweep` still hangs up, concludes and closes them.
        Some(InteractiveExecutionResult::Executed(ExecutionResult {
            next_control_flow: ExecutionControlFlow::ExitShell,
            exit_code: 130u8.into(),
        }))
    }

    fn on_eof(&mut self) -> Option<InteractiveExecutionResult> {
        // Ctrl-D is `exit` typed with one key, so it gets `exit`'s contract: one warning while jobs
        // hold open transactions, and a second press that means it. The refusal is one-shot by
        // construction — `may_exit` arms `exit_armed`, and only a submitted non-exit line clears
        // it — so a non-terminal stdin still terminates on its immediate second `Eof`.
        if with_console(&self.console, |console| {
            console.may_exit(&mut std::io::stderr())
        }) {
            return None;
        }
        Some(executed(0))
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
    let outcome = {
        let context = ExecutionContext {
            shell: &mut guard,
            command_name: name.to_string(),
            params,
        };
        (registration.execute_func)(context, argv).await
    };
    drop(guard);

    match outcome {
        Ok(result) => InteractiveExecutionResult::Executed(result),
        Err(error) => InteractiveExecutionResult::Failed(error),
    }
}

/// A completed console builtin, with the exit status the shell should record.
fn executed(code: u8) -> InteractiveExecutionResult {
    InteractiveExecutionResult::Executed(ExecutionResult::new(code))
}
