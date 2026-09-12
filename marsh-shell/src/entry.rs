//! Session startup and the routing of every submitted line.
//!
//! The order in here is load-bearing, and it was bought with a bug: fd 3 is claimed *first*, before
//! any other file is opened, because the kernel hands out the lowest free descriptor and the mux's
//! write-ahead log is the very next thing opened.
//!
//! Everything after it happens inside one Tokio runtime, because the mux is an asynchronous API
//! that owns tasks: it is built inside `block_on` and shut down there too.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use brush_builtins::BuiltinSet;
use brush_core::extensions::DefaultShellExtensions;
use brush_core::openfiles::OpenFile;
use brush_core::results::ExecutionControlFlow;
use brush_core::sys::terminal::SuspendKeyGuard;
use brush_core::{CommandArg, ExecutionContext, ExecutionResult, ShellVariable};
use brush_interactive::{
    BasicInputBackend, InputBackend, InteractiveExecutionResult, InteractiveOptions,
    InteractiveShell, LineExecutor, MinimalInputBackend, ReedlineInputBackend, ShellError,
    ShellRef, UIOptions,
};
use clap::Parser;
use marsh_rest::frontend::RestFrontend;
use marsh_rest::routes::{self, AppState};
use shellmux::{
    MarshExecutor, MarshFrontend, MarshFrontendJoin, PersistenceLayer, PurityCheckerBuilder,
    ShellId, ShellMux,
};

use crate::console::{self, Console, ConsoleFrontend};
use crate::error::Error;
use shellmux::repl::{self, Input};

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

    /// Run the full-screen interface: one terminal tab per job plus a `caps` tab listing the
    /// authority's active granted capabilities.
    #[arg(long, conflicts_with_all = ["input_backend", "disable_color", "disable_highlighting", "disable_bracketed_paste"])]
    tui: bool,

    /// Also serve this session as a REST/WebSocket API on 127.0.0.1:<PORT> — the marsh-rest
    /// protocol — so a browser client drives the same jobs the console shows.
    #[arg(long, value_name = "PORT", conflicts_with = "tui")]
    rest_api: Option<u16>,
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
  bg DIR                 the same, named 1, 2, … in turn
  CMD &                  run CMD in a new job rooted where you are, without waiting
  CMD &NAME              the same, as job NAME — &\"NAME\" for a name with spaces
  jobs                   list the open jobs
  fg [JOB]               attach a job to the terminal (default: the most recent one)
  stop [-f] JOB          close a job once its command finishes; -f kills that command now
  kill [-SIG] PID        signal a process id
  exit                   end the session (Ctrl-D does too)

JOB is a job's name, spaces and all: fg long build. Quote it — fg \"long build\" — when it
would otherwise read as a flag.

The foreground job owns the terminal, so full-screen programs work: Ctrl-C interrupts it. Ctrl-Z is
disabled — a suspended job holds a transaction nothing can conclude. Instrumentation — capability
requests, verdicts, and anything a command writes to fd 3 — is printed in gray.\
";

/// Runs the console, returning the process's exit code.
pub fn run() -> std::process::ExitCode {
    // Before anything the process could fail on: `--help` and `--version` must not claim fd 3 or
    // touch the filesystem, and an unexpected argument is clap's diagnostic and exit 2.
    let cli = Cli::parse();

    // Before anything else opens a file: fd 3 is a standard stream of this process, and the kernel
    // hands out the lowest free descriptor to whoever asks first. Claiming it here is what keeps
    // the mux's own write-ahead log — the very next thing opened — from landing on the number the
    // instrumentation stream owns. The full-screen interface has no gray line printer to feed, so
    // it claims the number with a sink instead of a pipe.
    let claimed = if cli.tui {
        console::reserve_instrumentation_fd()
    } else {
        console::open_instrumentation().map(console::spawn_instrumentation_reader)
    };
    if let Err(error) = claimed {
        eprintln!("marsh: {error}");
        return std::process::ExitCode::FAILURE;
    }

    // No `chdir`: a command's working directory is its job's snapshot, which the mux sets, and this
    // process stays wherever the user started it.

    // A multi-thread runtime, not a current-thread one: reedline's history adapter blocks on the
    // shell mutex through `block_in_place`, which panics on a current-thread runtime — and the mux
    // moves its own blocking work onto this runtime's blocking pool.
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

    let result = if cli.tui {
        runtime.block_on(tui_session())
    } else {
        runtime.block_on(session(&cli))
    };
    runtime.shutdown_background();
    if let Err(error) = result {
        eprintln!("marsh: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Builds the mux over the seed containing `cwd`, at `frontend`'s geometry.
///
/// The four collaborators, in the order they take ownership: the storage, the executor that takes
/// its exclusive lease and performs every instrumented run, the purity checker, and the frontend
/// every job's bytes and results are delivered to. The CLI selects the *learned* checker
/// explicitly — a command an earlier traced run showed requesting nothing and writing nothing skips
/// the snapshot and the merge entirely — and the caller supplies `environment`, so the console
/// keeps inheriting the terminal's own environment unchanged while the full-screen interface can
/// seed the `TERM` its emulator implements.
///
/// Generic over the frontend because both front-ends open the same session; nothing else about the
/// bootstrap differs between them.
///
/// Must be called from inside the runtime: the mux starts the task that concludes its
/// transactions; each command's exit watcher starts with the command.
fn open_mux<V: MarshFrontend>(
    cwd: &Path,
    frontend: Arc<Mutex<V>>,
    environment: brush_core::env::ShellEnvironment,
) -> Result<Arc<ShellMux>, shellmux::MuxError> {
    let persistence = PersistenceLayer::discover(cwd)?;
    let executor = MarshExecutor::builder(persistence).build()?;
    let checker = PurityCheckerBuilder::new().learned().build();
    ShellMux::new(executor, checker, environment, frontend)
}

/// Runs the full-screen interface over a session opened the same way the console's is.
async fn tui_session() -> Result<(), Error> {
    let cwd = std::env::current_dir().map_err(Error::Storage)?;
    marsh_tui::run(move |frontend, environment| open_mux(&cwd, frontend, environment)).await?;
    Ok(())
}

/// Sets up the terminal and the outer shell, then runs the REPL.
///
/// fd 3 already holds the instrumentation pipe (claimed in [`run`], before any other descriptor
/// could take the number), which is what the outer shell's file table picks up when it is built
/// below; the terminal handle is opened here, *after* fd 3 is occupied, so it cannot land on that
/// number either.
async fn session(cli: &Cli) -> Result<(), Error> {
    // A job's terminal is a pseudoterminal the mux owns, but its *size* is this one's: `/dev/tty`
    // is the real terminal even if stdout has been redirected. Converted once: `OpenFile::clone`
    // shares this descriptor, so the console and the suspend guard hold the same open terminal
    // rather than two.
    let tty: OpenFile = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(Error::Terminal)?
        .into();

    console::claim_terminal_signals();

    // Before the shell, the console and any raw-mode snapshot a line editor takes: everything below
    // reads or restores terminal attributes, and each of them must see suspension already gone.
    // Local to this function on purpose — the console lives in a `OnceLock` that never drops, so a
    // guard stored there would never restore the user's suspend character.
    let _suspend_key = SuspendKeyGuard::new(tty.clone()).map_err(Error::SuspendKey)?;

    let (rows, cols) = terminal_geometry(&tty);
    // Before the mux, because the mux reads its geometry and binds itself to it: the frontend is
    // where a job's bytes go from the moment its terminal exists.
    let frontend = Arc::new(Mutex::new(ConsoleFrontend::new(rows, cols)));
    let cwd = std::env::current_dir().map_err(Error::Storage)?;
    // Bound before the mux exists so a refused port aborts startup instead of surfacing once the
    // session is already open. `rest_addr` is read back from the listener so `--rest-api 0` prints
    // the port the kernel actually assigned.
    let mut rest: Option<(tokio::net::TcpListener, Arc<Mutex<RestFrontend>>)> = None;
    let mut rest_addr = None;
    let mux = if let Some(port) = cli.rest_api {
        let requested = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        let listener = tokio::net::TcpListener::bind(requested)
            .await
            .map_err(|source| Error::RestBind {
                addr: requested,
                source,
            })?;
        rest_addr = Some(listener.local_addr().unwrap_or(requested));
        // The browser side of the join, at the terminal's own geometry: the join opens every
        // pseudoterminal at the per-dimension minimum of its sides, and two equal sides keep that
        // the terminal's size until a client resizes the mux.
        let rest_frontend = Arc::new(Mutex::new(RestFrontend::new(rows, cols)));
        let join = Arc::new(Mutex::new(MarshFrontendJoin {
            left: Arc::clone(&frontend),
            right: Arc::clone(&rest_frontend),
        }));
        let mux = open_mux(&cwd, join, brush_core::env::ShellEnvironment::new())?;
        rest = Some((listener, rest_frontend));
        mux
    } else {
        open_mux(
            &cwd,
            Arc::clone(&frontend),
            brush_core::env::ShellEnvironment::new(),
        )?
    };
    // Started only once the mux exists: the router answers from it on the first request.
    let rest_server = rest.map(|(listener, rest_frontend)| {
        let state = AppState {
            mux: Arc::clone(&mux),
            frontend: rest_frontend,
        };
        tokio::spawn(async move {
            if let Err(error) = routes::serve(listener, state).await {
                console::gray(&format!("marsh: rest api stopped: {error}"));
            }
        })
    });

    // `meta/history.jsonl` is the authority's; two files called `history` in one directory would be
    // a trap.
    let history = mux.persistence().meta().join("console.history");
    let shell = build_shell(&history).await.map_err(Error::Shell)?;
    let shell_ref: ShellRef<DefaultShellExtensions> = Arc::new(tokio::sync::Mutex::new(shell));

    let console = Console::open(frontend, tty.clone()).await?;
    let console = Arc::new(Mutex::new(console));
    // Installed before the loop starts, because the job-control builtins reach the console through
    // this process-global: a `Registration`'s `execute_func` is a plain function pointer.
    console::install(Arc::clone(&console))?;
    watch_terminal_size(Arc::clone(&mux), tty);
    refresh_prompt(&shell_ref, &console).await;

    let (seed, root) = {
        let persistence = mux.persistence();
        (
            persistence.seed.display().to_string(),
            persistence.root.display().to_string(),
        )
    };
    println!("marsh: seed {seed}");
    println!("  state {root}");
    if let Some(addr) = rest_addr {
        println!("  rest http://{addr}");
    }
    console::gray(
        "builtins: sd NAME DIR · bg DIR · CMD &[NAME] · jobs · fg [JOB] · stop [-f] JOB · \
         kill [-SIG] PID · exit",
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

    // Stops accepting REST work before the teardown below: open sockets die with the task, which
    // is what ending the session means.
    if let Some(server) = rest_server {
        server.abort();
    }

    // Exit cancels queued conclusions, terminates outstanding commands and joins the mux's own
    // tasks. Persistent recovery and reclamation belong to startup.
    let shared = with_console(&console, |console| console.shared());
    shared.shutdown().await;

    result.map_err(Error::from)
}

/// The real terminal's size, rows first, falling back to a conventional 24×80.
///
/// Rows before columns, in that order, everywhere: it is the order [`ShellMux::new`] and
/// [`ShellMux::resize`] take, and swapping them would render every job into the wrong shape.
fn terminal_geometry(tty: &OpenFile) -> (u16, u16) {
    /// What a terminal that cannot be measured is assumed to be.
    const FALLBACK: (u16, u16) = (24, 80);

    let Ok(fd) = tty.try_borrow_as_fd() else {
        return FALLBACK;
    };
    match brush_core::sys::terminal::terminal_size(fd) {
        // A terminal that reports a zero dimension is one no job could use; the fallback is what a
        // detached session gets anyway.
        Ok((rows, cols)) if rows > 0 && cols > 0 => (rows, cols),
        _ => FALLBACK,
    }
}

/// Starts the task that follows the real terminal's size onto every job.
///
/// One resize for the whole mux: a window change resizes every job it owns, including the ones
/// nobody is looking at, because a job whose terminal disagrees with the window redraws wrongly the
/// moment it is selected.
fn watch_terminal_size(mux: Arc<ShellMux>, tty: OpenFile) {
    let Ok(mut changes) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
    else {
        console::gray("marsh: cannot follow terminal size changes");
        return;
    };
    drop(tokio::spawn(async move {
        while changes.recv().await.is_some() {
            let (rows, cols) = terminal_geometry(&tty);
            if let Err(error) = mux.resize(rows, cols).await {
                console::gray(&format!("marsh: {error}"));
            }
        }
    }));
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
/// `PS1` is not a constant here: it names the job every typed line runs in, and `sd`, `bg` and
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

/// Runs `action` against the console under a short lock.
///
/// The lock is never held across an await: an operation that has to await clones the console's
/// shared half here, releases the lock, and awaits outside it.
fn with_console<R>(console: &Arc<Mutex<Console>>, action: impl FnOnce(&mut Console) -> R) -> R {
    let mut console = console.lock().unwrap_or_else(PoisonError::into_inner);
    action(&mut console)
}

/// Prints a console operation's diagnostic, if it had one, and returns the exit code for the line.
///
/// A console operation formats its own message — the verb prefix is part of what a reader reads —
/// so this only decides where it goes and what status it means.
fn report(outcome: Result<u8, String>) -> u8 {
    match outcome {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "{message}");
            1
        }
    }
}

/// The handle installed into the interactive loop.
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
                Input::Kill(args) => invoke_builtin(shell, "kill", args).await,
                Input::Stop(args) => invoke_builtin(shell, "stop", args).await,
                Input::SpawnDir { name, dir } => match name {
                    Some(name) => invoke_builtin(shell, "sd", vec![name, dir]).await,
                    None => invoke_builtin(shell, "bg", vec![dir]).await,
                },
                Input::Exit => self.exit(),
                Input::Background { cmd, name } => {
                    let shared = with_console(&self.console, |console| console.shared());
                    let id = name.map(ShellId::from);
                    executed(report(
                        shared.open_job(".", id, Some(cmd)).await.map(|()| 0),
                    ))
                }
                Input::Foreground(cmd) => {
                    let shared = with_console(&self.console, |console| console.shared());
                    executed(report(shared.foreground(&cmd).await))
                }
                Input::Invalid(message) => {
                    let _ = writeln!(std::io::stderr(), "{message}");
                    executed(2)
                }
            };
            // A terminating line cannot need another prompt; avoid doing console work after exit
            // has been accepted.
            if !matches!(
                &result,
                InteractiveExecutionResult::Executed(ExecutionResult {
                    next_control_flow: ExecutionControlFlow::ExitShell,
                    ..
                })
            ) {
                refresh_prompt(shell, &self.console).await;
            }
            Ok(result)
        })
    }

    fn before_prompt(&mut self) {
        // Nothing to poll: the mux watches each command's exit itself, and a job's verdict is
        // published as soon as its conclusion lands rather than at the next prompt turn.
    }

    fn on_interrupt(&mut self) -> Option<InteractiveExecutionResult> {
        if !console::note_interrupt() {
            return None;
        }
        // escape hatch, and demanding a third press because jobs are running is what "cannot get
        // out" means.
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
