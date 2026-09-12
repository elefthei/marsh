//! Session startup: one mux over the seed this process was started in, served on a socket.
//!
//! The order is the mux's, not this crate's. The frontend is built *before* the mux, because
//! [`ShellMux::new`] reads the geometry every pseudoterminal is opened at from it, and because a
//! frontend that could not exist before the mux did would have nowhere to report the mux's own
//! construction failure. The `main` job follows, so a browser attaching to a fresh session has
//! something to type in. The server comes last and the shutdown after it, because a mux torn down
//! under a live socket would be answering requests with a corpse.
//!
//! Everything happens inside one Tokio runtime: the mux is an asynchronous API that owns tasks —
//! the conclusion queue, one exit watcher per command, one pump per stream — so it is built inside
//! `block_on` and shut down there too.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::Parser;
use shellmux::{
    MarshExecutor, MarshFrontend, MuxError, PersistenceLayer, PurityCheckerBuilder, ShellId,
    ShellMux,
};

use crate::error::Error;
use crate::frontend::RestFrontend;
use crate::routes::{AppState, router};

/// The job a fresh session opens, rooted where marsh-rest was started.
const FOREGROUND: &str = "main";

// Deliberately plain `//` comments, not doc comments: clap's derive turns a doc comment on the
// struct into `about`/`long_about`, and this crate's clap has no `wrap_help`, so the text below is
// printed with its own formatting.
#[derive(Parser)]
#[command(name = "marsh-rest", version, about = ABOUT, long_about = LONG_ABOUT)]
struct Cli {
    /// Address to serve on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// Initial height of every job's terminal, until a client reports its own.
    #[arg(long, default_value_t = 24)]
    rows: u16,

    /// Initial width of every job's terminal, until a client reports its own.
    #[arg(long, default_value_t = 80)]
    cols: u16,
}

/// One-line summary, shown by `-h`.
const ABOUT: &str = "Serves one marsh session over REST and a WebSocket";

/// Full help, shown by `--help`.
const LONG_ABOUT: &str = "\
marsh-rest opens the same session marsh does — the btrfs subvolume containing the directory it was
started in is the seed, and every command submitted to a job is one capability-gated transaction
against it — and serves it on a socket instead of a terminal.

Control actions are REST calls under /api; a job's output, its instrumentation, and each
transaction's verdict arrive on the WebSocket at /api/ws, which also carries raw keyboard input.

No assets are served: the web client runs on its own development server, proxying /api here. The
default address is loopback and there is no authentication, because a session's commands run as the
user who started it.\
";

/// Serves the session, returning the process's exit code.
pub fn run() -> std::process::ExitCode {
    // Before anything the process could fail on: `--help` and `--version` must not touch the
    // filesystem, and an unexpected argument is clap's diagnostic and exit 2.
    let cli = Cli::parse();

    // No `chdir`: a command's working directory is its job's snapshot, which the mux sets, and this
    // process stays wherever the user started it.

    // A multi-thread runtime: the mux moves its blocking work — snapshots, merges, waits — onto
    // this runtime's blocking pool while the server keeps answering.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("marsh-rest: {}", Error::Runtime(error));
            return std::process::ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(session(&cli));
    runtime.shutdown_background();
    if let Err(error) = result {
        eprintln!("marsh-rest: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Builds the mux over the seed containing `cwd`, at `frontend`'s geometry.
///
/// The four collaborators, in the order they take ownership: the storage, the executor that takes
/// its exclusive lease and performs every instrumented run, the purity checker, and the frontend
/// every job's bytes and results are delivered to. The *learned* checker is selected for the same
/// reason the console selects it — a command an earlier traced run showed requesting nothing and
/// writing nothing skips the snapshot and the merge entirely.
///
/// The environment is a fresh one rather than this process's: nothing here is a terminal, so there
/// is no inherited `TERM` worth passing on, and a browser's emulator is the client's own.
///
/// Must be called from inside the runtime: the mux starts the task that concludes its transactions.
fn open_mux(cwd: &Path, frontend: Arc<Mutex<RestFrontend>>) -> Result<Arc<ShellMux>, MuxError> {
    let persistence = PersistenceLayer::discover(cwd)?;
    let executor = MarshExecutor::builder(persistence).build()?;
    let checker = PurityCheckerBuilder::new().learned().build();
    ShellMux::new(
        executor,
        checker,
        brush_core::env::ShellEnvironment::new(),
        frontend,
    )
}

/// Opens the session, serves it, and shuts it down.
async fn session(cli: &Cli) -> Result<(), Error> {
    // Before the mux, because the mux reads its geometry and binds itself to it: the frontend is
    // where a job's bytes go from the moment its terminal exists.
    let frontend = Arc::new(Mutex::new(RestFrontend::new(cli.rows, cli.cols)));
    let cwd = std::env::current_dir().map_err(Error::Storage)?;
    let mux = open_mux(&cwd, Arc::clone(&frontend))?;

    open_default_job(&mux).await?;

    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .map_err(|source| Error::Bind {
            addr: cli.bind,
            source,
        })?;

    let (seed, root) = {
        let persistence = mux.persistence();
        (
            persistence.seed.display().to_string(),
            persistence.root.display().to_string(),
        )
    };
    println!("marsh-rest: seed {seed}");
    println!("  state {root}");
    println!("  serving http://{}", cli.bind);

    let served = axum::serve(
        listener,
        router(AppState {
            mux: Arc::clone(&mux),
            frontend,
        }),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await;

    // After the server stops accepting, never before: a mux shut down under a live socket would be
    // answering requests against a session whose tasks are already joined.
    let shutdown = mux.shutdown().await;
    served.map_err(Error::Serve)?;
    shutdown.map_err(Error::from)
}

/// Opens `main`, rooted where marsh-rest was started, and selects it.
///
/// The same job the console opens, for the same reason: a session is usable before anything is
/// typed, and a bare `ls` lists the directory the user started in rather than the seed root. The
/// handle is not taken here — [`shellmux::FrontendEvent::Opened`] installs it in the frontend while
/// `spawn` is still running.
async fn open_default_job(mux: &Arc<ShellMux>) -> Result<(), MuxError> {
    // Canonicalized because the seed is; a directory that cannot be read falls through to the seed
    // root.
    let cwd = std::env::current_dir()
        .and_then(|dir| dir.canonicalize())
        .unwrap_or_default();
    let dir = mux.persistence().default_dir(&cwd);
    let id = ShellId::from(FOREGROUND);
    mux.spawn(&dir, Some(id.clone()), None).await?;
    mux.switch(&id).await?;
    Ok(())
}
