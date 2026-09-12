//! The HTTP surface: what a browser may ask the mux to do, and the socket it watches it on.
//!
//! Two shapes, split by whether the answer exists yet. Opening a job, starting a command, selecting
//! a tab, stopping a job and resizing all have an immediate answer — it happened, or it failed for
//! a nameable reason — so they are REST calls with a status. Everything a command *produces*
//! happens later and unbidden, so it arrives on the socket.
//!
//! A transaction's verdict is on the later side, which is the one thing worth stating plainly: a
//! denied capability, a stale snapshot and a failed command are **not** HTTP errors. `start`
//! answers 202 the moment the command is launched, and the verdict reaches every attached client
//! as a `finished` message whenever the merge concludes.
//!
//! The lock discipline here is the mux's contract read backwards. The mux delivers events with the
//! frontend's mutex held, so a handler that held that mutex across a mux call would deadlock the
//! session. Every lock in this module is taken for one field read and dropped on the next line,
//! before anything is awaited.

use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, routing};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use shellmux::{MuxError, ShellId, ShellMux};
use tokio::sync::broadcast::error::RecvError;

use crate::dto::{
    ForceQuery, JobDto, JobsSnapshot, ResizeRequest, SpawnRequest, StartRequest, job_dto, snapshot,
};
use crate::frontend::{ClientMessage, RestFrontend, ServerMessage};

/// Everything a handler reaches: the session, and the publisher clients watch it through.
#[derive(Clone)]
pub struct AppState {
    /// The session every request acts on.
    pub mux: Arc<ShellMux>,
    /// The frontend, for the input handles and the event subscription.
    pub frontend: Arc<Mutex<RestFrontend>>,
}

/// A request that could not be carried out.
///
/// Two sources, because the two have different answers. A [`MuxError`] is the session saying no,
/// and its message is already written as the whole sentence a user reads. A malformed request is
/// this crate's own refusal, made before the mux was ever asked.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The mux refused, or broke.
    #[error(transparent)]
    Mux(#[from] MuxError),
    /// The request itself was unusable.
    #[error("{0}")]
    BadRequest(String),
}

impl IntoResponse for ApiError {
    /// Maps a refusal onto the status a client can act on.
    ///
    /// The distinction that matters is 4xx against 5xx: a name already taken, a job that is busy
    /// and a job that is closing are all things the *client* did, and retrying differently fixes
    /// them. Everything else — a failed snapshot, an unparsable trace, a broken write-ahead log —
    /// is the session breaking, and no request will fix it.
    fn into_response(self) -> Response {
        let status = match &self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Mux(error) => match error {
                MuxError::NoSuchJob(_) => StatusCode::NOT_FOUND,
                MuxError::JobExists(_)
                | MuxError::JobBusy(_)
                | MuxError::JobClosing(_)
                | MuxError::SessionBusy(_) => StatusCode::CONFLICT,
                MuxError::InvalidTerminalSize { .. } | MuxError::SandboxDir { .. } => {
                    StatusCode::BAD_REQUEST
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// The whole surface: the control calls, and the one socket everything is observed on.
///
/// Everything lives under `/api` so that a development server proxies the REST calls and the
/// WebSocket upgrade with a single rule.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/jobs", get(list_jobs).post(spawn_job))
        .route("/api/jobs/{id}", routing::delete(stop_job))
        .route("/api/jobs/{id}/start", post(start_cmd))
        .route("/api/jobs/{id}/select", post(select_job))
        .route("/api/resize", post(resize))
        .route("/api/ws", get(open_socket))
        .with_state(state)
}

/// Serves the surface on an already-bound listener until the task running it is dropped or the
/// listener fails.
///
/// For an embedder that joins this frontend onto its own session (`marsh --rest-api`): binding is
/// the caller's — a refused port is its startup error — and shutdown is the caller's too, by
/// aborting the task. The standalone `marsh-rest` binary keeps its own graceful-shutdown serve in
/// [`crate::entry`].
///
/// # Errors
///
/// Fails when accepting on the listener fails.
pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

/// The job table and the selection.
async fn list_jobs(State(state): State<AppState>) -> Json<JobsSnapshot> {
    Json(snapshot(&state.mux))
}

/// Opens a job under a given name, rooted at a given directory.
///
/// The name is the client's, not the mux's: a browser's tabs are addressable URLs, so a job it
/// opened has to be one it can name afterwards. An empty one is refused here rather than by the
/// mux, because the mux would take it and the resulting job would have no reachable route.
async fn spawn_job(
    State(state): State<AppState>,
    Json(request): Json<SpawnRequest>,
) -> Result<(StatusCode, Json<JobDto>), ApiError> {
    if request.id.is_empty() {
        return Err(ApiError::BadRequest("a job needs a name".to_string()));
    }
    let id = ShellId::from(request.id);
    let spawned = state
        .mux
        .spawn(&request.dir, Some(id.clone()), None)
        .await?;
    // Read back rather than composed from `spawned`: the job may already be running something by
    // now, and a table row is what a client's tab is drawn from.
    let dto = state.mux.job(&id).map_or_else(
        || JobDto {
            id: spawned.id.clone(),
            uid: spawned.sandbox.uid.clone(),
            dir: spawned.sandbox.dir.clone(),
            running: None,
            starting: false,
            closing: false,
            merging: false,
        },
        |view| {
            let merging = state.mux.is_merging(&id);
            job_dto(&view, merging)
        },
    );
    Ok((StatusCode::CREATED, Json(dto)))
}

/// Launches one command in a job.
///
/// 202, not 200: what this answers is that the command *started*. Its transaction is concluded
/// later, and its verdict — committed, denied, stale, unsupported — reaches every attached client
/// as a `finished` message rather than as this call's status.
///
/// No completion callback is given: the frontend already observes every conclusion, and a second
/// notification would be a second place for a verdict to be rendered from.
async fn start_cmd(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<StartRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .mux
        .start_in(&ShellId::from(id), &request.cmd, None)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

/// Selects a job: the one a mux-level operation with no named job acts on.
async fn select_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<JobDto>, ApiError> {
    let id = ShellId::from(id);
    let view = state.mux.switch(&id).await?;
    let merging = state.mux.is_merging(&id);
    Ok(Json(job_dto(&view, merging)))
}

/// Closes a job, once its command finishes or — with `force` — by killing its process group now.
async fn stop_job(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ForceQuery>,
) -> Result<StatusCode, ApiError> {
    state.mux.stop(&ShellId::from(id), query.force).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets the geometry of every job's terminal.
///
/// Mux-wide by the mux's own design, and therefore last-writer-wins across clients: a job whose
/// terminal disagrees with the window it is displayed in redraws wrongly the moment it is selected,
/// so the mux keeps one geometry rather than one per viewer.
async fn resize(
    State(state): State<AppState>,
    Json(request): Json<ResizeRequest>,
) -> Result<StatusCode, ApiError> {
    state.mux.resize(request.rows, request.cols).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Upgrades to the event socket.
async fn open_socket(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| serve_socket(socket, state))
}

/// Runs one client's socket until either side is done with it.
///
/// The greeting is a full job snapshot, always: it is what makes reconnecting equivalent to
/// connecting, so a client that lost its socket redraws from the same message it started from and
/// needs no replay.
async fn serve_socket(mut socket: WebSocket, state: AppState) {
    let mut events = {
        let frontend = state
            .frontend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        frontend.subscribe()
    };

    if !send_message(&mut socket, &ServerMessage::Jobs(snapshot(&state.mux))).await {
        return;
    }

    loop {
        tokio::select! {
            published = events.recv() => match published {
                Ok(message) => {
                    if !send_message(&mut socket, &message).await {
                        return;
                    }
                }
                // This client fell behind and the channel dropped what it had not read. The bytes
                // are gone — the mux does not replay a terminal — but the *table* is recoverable,
                // and it is the part a stale copy of would leave the display wrong for good.
                Err(RecvError::Lagged(_)) => {
                    if !send_message(&mut socket, &ServerMessage::Jobs(snapshot(&state.mux))).await {
                        return;
                    }
                }
                Err(RecvError::Closed) => return,
            },
            received = socket.recv() => match received {
                Some(Ok(Message::Text(text))) => forward_input(&state, text.as_str()).await,
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                // Ping and pong are the server's transport to answer; binary frames are not part
                // of this protocol, since input is base64 inside JSON like everything else.
                Some(Ok(_)) => {}
            },
        }
    }
}

/// Serializes and sends one message, reporting whether the socket is still usable.
///
/// A message that cannot be serialized is dropped rather than fatal: it would be this crate's own
/// bug, and tearing down a working session over one frame would lose a display that is otherwise
/// still correct.
async fn send_message(socket: &mut WebSocket, message: &ServerMessage) -> bool {
    let Ok(text) = serde_json::to_string(message) else {
        return true;
    };
    socket.send(Message::Text(text.into())).await.is_ok()
}

/// Writes one input frame's bytes to its job's terminal.
///
/// Every failure here is silent, and each for the same reason: input is unacknowledged. A frame
/// naming a job that just closed, a frame that arrived after the handle was released, a malformed
/// frame — none of them has anywhere to report to, and none of them is worth ending a session that
/// is otherwise working.
async fn forward_input(state: &AppState, text: &str) {
    let Ok(ClientMessage::Input { job, data }) = serde_json::from_str::<ClientMessage>(text) else {
        return;
    };
    let Ok(bytes) = BASE64.decode(data) else {
        return;
    };
    // The guard is dropped before the write: the mux delivers events with this mutex held, so
    // awaiting a mux call under it would deadlock the session against its own byte pump.
    let handle = {
        let frontend = state
            .frontend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        frontend.handle(&job)
    };
    if let Some(handle) = handle {
        let _ = state.mux.write_input(&handle, &bytes).await;
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A name a live job already holds is the client's problem and it is retryable under another
    /// name, so it is a conflict rather than a server failure.
    #[test]
    fn a_taken_name_is_a_conflict() {
        let response = ApiError::Mux(MuxError::JobExists(ShellId::from("main"))).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// A job that is running a command takes no second one: also retryable, also a conflict.
    #[test]
    fn a_busy_job_is_a_conflict() {
        let response = ApiError::Mux(MuxError::JobBusy(ShellId::from("main"))).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    /// An unknown job is a 404, so a client whose tab outlived its job can tell that apart from a
    /// session that is broken.
    #[test]
    fn an_unknown_job_is_not_found() {
        let response = ApiError::Mux(MuxError::NoSuchJob(ShellId::from("gone"))).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A zero dimension is a request the mux will never accept, whoever sends it.
    #[test]
    fn a_degenerate_geometry_is_a_bad_request() {
        let response =
            ApiError::Mux(MuxError::InvalidTerminalSize { rows: 0, cols: 80 }).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// A job with no name has no route to reach it by, so it is refused before the mux is asked.
    #[test]
    fn a_nameless_job_is_a_bad_request() {
        let response = ApiError::BadRequest("a job needs a name".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// The session breaking is a 500: no retry of this request fixes it.
    #[test]
    fn an_infrastructure_failure_is_a_server_error() {
        let response = ApiError::Mux(MuxError::Wal("truncated".to_string())).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
