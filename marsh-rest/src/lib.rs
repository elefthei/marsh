//! A REST and WebSocket frontend over one marsh transaction mux.
//!
//! The same session `marsh` opens on a terminal, opened on a socket instead: one [`ShellMux`] over
//! the seed containing the directory this process started in, one
//! [`MarshFrontend`](shellmux::MarshFrontend) publishing everything the mux observes, and an axum
//! server handing both to browsers.
//!
//! The split between the two halves is the mux's own. Everything a display *observes* — a job's
//! terminal bytes, its instrumentation, a transaction's verdict, a closure, a resize — arrives as a
//! [`FrontendEvent`](shellmux::FrontendEvent) and leaves on the WebSocket, because it is a stream
//! nobody asked for. Everything a display *does* — spawn, start, select, stop, resize — is a
//! request/response with a status, so it is REST. The only thing travelling the other way on the
//! socket is raw keyboard input, which has no reply and must not wait for one.
//!
//! Terminal bytes are base64 on the wire. A chunk is whatever a read returned: it may split a UTF-8
//! sequence or an escape sequence, and JSON has no way to carry that as text.
//!
//! This binary serves no assets. The web client is a separate repository developed against a dev
//! server that proxies `/api` here.

pub mod dto;
pub mod entry;
pub mod error;
pub mod frontend;
pub mod routes;
