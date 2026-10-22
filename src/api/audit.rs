//! Audit reports (PORTA.md §9.3; note 03 §5).
//! Success: 200 + empty body (`ok_empty`); internal error: 200 + `{"error"}` (`ok_internal`, the
//! client retries); bad body: 400. Handlers return `Response` so `?` cannot produce a plain 400.

use crate::state::AppState;
use axum::{body::Bytes, extract::State, response::Response};

/// `POST /api/audit/conn`: new / authed / close, and the controller's session note (no uuid, no nonce).
pub(crate) async fn conn(State(_state): State<AppState>, _body: Bytes) -> Response {
    todo!()
}

/// `POST /api/audit/file`.
pub(crate) async fn file(State(_state): State<AppState>, _body: Bytes) -> Response {
    todo!()
}

/// `POST /api/audit/alarm`.
pub(crate) async fn alarm(State(_state): State<AppState>, _body: Bytes) -> Response {
    todo!()
}
