//! Device reports: sysinfo and heartbeat / strategy push (PORTA.md §9.3, §10; notes 01, 03 §4).
//! No authentication (compatibility debt); weak `uuid` check against hbbs' `peer` table.

use super::{ApiResult, ClientIp};
use crate::state::AppState;
use axum::{body::Bytes, extract::State};

/// `POST /api/sysinfo`: plain text `SYSINFO_UPDATED` on success, never `ID_NOT_FOUND`.
pub(crate) async fn sysinfo(State(_state): State<AppState>, _body: Bytes) -> ApiResult {
    todo!()
}

/// `POST /api/heartbeat`: always a JSON object (at least `{}`); strategy only when `modified_at != rev`.
pub(crate) async fn heartbeat(
    State(_state): State<AppState>,
    ClientIp(_ip): ClientIp,
    _body: Bytes,
) -> ApiResult {
    todo!()
}
