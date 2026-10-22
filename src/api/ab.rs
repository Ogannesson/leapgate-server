//! Address book, the 12 endpoints of the new protocol (PORTA.md §12; note 04).
//! Writes succeed with 200 + empty body only; `personal`, `settings`, `shared/profiles` never 404.

use super::{ApiResult, CurrentUser, PageQuery};
use crate::state::AppState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
};

/// `POST /api/ab/personal`: `{"guid": …}`, creating the personal book on first use.
pub(crate) async fn personal(State(_state): State<AppState>, _user: CurrentUser) -> ApiResult {
    todo!()
}

/// `POST /api/ab/settings`: `{"max_peer_one_ab": 0}`.
pub(crate) async fn settings(State(_state): State<AppState>, _user: CurrentUser) -> ApiResult {
    todo!()
}

/// `POST /api/ab/shared/profiles?current=&pageSize=`.
pub(crate) async fn shared_profiles(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Query(_page): Query<PageQuery>,
) -> ApiResult {
    todo!()
}

/// `POST /api/ab/peers?current=&pageSize=&ab=<guid>`.
pub(crate) async fn peers(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Query(_page): Query<PageQuery>,
) -> ApiResult {
    todo!()
}

/// `POST /api/ab/tags/<guid>`: JSON array.
pub(crate) async fn tags(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
) -> ApiResult {
    todo!()
}

/// `POST /api/ab/peer/add/<guid>`: merge-update when the id exists.
pub(crate) async fn peer_add(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `PUT /api/ab/peer/update/<guid>`: merges only the fields present.
pub(crate) async fn peer_update(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `DELETE /api/ab/peer/<guid>`: body is a JSON array of ids.
pub(crate) async fn peer_delete(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `POST /api/ab/tag/add/<guid>`.
pub(crate) async fn tag_add(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `PUT /api/ab/tag/rename/<guid>`: cascades into the peers' `tags`.
pub(crate) async fn tag_rename(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `PUT /api/ab/tag/update/<guid>`: color.
pub(crate) async fn tag_update(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `DELETE /api/ab/tag/<guid>`: body is a JSON array of names; cascades into the peers' `tags`.
pub(crate) async fn tag_delete(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Path(_guid): Path<String>,
    _body: Bytes,
) -> ApiResult {
    todo!()
}
