//! Account endpoints (PORTA.md §9.2, §11; note 03 §2).

use super::{ApiResult, CurrentUser};
use crate::state::AppState;
use axum::{body::Bytes, extract::State};

/// `GET /api/login-options` (also answers HEAD): `[]`.
pub(crate) async fn login_options() -> ApiResult {
    todo!()
}

/// `POST /api/login`, `type=account` only.
pub(crate) async fn login(State(_state): State<AppState>, _body: Bytes) -> ApiResult {
    todo!()
}

/// `POST /api/currentUser`: ignores the body; internal errors answer 200 + `{"error"}` (`ApiError::ok_internal`).
pub(crate) async fn current_user(
    State(_state): State<AppState>,
    _user: CurrentUser,
    _body: Bytes,
) -> ApiResult {
    todo!()
}

/// `POST /api/logout`: deletes only the token used.
pub(crate) async fn logout(
    State(_state): State<AppState>,
    _user: CurrentUser,
    _body: Bytes,
) -> ApiResult {
    todo!()
}
