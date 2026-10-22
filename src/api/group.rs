//! Group panel (PORTA.md §12.3; note 03 §3).

use super::{ApiResult, CurrentUser, PageQuery};
use crate::state::AppState;
use axum::extract::{Query, State};

/// `GET /api/users?current=&pageSize=&accessible=&status=1`.
pub(crate) async fn users(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Query(_page): Query<PageQuery>,
) -> ApiResult {
    todo!()
}

/// `GET /api/peers?current=&pageSize=&accessible=&status=1`.
pub(crate) async fn peers(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Query(_page): Query<PageQuery>,
) -> ApiResult {
    todo!()
}

/// `GET /api/device-group/accessible`: `{"total":0,"data":[]}`.
pub(crate) async fn device_groups(
    State(_state): State<AppState>,
    _user: CurrentUser,
    Query(_page): Query<PageQuery>,
) -> ApiResult {
    todo!()
}
