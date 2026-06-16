//! Friend-list REST handlers (`/friends`).
//!
//! Extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use emulebb_core::FriendCreate;

use crate::handlers::prelude::*;

pub(crate) async fn friends(State(state): State<RestState>) -> impl IntoResponse {
    api_collection(state.core.friends().await)
}

pub(crate) async fn create_friend(State(state): State<RestState>, body: Bytes) -> impl IntoResponse {
    let request = match parse_required_json_body::<FriendCreate>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    match state.core.add_friend(request).await {
        Ok(friend) => api_ok(friend).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}

pub(crate) async fn delete_friend(
    State(state): State<RestState>,
    Path(user_hash): Path<String>,
) -> impl IntoResponse {
    match state.core.delete_friend(&user_hash).await {
        Ok(Some(_friend)) => api_ok(json!({ "ok": true })).into_response(),
        Ok(None) => {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "friend not found").into_response()
        }
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}
