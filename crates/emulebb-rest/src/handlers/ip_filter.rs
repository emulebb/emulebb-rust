//! IP filter REST handlers (`/ip-filter` and reload operation).

use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::handlers::prelude::*;

pub(crate) async fn ip_filter(State(state): State<RestState>) -> impl IntoResponse {
    api_ok(state.core.ip_filter_status())
}

pub(crate) async fn reload_ip_filter(State(state): State<RestState>) -> impl IntoResponse {
    match state.core.reload_ip_filter_status() {
        Ok(status) => api_ok(status).into_response(),
        Err(error) => {
            api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.to_string()).into_response()
        }
    }
}
