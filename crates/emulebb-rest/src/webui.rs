use std::{convert::Infallible, path::PathBuf};

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use tower::{ServiceExt, service_fn};
use tower_http::services::{ServeDir, ServeFile};

pub(crate) fn mount_webui(router: Router, web_root_dir: Option<PathBuf>) -> Router {
    let Some(root) = web_root_dir else {
        return router;
    };
    let index = root.join("index.html");
    let html_fallback = service_fn(move |request: Request<Body>| {
        let index = index.clone();
        async move {
            if accepts_html(&request) {
                let response = ServeFile::new(index).oneshot(request).await?;
                return Ok::<_, Infallible>(response.map(Body::new));
            }
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    });
    router.fallback_service(ServeDir::new(root).fallback(html_fallback))
}

fn accepts_html(request: &Request<Body>) -> bool {
    request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|media_range| {
                media_range
                    .split(';')
                    .next()
                    .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/html"))
            })
        })
}
