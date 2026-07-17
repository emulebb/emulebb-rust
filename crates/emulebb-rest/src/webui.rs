use std::path::PathBuf;

use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

pub(crate) fn mount_webui(router: Router, web_root_dir: Option<PathBuf>) -> Router {
    let Some(root) = web_root_dir else {
        return router;
    };
    let index = root.join("index.html");
    router.fallback_service(ServeDir::new(root).fallback(ServeFile::new(index)))
}
