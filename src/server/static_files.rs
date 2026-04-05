use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::AppState;

/// GET /realms/{realm}/static/{*path} — serve per-realm branding assets
pub async fn serve_static(
    State(state): State<AppState>,
    Path((realm, file_path)): Path<(String, String)>,
) -> Response {
    // Reject path traversal
    if file_path.contains("..") {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let base = std::path::Path::new(&state.config.realms_dir)
        .join(&realm)
        .join("branding");

    let full_path = base.join(&file_path);

    // Canonicalize both and verify the file is inside the branding directory
    let Ok(canonical_base) = base.canonicalize() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(canonical_file) = full_path.canonicalize() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !canonical_file.starts_with(&canonical_base) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Read and serve the file
    let Ok(contents) = tokio::fs::read(&canonical_file).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let mime = mime_guess::from_path(&canonical_file)
        .first_or_octet_stream()
        .to_string();

    Response::builder()
        .header(CONTENT_TYPE, mime)
        .body(Body::from(contents))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
